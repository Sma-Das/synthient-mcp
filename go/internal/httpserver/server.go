package httpserver

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Sma-Das/synthient-mcp/go/internal/buildinfo"
	"github.com/Sma-Das/synthient-mcp/go/internal/config"
	"github.com/Sma-Das/synthient-mcp/go/internal/forwarding"
	"github.com/Sma-Das/synthient-mcp/go/internal/mcpserver"
	"github.com/Sma-Das/synthient-mcp/go/internal/synthient"
)

type telemetry struct {
	httpRequests          atomic.Int64
	httpInflight          atomic.Int64
	httpRejected          atomic.Int64
	httpPrincipalRejected atomic.Int64
	httpRateRejected      atomic.Int64
	upstreamRequests      atomic.Int64
	upstreamTransport     atomic.Int64
	upstreamSuccess       atomic.Int64
	upstreamClientErrors  atomic.Int64
	upstreamServerErrors  atomic.Int64
	upstreamDurationNanos atomic.Int64
}

func NewHandler(cfg config.Config) http.Handler {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewHandlerWithLogger(cfg, logger)
}

func NewHandlerWithLogger(cfg config.Config, logger *slog.Logger) http.Handler {
	return newHandler(cfg, logger, nil)
}

func newHandler(cfg config.Config, logger *slog.Logger, verifier auth.TokenVerifier) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	requestTimeout := cfg.RequestTimeout
	if requestTimeout <= 0 {
		requestTimeout = 15 * time.Second
	}
	maxConcurrent := cfg.MaxConcurrentRequests
	if maxConcurrent <= 0 {
		maxConcurrent = 8
	}
	maxRequestBody := cfg.MaxRequestBody
	if maxRequestBody <= 0 {
		maxRequestBody = 1 << 20
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxConnsPerHost = maxConcurrent
	transport.MaxIdleConnsPerHost = maxConcurrent
	transport.MaxIdleConns = maxConcurrent * 2
	transport.ResponseHeaderTimeout = requestTimeout
	transport.MaxResponseHeaderBytes = 64 << 10
	apiClient := &http.Client{Timeout: requestTimeout, Transport: transport}
	// Live samples are bounded by their own operation deadline, which may exceed
	// REQUEST_TIMEOUT_MS, so their transport must not impose the shorter
	// response-header timeout used for ordinary lookups.
	streamTransport := transport.Clone()
	streamTransport.ResponseHeaderTimeout = 0
	streamClient := &http.Client{Transport: streamTransport}
	stats := &telemetry{}

	schemaCache := mcp.NewSchemaCache()
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(request *http.Request) *mcp.Server {
			apiKey := request.Header.Get("X-API-Key")
			if cfg.AuthMode == "oauth" {
				apiKey = cfg.SynthientAPIKey
			}
			client := synthient.NewClient(
				cfg.SynthientBaseURL,
				apiKey,
				request.Header.Get("X-Forwarded-For"),
				apiClient,
				stats,
			).WithGRPCEndpoint(cfg.SynthientGRPCEndpoint).WithStreamHTTPClient(streamClient)
			return mcpserver.New(client, schemaCache, mcpserver.Options{
				LegacyToolNames: cfg.LegacyToolNames,
				SampleTimeout:   cfg.StreamTimeout,
			})
		},
		&mcp.StreamableHTTPOptions{
			Stateless:                    true,
			JSONResponse:                 true,
			MaxRequestBodyBytes:          maxRequestBody,
			PropagateRequestCancellation: true,
		},
	)

	crossOrigin := http.NewCrossOriginProtection()
	for _, origin := range cfg.AllowedOrigins {
		if err := crossOrigin.AddTrustedOrigin(origin); err != nil {
			panic(fmt.Sprintf("invalid allowed origin %q: %v", origin, err))
		}
	}
	crossOrigin.SetDenyHandler(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		writeError(response, http.StatusForbidden, "Origin header is not allowed")
	}))

	perPrincipal := cfg.MaxConcurrentPerUser
	if perPrincipal <= 0 {
		perPrincipal = 2
	}
	// The batch guard reads the request body, so it runs inside the
	// per-principal limiters: an over-limit caller is rejected before any of
	// its body is read.
	mcpRoute := rejectJSONRPCBatches(maxRequestBody, mcpHandler)
	mcpRoute = limitConcurrentPerPrincipal(perPrincipal, stats, mcpRoute)
	if cfg.MaxRequestsPerMinute > 0 {
		mcpRoute = limitRatePerPrincipal(cfg.MaxRequestsPerMinute, stats, mcpRoute)
	}
	mcpRoute = protectMCP(cfg, mcpRoute)
	if cfg.AuthMode == "oauth" {
		if verifier == nil {
			verifier = oidcTokenVerifier(cfg)
		}
		mcpRoute = oauthProtection(cfg, verifier)(mcpRoute)
	}
	mcpRoute = limitConcurrent(maxConcurrent, stats, mcpRoute)
	mcpRoute = requireExactOrigin(cfg, mcpRoute)
	mcpRoute = crossOrigin.Handler(mcpRoute)
	if cfg.CORSEnabled {
		mcpRoute = allowCORS(cfg, mcpRoute)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(response).Encode(map[string]string{
			"status":  "ok",
			"version": buildinfo.Version,
			"commit":  buildinfo.Commit,
		})
	})
	if cfg.MetricsEnabled {
		mux.Handle("GET /metrics", stats)
	}
	if cfg.AuthMode == "oauth" {
		metadata := protectedResourceHandler(cfg)
		metadataPath := resourceMetadataPath(cfg.MCPResourceURL)
		mux.Handle(metadataPath, metadata)
		if metadataPath != "/.well-known/oauth-protected-resource" {
			mux.Handle("/.well-known/oauth-protected-resource", metadata)
		}
	}
	mux.Handle("/mcp", mcpRoute)
	return observeRequests(logger, stats, mux)
}

func requireExactOrigin(cfg config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		origin := request.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(response, request)
			return
		}
		parsed, err := url.ParseRequestURI(origin)
		if err != nil || parsed == nil || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
			writeError(response, http.StatusForbidden, "Origin header is not allowed")
			return
		}
		canonical := (&url.URL{Scheme: strings.ToLower(parsed.Scheme), Host: strings.ToLower(parsed.Host)}).String()
		if sameOrigin(cfg, request, canonical) || stringInSlice(cfg.AllowedOrigins, canonical) {
			next.ServeHTTP(response, request)
			return
		}
		writeError(response, http.StatusForbidden, "Origin header is not allowed")
	})
}

// sameOrigin reports whether origin names this server as the request reached
// it. Behind a trusted TLS-terminating proxy the scheme comes from
// X-Forwarded-Proto, which is honoured only when the direct peer is trusted.
func sameOrigin(cfg config.Config, request *http.Request, origin string) bool {
	host := strings.ToLower(request.Host)
	if host == "" {
		return false
	}
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	} else if cfg.TrustProxyHops > 0 && forwarding.TrustedPeer(request, cfg.TrustedProxyCIDRs) {
		// The trusted edge must overwrite X-Forwarded-Proto. A duplicated or
		// comma-joined value means a client-supplied value may have survived,
		// so it is ignored and the connection's own scheme is used.
		if values := request.Header.Values("X-Forwarded-Proto"); len(values) == 1 {
			if proto := strings.ToLower(strings.TrimSpace(values[0])); proto == "https" || proto == "http" {
				scheme = proto
			}
		}
	}
	return origin == (&url.URL{Scheme: scheme, Host: host}).String()
}

func stringInSlice(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func protectMCP(cfg config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		if !allowedRequestHost(request.Host, cfg.AllowedHosts) {
			writeError(response, http.StatusForbidden, "Host header is not allowed")
			return
		}

		if cfg.AuthMode != "oauth" {
			keys := request.Header.Values("X-API-Key")
			if len(keys) == 0 || strings.TrimSpace(keys[0]) == "" {
				writeError(response, http.StatusUnauthorized, "Provide your Synthient API key in the x-api-key header.")
				return
			}
			maxKeyLength := cfg.MaxAPIKeyLength
			if maxKeyLength <= 0 {
				maxKeyLength = 1024
			}
			if len(keys) != 1 || keys[0] != strings.TrimSpace(keys[0]) || strings.Contains(keys[0], ",") || len(keys[0]) > maxKeyLength {
				writeError(response, http.StatusBadRequest, "The x-api-key header must contain one bounded value without surrounding whitespace.")
				return
			}
		} else {
			request.Header.Del("X-API-Key")
		}

		// Resolve the client address from the inbound chain before replacing it,
		// so only the single validated address is ever forwarded upstream.
		clientIP := ""
		if cfg.ForwardClientIP {
			resolved, err := forwarding.CanonicalClientIP(request, cfg.TrustProxyHops, cfg.TrustedProxyCIDRs)
			if err != nil {
				writeError(response, http.StatusBadRequest, err.Error())
				return
			}
			clientIP = resolved
		}
		request.Header.Del("X-Forwarded-For")
		if clientIP != "" {
			request.Header.Set("X-Forwarded-For", clientIP)
		}
		next.ServeHTTP(response, request)
	})
}

func limitConcurrentPerPrincipal(limit int, stats *telemetry, next http.Handler) http.Handler {
	var mutex sync.Mutex
	inflight := map[string]int{}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		principal := requestPrincipal(request)
		if principal == "" {
			writeError(response, http.StatusUnauthorized, "Unable to identify the authenticated principal.")
			return
		}
		mutex.Lock()
		if inflight[principal] >= limit {
			mutex.Unlock()
			stats.httpPrincipalRejected.Add(1)
			response.Header().Set("Retry-After", "1")
			writeError(response, http.StatusTooManyRequests, "The authenticated principal is at its concurrent request limit.")
			return
		}
		inflight[principal]++
		mutex.Unlock()
		defer func() {
			mutex.Lock()
			inflight[principal]--
			if inflight[principal] == 0 {
				delete(inflight, principal)
			}
			mutex.Unlock()
		}()
		next.ServeHTTP(response, request)
	})
}

func requestPrincipal(request *http.Request) string {
	if token := auth.TokenInfoFromContext(request.Context()); token != nil && token.UserID != "" {
		return "oauth:" + token.UserID
	}
	if key := request.Header.Get("X-API-Key"); key != "" {
		digest := sha256.Sum256([]byte(key))
		return "api-key:" + hex.EncodeToString(digest[:])
	}
	return ""
}

const maxTrackedRatePrincipals = 10000

type principalRateWindow struct {
	count   int
	resetAt time.Time
}

type principalRateLimiter struct {
	mutex   sync.Mutex
	limit   int
	now     func() time.Time
	windows map[string]principalRateWindow
	stats   *telemetry
}

func limitRatePerPrincipal(limit int, stats *telemetry, next http.Handler) http.Handler {
	limiter := &principalRateLimiter{
		limit:   limit,
		now:     time.Now,
		windows: make(map[string]principalRateWindow),
		stats:   stats,
	}
	return limiter.handler(next)
}

func (limiter *principalRateLimiter) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		principal := requestPrincipal(request)
		if principal == "" {
			writeError(response, http.StatusUnauthorized, "Unable to identify the authenticated principal.")
			return
		}
		now := limiter.now()
		limiter.mutex.Lock()
		window, exists := limiter.windows[principal]
		if exists && !now.Before(window.resetAt) {
			delete(limiter.windows, principal)
			exists = false
		}
		if !exists && len(limiter.windows) >= maxTrackedRatePrincipals && !limiter.evictLocked(now) {
			limiter.mutex.Unlock()
			limiter.reject(response, 1, "The server is tracking its maximum number of active principals; retry shortly.")
			return
		}
		if !exists {
			window = principalRateWindow{resetAt: now.Add(time.Minute)}
		}
		if window.count >= limiter.limit {
			remaining := window.resetAt.Sub(now)
			retryAfter := max(1, int((remaining+time.Second-1)/time.Second))
			limiter.mutex.Unlock()
			limiter.reject(response, retryAfter, "The authenticated principal has reached its request rate limit.")
			return
		}
		window.count++
		limiter.windows[principal] = window
		limiter.mutex.Unlock()
		next.ServeHTTP(response, request)
	})
}

// evictLocked frees room for a new principal and reports whether it did. It
// drops expired windows and, if the table is still full, the window closest to
// expiry among those that still have quota left. Exhausted windows are never
// evicted, so a principal at its limit stays limited until its window ends.
// In api_key mode principals are unverified until Synthient sees the key, so
// simply refusing new principals when the table fills would let a flood of
// random keys lock out every legitimate caller. Evicting a window that still
// has quota grants that principal at most one fresh window early.
//
// The scan is O(n) under the lock, but runs only while the table is full,
// and global and per-principal concurrency limits bound how often that is.
func (limiter *principalRateLimiter) evictLocked(now time.Time) bool {
	var victim string
	var victimReset time.Time
	for key, candidate := range limiter.windows {
		if !now.Before(candidate.resetAt) {
			delete(limiter.windows, key)
			continue
		}
		if candidate.count >= limiter.limit {
			continue
		}
		if victim == "" || candidate.resetAt.Before(victimReset) {
			victim, victimReset = key, candidate.resetAt
		}
	}
	if len(limiter.windows) < maxTrackedRatePrincipals {
		return true
	}
	if victim == "" {
		return false
	}
	delete(limiter.windows, victim)
	return true
}

func (limiter *principalRateLimiter) reject(response http.ResponseWriter, retryAfter int, message string) {
	limiter.stats.httpRateRejected.Add(1)
	response.Header().Set("Retry-After", fmt.Sprint(retryAfter))
	writeError(response, http.StatusTooManyRequests, message)
}

func allowCORS(cfg config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		origin := canonicalOriginHeader(request.Header.Get("Origin"))
		if origin == "" {
			next.ServeHTTP(response, request)
			return
		}
		if sameOrigin(cfg, request, origin) {
			// Same-origin requests need no CORS grant; requireExactOrigin and
			// the Host allowlist still apply downstream.
			next.ServeHTTP(response, request)
			return
		}
		if !stringInSlice(cfg.AllowedOrigins, origin) || !allowedRequestHost(request.Host, cfg.AllowedHosts) {
			writeError(response, http.StatusForbidden, "Origin header is not allowed")
			return
		}
		response.Header().Set("Access-Control-Allow-Origin", origin)
		response.Header().Set("Access-Control-Allow-Credentials", "true")
		response.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id, X-Request-ID, WWW-Authenticate, Retry-After")
		response.Header().Add("Vary", "Origin")
		if request.Method == http.MethodOptions {
			response.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			response.Header().Set("Access-Control-Allow-Headers", "Authorization, X-API-Key, Content-Type, Accept, MCP-Protocol-Version, MCP-Session-Id, Mcp-Method, Mcp-Name, Last-Event-ID")
			response.Header().Set("Access-Control-Max-Age", "600")
			response.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(response, request)
	})
}

func canonicalOriginHeader(value string) string {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed == nil || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	return (&url.URL{Scheme: strings.ToLower(parsed.Scheme), Host: strings.ToLower(parsed.Host)}).String()
}

func limitConcurrent(limit int, stats *telemetry, next http.Handler) http.Handler {
	semaphore := make(chan struct{}, limit)
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		select {
		case semaphore <- struct{}{}:
			defer func() { <-semaphore }()
			next.ServeHTTP(response, request)
		default:
			stats.httpRejected.Add(1)
			response.Header().Set("Retry-After", "1")
			writeError(response, http.StatusServiceUnavailable, "The server is at its concurrent request limit; retry shortly.")
		}
	})
}

func allowedRequestHost(value string, allowed []string) bool {
	host := value
	if parsed, _, err := net.SplitHostPort(value); err == nil {
		host = parsed
	}
	return containsHostname(allowed, host)
}

func containsHostname(allowed []string, candidate string) bool {
	candidate = strings.ToLower(strings.Trim(strings.TrimSpace(candidate), "[]"))
	for _, value := range allowed {
		if strings.ToLower(strings.Trim(value, "[]")) == candidate {
			return true
		}
	}
	return false
}

func writeError(response http.ResponseWriter, status int, message string) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]any{
		"jsonrpc": "2.0",
		"error": map[string]any{
			"code":    -32000,
			"message": message,
		},
		"id": nil,
	})
}

func ListenAddress(cfg config.Config) string {
	return fmt.Sprintf("http://%s/mcp", cfg.Address())
}

func observeRequests(logger *slog.Logger, stats *telemetry, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		started := time.Now()
		requestID := newRequestID()
		response.Header().Set("X-Request-ID", requestID)
		recorder := &statusRecorder{ResponseWriter: response, status: http.StatusOK}
		stats.httpRequests.Add(1)
		stats.httpInflight.Add(1)
		defer stats.httpInflight.Add(-1)

		next.ServeHTTP(recorder, request)
		// ServeMux records the matched pattern on the request. Logging it rather
		// than the raw path keeps arbitrary caller-supplied paths out of logs.
		route := request.Pattern
		if route == "" {
			route = "unmatched"
		}
		level := slog.LevelInfo
		if route == "GET /healthz" || route == "GET /metrics" {
			level = slog.LevelDebug
		}
		logger.Log(request.Context(), level, "HTTP request",
			"request_id", requestID,
			"method", request.Method,
			"route", route,
			"status", recorder.status,
			"duration_ms", time.Since(started).Milliseconds(),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (response *statusRecorder) WriteHeader(status int) {
	if response.wroteHeader {
		return
	}
	response.wroteHeader = true
	response.status = status
	response.ResponseWriter.WriteHeader(status)
}

func (response *statusRecorder) Write(value []byte) (int, error) {
	if !response.wroteHeader {
		response.wroteHeader = true
		response.status = http.StatusOK
	}
	return response.ResponseWriter.Write(value)
}

func (response *statusRecorder) Unwrap() http.ResponseWriter {
	return response.ResponseWriter
}

func newRequestID() string {
	var value [12]byte
	if _, err := rand.Read(value[:]); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(value[:])
}

func (stats *telemetry) ObserveUpstream(status int, duration time.Duration) {
	stats.upstreamRequests.Add(1)
	stats.upstreamDurationNanos.Add(duration.Nanoseconds())
	switch {
	case status == 0:
		stats.upstreamTransport.Add(1)
	case status >= 200 && status < 300:
		stats.upstreamSuccess.Add(1)
	case status >= 400 && status < 500:
		stats.upstreamClientErrors.Add(1)
	default:
		stats.upstreamServerErrors.Add(1)
	}
}

func (stats *telemetry) ServeHTTP(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Content-Type", "text/plain; version=0.0.4")
	response.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprintf(response, "# TYPE synthient_mcp_http_requests_total counter\nsynthient_mcp_http_requests_total %d\n", stats.httpRequests.Load())
	_, _ = fmt.Fprintf(response, "# TYPE synthient_mcp_http_inflight gauge\nsynthient_mcp_http_inflight %d\n", stats.httpInflight.Load())
	_, _ = fmt.Fprintf(response, "# TYPE synthient_mcp_http_rejected_total counter\nsynthient_mcp_http_rejected_total %d\n", stats.httpRejected.Load())
	_, _ = fmt.Fprintf(response, "# TYPE synthient_mcp_http_principal_rejected_total counter\nsynthient_mcp_http_principal_rejected_total %d\n", stats.httpPrincipalRejected.Load())
	_, _ = fmt.Fprintf(response, "# TYPE synthient_mcp_http_rate_rejected_total counter\nsynthient_mcp_http_rate_rejected_total %d\n", stats.httpRateRejected.Load())
	_, _ = fmt.Fprintf(response, "# TYPE synthient_mcp_upstream_requests_total counter\nsynthient_mcp_upstream_requests_total %d\n", stats.upstreamRequests.Load())
	_, _ = fmt.Fprintln(response, "# TYPE synthient_mcp_upstream_requests_by_outcome counter")
	_, _ = fmt.Fprintf(response, "synthient_mcp_upstream_requests_by_outcome{outcome=\"success\"} %d\n", stats.upstreamSuccess.Load())
	_, _ = fmt.Fprintf(response, "synthient_mcp_upstream_requests_by_outcome{outcome=\"client_error\"} %d\n", stats.upstreamClientErrors.Load())
	_, _ = fmt.Fprintf(response, "synthient_mcp_upstream_requests_by_outcome{outcome=\"server_error\"} %d\n", stats.upstreamServerErrors.Load())
	_, _ = fmt.Fprintf(response, "synthient_mcp_upstream_requests_by_outcome{outcome=\"transport_error\"} %d\n", stats.upstreamTransport.Load())
	_, _ = fmt.Fprintf(response, "# TYPE synthient_mcp_upstream_duration_seconds_total counter\nsynthient_mcp_upstream_duration_seconds_total %.6f\n", float64(stats.upstreamDurationNanos.Load())/float64(time.Second))
}

// rejectJSONRPCBatches refuses JSON-RPC batch bodies. Older MCP protocol
// versions allow batches, which would let one HTTP request start many tool
// calls while consuming a single concurrency slot and rate-limit unit.
func rejectJSONRPCBatches(maxBody int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Body == nil {
			next.ServeHTTP(response, request)
			return
		}
		body := http.MaxBytesReader(response, request.Body, maxBody)
		reader := bufio.NewReader(body)
		first, err := firstNonSpace(reader)
		if err == nil && first == '[' {
			writeError(response, http.StatusBadRequest, "JSON-RPC batch requests are not supported; send one message per request.")
			return
		}
		request.Body = struct {
			io.Reader
			io.Closer
		}{reader, body}
		next.ServeHTTP(response, request)
	})
}

func firstNonSpace(reader *bufio.Reader) (byte, error) {
	for {
		value, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}
		switch value {
		case ' ', '\t', '\r', '\n':
			continue
		}
		return value, reader.UnreadByte()
	}
}
