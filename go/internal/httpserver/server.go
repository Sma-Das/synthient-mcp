package httpserver

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

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
	stats := &telemetry{}

	schemaCache := mcp.NewSchemaCache()
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(request *http.Request) *mcp.Server {
			client := synthient.NewClient(
				cfg.SynthientBaseURL,
				request.Header.Get("X-API-Key"),
				request.Header.Get("X-Forwarded-For"),
				apiClient,
				stats,
			)
			return mcpserver.New(client, schemaCache)
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

	mcpRoute := limitConcurrent(maxConcurrent, stats, mcpHandler)
	mcpRoute = protectMCP(cfg, mcpRoute)
	mcpRoute = requireExactOrigin(cfg.AllowedOrigins, mcpRoute)
	mcpRoute = crossOrigin.Handler(mcpRoute)

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
	mux.Handle("/mcp", mcpRoute)
	return observeRequests(logger, stats, mux)
}

func requireExactOrigin(allowed []string, next http.Handler) http.Handler {
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
		scheme := "http"
		if request.TLS != nil {
			scheme = "https"
		}
		requestOrigin := (&url.URL{Scheme: scheme, Host: strings.ToLower(request.Host)}).String()
		if canonical == requestOrigin || stringInSlice(allowed, canonical) {
			next.ServeHTTP(response, request)
			return
		}
		writeError(response, http.StatusForbidden, "Origin header is not allowed")
	})
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

		clientIP, err := forwarding.CanonicalClientIP(request, cfg.TrustProxyHops, cfg.TrustedProxyCIDRs)
		if err != nil {
			writeError(response, http.StatusBadRequest, err.Error())
			return
		}
		request.Header.Set("X-Forwarded-For", clientIP)
		next.ServeHTTP(response, request)
	})
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
		level := slog.LevelInfo
		if request.URL.Path == "/healthz" || request.URL.Path == "/metrics" {
			level = slog.LevelDebug
		}
		logger.Log(request.Context(), level, "HTTP request",
			"request_id", requestID,
			"method", request.Method,
			"path", request.URL.Path,
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
	_, _ = fmt.Fprintf(response, "# TYPE synthient_mcp_upstream_requests_total counter\nsynthient_mcp_upstream_requests_total %d\n", stats.upstreamRequests.Load())
	_, _ = fmt.Fprintln(response, "# TYPE synthient_mcp_upstream_requests_by_outcome counter")
	_, _ = fmt.Fprintf(response, "synthient_mcp_upstream_requests_by_outcome{outcome=\"success\"} %d\n", stats.upstreamSuccess.Load())
	_, _ = fmt.Fprintf(response, "synthient_mcp_upstream_requests_by_outcome{outcome=\"client_error\"} %d\n", stats.upstreamClientErrors.Load())
	_, _ = fmt.Fprintf(response, "synthient_mcp_upstream_requests_by_outcome{outcome=\"server_error\"} %d\n", stats.upstreamServerErrors.Load())
	_, _ = fmt.Fprintf(response, "synthient_mcp_upstream_requests_by_outcome{outcome=\"transport_error\"} %d\n", stats.upstreamTransport.Load())
	_, _ = fmt.Fprintf(response, "# TYPE synthient_mcp_upstream_duration_seconds_total counter\nsynthient_mcp_upstream_duration_seconds_total %.6f\n", float64(stats.upstreamDurationNanos.Load())/float64(time.Second))
}
