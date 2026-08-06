package httpserver

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Sma-Das/synthient-mcp/go/internal/config"
	"github.com/Sma-Das/synthient-mcp/go/internal/forwarding"
	"github.com/Sma-Das/synthient-mcp/go/internal/mcpserver"
	"github.com/Sma-Das/synthient-mcp/go/internal/synthient"
)

func NewHandler(cfg config.Config) http.Handler {
	schemaCache := mcp.NewSchemaCache()
	apiClient := &http.Client{Timeout: cfg.RequestTimeout}

	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(request *http.Request) *mcp.Server {
			client := synthient.NewClient(
				cfg.SynthientBaseURL,
				request.Header.Get("X-API-Key"),
				request.Header.Get("X-Forwarded-For"),
				apiClient,
			)
			return mcpserver.New(client, schemaCache)
		},
		&mcp.StreamableHTTPOptions{
			Stateless:                    true,
			JSONResponse:                 true,
			MaxRequestBodyBytes:          cfg.MaxRequestBody,
			PropagateRequestCancellation: true,
		},
	)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]string{"status": "ok"})
	})
	mux.Handle("/mcp", protectMCP(cfg, mcpHandler))
	return mux
}

func protectMCP(cfg config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !allowedRequestHost(request.Host, cfg.AllowedHosts) {
			writeError(response, http.StatusForbidden, "Host header is not allowed")
			return
		}
		if !allowedOrigin(request.Header.Get("Origin"), cfg.AllowedOrigins) {
			writeError(response, http.StatusForbidden, "Origin header is not allowed")
			return
		}
		if strings.TrimSpace(request.Header.Get("X-API-Key")) == "" {
			writeError(response, http.StatusUnauthorized, "Provide your Synthient API key in the x-api-key header.")
			return
		}

		clientIP, err := forwarding.CanonicalClientIP(request, cfg.TrustProxyHops)
		if err != nil {
			writeError(response, http.StatusBadRequest, err.Error())
			return
		}
		request.Header.Set("X-Forwarded-For", clientIP)
		next.ServeHTTP(response, request)
	})
}

func allowedRequestHost(value string, allowed []string) bool {
	host := value
	if parsed, _, err := net.SplitHostPort(value); err == nil {
		host = parsed
	}
	return containsHostname(allowed, host)
}

func allowedOrigin(value string, allowed []string) bool {
	if value == "" {
		return true
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	return containsHostname(allowed, parsed.Hostname())
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
