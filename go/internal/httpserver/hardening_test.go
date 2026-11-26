package httpserver

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Sma-Das/synthient-mcp/go/internal/config"
)

func TestForwardedClientIPIsResolvedBeforeTheChainIsStripped(t *testing.T) {
	cfg := config.Config{
		AllowedHosts:      []string{"service.example"},
		ForwardClientIP:   true,
		TrustProxyHops:    1,
		TrustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	for _, test := range []struct {
		name      string
		forwarded string
		remote    string
		want      string
		status    int
	}{
		{name: "one trusted hop", forwarded: "203.0.113.9", remote: "10.0.0.5:4000", want: "203.0.113.9", status: http.StatusNoContent},
		{name: "spoofed prefix is ignored", forwarded: "192.0.2.66, 203.0.113.9", remote: "10.0.0.5:4000", want: "203.0.113.9", status: http.StatusNoContent},
		{name: "untrusted peer", forwarded: "203.0.113.9", remote: "198.51.100.1:4000", status: http.StatusBadRequest},
		{name: "missing chain", remote: "10.0.0.5:4000", status: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := ""
			handler := protectMCP(cfg, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				got = strings.Join(request.Header.Values("X-Forwarded-For"), "|")
				response.WriteHeader(http.StatusNoContent)
			}))
			request := httptest.NewRequest(http.MethodPost, "http://service.example/mcp", nil)
			request.RemoteAddr = test.remote
			request.Header.Set("X-API-Key", "key")
			if test.forwarded != "" {
				request.Header.Set("X-Forwarded-For", test.forwarded)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || got != test.want {
				t.Fatalf("status=%d forwarded=%q; want status=%d forwarded=%q", response.Code, got, test.status, test.want)
			}
		})
	}
}

func TestJSONRPCBatchesAreRejected(t *testing.T) {
	var received string
	handler := rejectJSONRPCBatches(1<<20, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		received = string(body)
		response.WriteHeader(http.StatusNoContent)
	}))

	batch := httptest.NewRecorder()
	handler.ServeHTTP(batch, httptest.NewRequest(http.MethodPost, "http://example.com/mcp", strings.NewReader(" \n\t[{\"jsonrpc\":\"2.0\"}]")))
	if batch.Code != http.StatusBadRequest {
		t.Fatalf("batch status=%d body=%s", batch.Code, batch.Body.String())
	}

	single := httptest.NewRecorder()
	handler.ServeHTTP(single, httptest.NewRequest(http.MethodPost, "http://example.com/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1}`)))
	if single.Code != http.StatusNoContent || received != `{"jsonrpc":"2.0","id":1}` {
		t.Fatalf("single status=%d received=%q", single.Code, received)
	}
}

func TestCORSPreflightAllowsMCPStandardHeadersAndExposesChallenge(t *testing.T) {
	cfg := config.Config{AllowedHosts: []string{"service.example"}, AllowedOrigins: []string{"https://app.example"}, CORSEnabled: true}
	request := httptest.NewRequest(http.MethodOptions, "https://service.example/mcp", nil)
	request.Header.Set("Origin", "https://app.example")
	request.Header.Set("Access-Control-Request-Method", "POST")
	response := httptest.NewRecorder()
	NewHandler(cfg).ServeHTTP(response, request)

	allowed := response.Header().Get("Access-Control-Allow-Headers")
	for _, header := range []string{"Mcp-Method", "Mcp-Name", "MCP-Protocol-Version", "Authorization"} {
		if !strings.Contains(allowed, header) {
			t.Fatalf("Access-Control-Allow-Headers = %q; missing %s", allowed, header)
		}
	}
	if exposed := response.Header().Get("Access-Control-Expose-Headers"); !strings.Contains(exposed, "WWW-Authenticate") {
		t.Fatalf("Access-Control-Expose-Headers = %q", exposed)
	}
}

func TestSameOriginIsAdmittedBehindTrustedTLSProxy(t *testing.T) {
	cfg := config.Config{
		AllowedHosts:      []string{"service.example"},
		CORSEnabled:       true,
		TrustProxyHops:    1,
		TrustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	inner := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	})
	handler := allowCORS(cfg, requireExactOrigin(cfg, inner))

	for _, test := range []struct {
		name   string
		remote string
		status int
	}{
		{name: "trusted proxy", remote: "10.0.0.2:5000", status: http.StatusNoContent},
		{name: "untrusted peer cannot claim https", remote: "198.51.100.2:5000", status: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://service.example/mcp", nil)
			request.RemoteAddr = test.remote
			request.Header.Set("Origin", "https://service.example")
			request.Header.Set("X-Forwarded-Proto", "https")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d; want %d; body=%s", response.Code, test.status, response.Body.String())
			}
		})
	}
}

func TestRateLimiterEvictsInsteadOfLockingOutNewPrincipals(t *testing.T) {
	now := time.Date(2026, time.November, 26, 12, 0, 0, 0, time.UTC)
	limiter := &principalRateLimiter{
		limit:   5,
		now:     func() time.Time { return now },
		windows: make(map[string]principalRateWindow, maxTrackedRatePrincipals),
		stats:   &telemetry{},
	}
	for index := range maxTrackedRatePrincipals {
		limiter.windows[fmt.Sprintf("api-key:flood-%d", index)] = principalRateWindow{count: 1, resetAt: now.Add(time.Duration(index+1) * time.Millisecond)}
	}
	handler := limiter.handler(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, "http://example.com/mcp", nil)
	request.Header.Set("X-API-Key", "legitimate")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(limiter.windows) > maxTrackedRatePrincipals {
		t.Fatalf("tracked principals = %d", len(limiter.windows))
	}
	if _, exists := limiter.windows["api-key:flood-0"]; exists {
		t.Fatal("window closest to expiry was not evicted")
	}
}

func TestAccessLogRecordsRoutePatternNotRawPath(t *testing.T) {
	var logs bytes.Buffer
	handler := NewHandlerWithLogger(config.Config{}, slog.New(slog.NewTextHandler(&logs, nil)))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.com/leaked-secret-token", nil))
	if strings.Contains(logs.String(), "leaked-secret-token") || !strings.Contains(logs.String(), "route=unmatched") {
		t.Fatalf("log = %q", logs.String())
	}
}
