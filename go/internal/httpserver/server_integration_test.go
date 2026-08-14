package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Sma-Das/synthient-mcp/go/internal/config"
)

type observedRequest struct {
	Method       string
	Path         string
	APIKey       string
	ForwardedFor string
}

type headerTransport struct {
	base http.RoundTripper
}

func TestRootDoesNotServeALandingPage(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	response := httptest.NewRecorder()

	NewHandler(config.Config{}).ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
	}
}

func (transport headerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header.Set("X-API-Key", "caller-key-is-preserved")
	clone.Header.Set("X-Forwarded-For", "198.51.100.77")
	return transport.base.RoundTrip(clone)
}

func TestMCPServerNegotiatesModernProtocolAndCallsTool(t *testing.T) {
	seen := make(chan observedRequest, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		seen <- observedRequest{
			Method:       request.Method,
			Path:         request.URL.Path,
			APIKey:       request.Header.Get("X-API-Key"),
			ForwardedFor: request.Header.Get("X-Forwarded-For"),
		}
		response.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/api/v4/account/me" {
			_ = json.NewEncoder(response).Encode(map[string]any{
				"api_key":      "must-not-leave-the-server",
				"email":        "caller@example.com",
				"organization": map[string]any{"name": "Example Org"},
				"lookup_quota": map[string]any{"credits": 42, "resets_in": 60},
			})
			return
		}
		if request.URL.Path == "/api/v4/lookup/ips" {
			_ = json.NewEncoder(response).Encode(map[string]any{"results": []any{map[string]any{"ip": "8.8.8.8"}}})
			return
		}
		if request.URL.Path == "/api/v4/lookup/domain/example.com" {
			_ = json.NewEncoder(response).Encode(map[string]any{"domain": "example.com", "status": "active"})
			return
		}
		_ = json.NewEncoder(response).Encode(map[string]any{
			"ip":           "8.8.8.8",
			"intelligence": map[string]any{"risk_score": 0},
		})
	}))
	defer upstream.Close()

	baseURL, err := url.Parse(upstream.URL + "/api/v4/")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		AllowedHosts:     []string{"127.0.0.1"},
		AllowedOrigins:   []string{"http://127.0.0.1"},
		TrustProxyHops:   0,
		SynthientBaseURL: baseURL,
		RequestTimeout:   time.Second,
		MaxRequestBody:   1 << 20,
	}
	mcpHTTP := httptest.NewServer(NewHandler(cfg))
	defer mcpHTTP.Close()

	clientHTTP := &http.Client{Transport: headerTransport{base: http.DefaultTransport}}
	transport := &mcp.StreamableClientTransport{
		Endpoint:             mcpHTTP.URL + "/mcp",
		HTTPClient:           clientHTTP,
		DisableStandaloneSSE: true,
	}
	client := mcp.NewClient(
		&mcp.Implementation{Name: "integration-test", Version: "1.0.0"},
		&mcp.ClientOptions{Capabilities: &mcp.ClientCapabilities{}},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	if got := session.InitializeResult().ProtocolVersion; got != "2026-07-28" {
		t.Fatalf("protocol version = %q", got)
	}
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	var domainSchema map[string]any
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
		if tool.Name == "lookup_domain" {
			domainSchema, _ = tool.OutputSchema.(map[string]any)
		}
	}
	wantNames := []string{
		"feed_snapshot_meta",
		"get_account",
		"grpc_schema",
		"list_feed_snapshots",
		"list_feed_streams",
		"lookup_domain",
		"lookup_ip",
		"sample_stream",
	}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("tools = %#v", names)
	}
	domainProperties, _ := domainSchema["properties"].(map[string]any)
	if domainProperties["domain"] == nil || domainProperties["status"] == nil || domainProperties["type"] != nil {
		t.Fatalf("domain output schema = %#v", domainSchema)
	}

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "lookup_ip",
		Arguments: map[string]any{"ips": []string{"8.8.8.8"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("tool error: %#v", result.Content)
	}
	if len(result.Content) == 0 || !strings.Contains(result.Content[0].(*mcp.TextContent).Text, "risk score") {
		t.Fatalf("tool summary = %#v", result.Content)
	}
	output, ok := result.StructuredContent.(map[string]any)
	outputIPs, _ := output["ips"].([]any)
	if !ok || len(outputIPs) != 1 || outputIPs[0].(map[string]any)["ip"] != "8.8.8.8" {
		t.Fatalf("structured output = %#v", result.StructuredContent)
	}
	accountResult, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "get_account"})
	if err != nil {
		t.Fatal(err)
	}
	accountOutput, ok := accountResult.StructuredContent.(map[string]any)
	quota, _ := accountOutput["lookup_quota"].(map[string]any)
	if !ok || quota["credits"] != float64(42) {
		t.Fatalf("account output = %#v", accountResult.StructuredContent)
	}
	if _, exists := accountOutput["api_key"]; exists {
		t.Fatal("account tool exposed upstream api_key")
	}
	batchResult, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "lookup_ip",
		Arguments: map[string]any{"ips": []string{"8.8.8.8", "2001:0db8::1"}},
	})
	if err != nil || batchResult.IsError {
		t.Fatalf("batch result=%#v error=%v", batchResult, err)
	}
	domainResult, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "lookup_domain",
		Arguments: map[string]any{"domain": "Example.COM."},
	})
	if err != nil || domainResult.IsError {
		t.Fatalf("domain result=%#v error=%v", domainResult, err)
	}
	invalidResult, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "lookup_ip",
		Arguments: map[string]any{"ips": []string{"../../account/me"}},
	})
	if err != nil || !invalidResult.IsError {
		t.Fatalf("invalid input result=%#v error=%v", invalidResult, err)
	}

	request := <-seen
	wantRequest := observedRequest{
		Method:       http.MethodGet,
		Path:         "/api/v4/lookup/ip/8.8.8.8",
		APIKey:       "caller-key-is-preserved",
		ForwardedFor: "127.0.0.1",
	}
	if request != wantRequest {
		t.Fatalf("upstream request = %#v", request)
	}
	accountRequest := <-seen
	if accountRequest.APIKey != "caller-key-is-preserved" || accountRequest.ForwardedFor != "127.0.0.1" {
		t.Fatalf("account upstream request = %#v", accountRequest)
	}
	batchRequest := <-seen
	if batchRequest.Method != http.MethodPost || batchRequest.Path != "/api/v4/lookup/ips" {
		t.Fatalf("batch upstream request = %#v", batchRequest)
	}
	domainRequest := <-seen
	if domainRequest.Method != http.MethodGet || domainRequest.Path != "/api/v4/lookup/domain/example.com" {
		t.Fatalf("domain upstream request = %#v", domainRequest)
	}
	select {
	case unexpected := <-seen:
		t.Fatalf("invalid input reached upstream: %#v", unexpected)
	default:
	}
}

func TestMCPServerRejectsMissingCredential(t *testing.T) {
	baseURL, _ := url.Parse("http://127.0.0.1:1/api/v4/")
	cfg := config.Config{
		AllowedHosts:     []string{"example.com"},
		AllowedOrigins:   []string{"https://example.com"},
		SynthientBaseURL: baseURL,
		RequestTimeout:   time.Second,
		MaxRequestBody:   1 << 20,
	}
	request := httptest.NewRequest(http.MethodPost, "http://example.com/mcp", nil)
	response := httptest.NewRecorder()

	NewHandler(cfg).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
	}
}

func TestMCPServerRejectsDisallowedOrigin(t *testing.T) {
	baseURL, _ := url.Parse("http://127.0.0.1:1/api/v4/")
	cfg := config.Config{
		AllowedHosts:     []string{"example.com"},
		AllowedOrigins:   []string{"https://example.com"},
		SynthientBaseURL: baseURL,
		RequestTimeout:   time.Second,
		MaxRequestBody:   1 << 20,
	}
	request := httptest.NewRequest(http.MethodPost, "http://example.com/mcp", nil)
	request.Header.Set("Origin", "https://evil.example")
	request.Header.Set("X-API-Key", "key")
	response := httptest.NewRecorder()

	NewHandler(cfg).ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
	}
}

func TestMCPServerRejectsDisallowedHost(t *testing.T) {
	cfg := config.Config{AllowedHosts: []string{"example.com"}}
	request := httptest.NewRequest(http.MethodPost, "http://evil.example/mcp", nil)
	request.Header.Set("X-API-Key", "key")
	response := httptest.NewRecorder()

	NewHandler(cfg).ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
	}
}

func TestMCPServerRequiresExactTrustedOrigin(t *testing.T) {
	cfg := config.Config{
		AllowedHosts:   []string{"service.example"},
		AllowedOrigins: []string{"https://app.example:8443"},
	}
	for _, origin := range []string{"https://app.example", "http://app.example:8443", "https://app.example:9443"} {
		request := httptest.NewRequest(http.MethodPost, "https://service.example/mcp", nil)
		request.Header.Set("Origin", origin)
		request.Header.Set("X-API-Key", "key")
		response := httptest.NewRecorder()

		NewHandler(cfg).ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Errorf("origin %q status = %d; body = %s", origin, response.Code, response.Body.String())
		}
	}
}

func TestMCPServerRequiresExactSameHostOrigin(t *testing.T) {
	cfg := config.Config{AllowedHosts: []string{"service.example"}}
	request := httptest.NewRequest(http.MethodPost, "https://service.example/mcp", nil)
	request.Header.Set("Origin", "https://service.example:8443")
	request.Header.Set("X-API-Key", "key")
	response := httptest.NewRecorder()

	NewHandler(cfg).ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
	}
}

func TestMCPServerRejectsAmbiguousCredentialHeader(t *testing.T) {
	cfg := config.Config{AllowedHosts: []string{"example.com"}}
	request := httptest.NewRequest(http.MethodPost, "http://example.com/mcp", nil)
	request.Header["X-Api-Key"] = []string{"first", "second"}
	response := httptest.NewRecorder()

	NewHandler(cfg).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
	}
}

func TestHealthAndMetricsAreSecretSafeAndNonCacheable(t *testing.T) {
	cfg := config.Config{MetricsEnabled: true}
	handler := NewHandler(cfg)
	for _, path := range []string{"/healthz", "/metrics"} {
		request := httptest.NewRequest(http.MethodGet, "http://example.com"+path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s status=%d cache=%q", path, response.Code, response.Header().Get("Cache-Control"))
		}
		if strings.Contains(response.Body.String(), "X-API-Key") {
			t.Errorf("%s exposed credential metadata", path)
		}
	}
}

func TestConcurrentLimitFailsFast(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	limited := limitConcurrent(1, &telemetry{}, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		response.WriteHeader(http.StatusNoContent)
	}))
	firstDone := make(chan struct{})
	go func() {
		limited.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "http://example.com/mcp", nil))
		close(firstDone)
	}()
	<-started
	second := httptest.NewRecorder()
	limited.ServeHTTP(second, httptest.NewRequest(http.MethodPost, "http://example.com/mcp", nil))
	if second.Code != http.StatusServiceUnavailable || second.Header().Get("Retry-After") == "" {
		t.Fatalf("status=%d headers=%v", second.Code, second.Header())
	}
	close(release)
	<-firstDone
}

func TestMCPServerRejectsOversizedBody(t *testing.T) {
	cfg := config.Config{
		AllowedHosts:   []string{"example.com"},
		MaxRequestBody: 64,
	}
	request := httptest.NewRequest(http.MethodPost, "http://example.com/mcp", strings.NewReader(strings.Repeat("x", 65)))
	request.Header.Set("X-API-Key", "key")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response := httptest.NewRecorder()

	NewHandler(cfg).ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
	}
}
