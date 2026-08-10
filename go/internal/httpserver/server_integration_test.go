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

func testConfig() config.Config {
	baseURL, _ := url.Parse("http://127.0.0.1:1/api/v4/")
	return config.Config{
		AllowedHosts:     []string{"example.com"},
		AllowedOrigins:   []string{"example.com"},
		SynthientBaseURL: baseURL,
		RequestTimeout:   time.Second,
		MaxRequestBody:   1 << 20,
	}
}

func TestLandingPageIncludesSearchMetadataAndStructuredContent(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	response := httptest.NewRecorder()

	NewHandler(testConfig()).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("content type = %q", got)
	}
	body := response.Body.String()
	for _, required := range []string{
		"<title>Synthient MCP Server for IP &amp; Domain Intelligence</title>",
		`<meta name="description"`,
		`<meta property="og:title"`,
		`<script type="application/ld+json">`,
		`<html lang="en">`,
	} {
		if !strings.Contains(body, required) {
			t.Errorf("landing page does not contain %q", required)
		}
	}
	if count := strings.Count(body, "<h1>"); count != 1 {
		t.Errorf("h1 count = %d", count)
	}
}

func TestCrawlerControlsKeepProtocolEndpointsOutOfSearch(t *testing.T) {
	handler := NewHandler(testConfig())

	robotsRequest := httptest.NewRequest(http.MethodGet, "http://example.com/robots.txt", nil)
	robotsResponse := httptest.NewRecorder()
	handler.ServeHTTP(robotsResponse, robotsRequest)
	if robotsResponse.Code != http.StatusOK || !strings.Contains(robotsResponse.Body.String(), "Disallow: /mcp") {
		t.Fatalf("robots response = %d %q", robotsResponse.Code, robotsResponse.Body.String())
	}

	mcpRequest := httptest.NewRequest(http.MethodPost, "http://example.com/mcp", nil)
	mcpResponse := httptest.NewRecorder()
	handler.ServeHTTP(mcpResponse, mcpRequest)
	if got := mcpResponse.Header().Get("X-Robots-Tag"); got != "noindex, nofollow" {
		t.Fatalf("X-Robots-Tag = %q", got)
	}
}

func (transport headerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header.Set("X-API-Key", "caller-key-is-preserved")
	clone.Header.Set("X-Forwarded-For", "198.51.100.77")
	return transport.base.RoundTrip(clone)
}

func TestMCPServerNegotiatesModernProtocolAndCallsTool(t *testing.T) {
	seen := make(chan observedRequest, 2)
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
				"api_key": "must-not-leave-the-server",
				"credits": 42,
			})
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
		AllowedOrigins:   []string{"127.0.0.1"},
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
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
	}
	wantNames := []string{
		"synthient_account",
		"synthient_lookup_domain",
		"synthient_lookup_ip",
		"synthient_lookup_ips",
	}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("tools = %#v", names)
	}

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "synthient_lookup_ip",
		Arguments: map[string]any{"ip": "8.8.8.8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("tool error: %#v", result.Content)
	}
	output, ok := result.StructuredContent.(map[string]any)
	if !ok || output["ip"] != "8.8.8.8" {
		t.Fatalf("structured output = %#v", result.StructuredContent)
	}
	accountResult, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "synthient_account"})
	if err != nil {
		t.Fatal(err)
	}
	accountOutput, ok := accountResult.StructuredContent.(map[string]any)
	if !ok || accountOutput["credits"] != float64(42) {
		t.Fatalf("account output = %#v", accountResult.StructuredContent)
	}
	if _, exists := accountOutput["api_key"]; exists {
		t.Fatal("account tool exposed upstream api_key")
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
}

func TestMCPServerRejectsMissingCredential(t *testing.T) {
	baseURL, _ := url.Parse("http://127.0.0.1:1/api/v4/")
	cfg := config.Config{
		AllowedHosts:     []string{"example.com"},
		AllowedOrigins:   []string{"example.com"},
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
		AllowedOrigins:   []string{"example.com"},
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
