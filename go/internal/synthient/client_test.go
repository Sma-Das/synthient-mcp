package synthient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newTestClient(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	baseURL, err := url.Parse(server.URL + "/api/v4/")
	if err != nil {
		t.Fatal(err)
	}
	return NewClient(baseURL, "exact-caller-key", "203.0.113.9", server.Client()), server
}

func TestClientForwardsCredentialAndCallerIP(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v4/lookup/ip/2001:db8::1" {
			t.Errorf("path = %q", request.URL.Path)
		}
		if got := request.Header.Get("X-API-Key"); got != "exact-caller-key" {
			t.Errorf("api key = %q", got)
		}
		if got := request.Header.Get("X-Forwarded-For"); got != "203.0.113.9" {
			t.Errorf("forwarded for = %q", got)
		}
		_ = json.NewEncoder(response).Encode(map[string]any{"ip": "2001:db8::1"})
	}))
	defer server.Close()

	result, err := client.LookupIP(context.Background(), "2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	if result["ip"] != "2001:db8::1" {
		t.Fatalf("result = %#v", result)
	}
}

func TestClientSendsBatchShape(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v4/lookup/ips" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		var body map[string][]string
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if len(body["ips"]) != 2 {
			t.Errorf("body = %#v", body)
		}
		_ = json.NewEncoder(response).Encode(map[string]any{"results": []any{}})
	}))
	defer server.Close()

	if _, err := client.LookupIPs(context.Background(), []string{"8.8.8.8", "1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
}

func TestClientPreservesRetryGuidance(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Retry-After", "12")
		response.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(response).Encode(map[string]any{"message": "rate limit exceeded"})
	}))
	defer server.Close()

	_, err := client.Account(context.Background())
	var apiError *APIError
	if !errors.As(err, &apiError) {
		t.Fatalf("error = %v", err)
	}
	if apiError.Status != 429 || apiError.RetryAfter != "12" {
		t.Fatalf("API error = %#v", apiError)
	}
}

func TestClientRejectsNonJSONSuccess(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte("temporarily unavailable"))
	}))
	defer server.Close()

	_, err := client.Account(context.Background())
	var apiError *APIError
	if !errors.As(err, &apiError) || apiError.Status != http.StatusBadGateway {
		t.Fatalf("error = %#v", err)
	}
}

func TestClientDoesNotForwardCredentialAcrossRedirect(t *testing.T) {
	leaked := make(chan string, 1)
	destination := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		leaked <- request.Header.Get("X-API-Key")
		_ = json.NewEncoder(response).Encode(map[string]any{"unexpected": true})
	}))
	defer destination.Close()

	client, source := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, destination.URL, http.StatusFound)
	}))
	defer source.Close()

	_, err := client.Account(context.Background())
	var apiError *APIError
	if !errors.As(err, &apiError) || apiError.Status != http.StatusFound {
		t.Fatalf("error = %#v", err)
	}
	select {
	case key := <-leaked:
		t.Fatalf("redirect destination received credential %q", key)
	default:
	}
}

func TestClientEscapesOpaquePathSegments(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got := request.RequestURI; got != "/api/v4/lookup/domain/..%2F..%2Faccount%2Fme" {
			t.Errorf("request URI = %q", got)
		}
		_ = json.NewEncoder(response).Encode(map[string]any{"type": "domain"})
	}))
	defer server.Close()

	if _, err := client.LookupDomain(context.Background(), "../../account/me"); err != nil {
		t.Fatal(err)
	}
}

func TestClientRedactsCredentialFromErrorsAndResponses(t *testing.T) {
	requestCount := 0
	client, server := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requestCount++
		if requestCount == 1 {
			response.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(response).Encode(map[string]any{"message": "invalid exact-caller-key"})
			return
		}
		_ = json.NewEncoder(response).Encode(map[string]any{
			"api_key": "exact-caller-key",
			"nested": map[string]any{
				"access_token": "exact-caller-key",
				"note":         "credential exact-caller-key was accepted",
			},
		})
	}))
	defer server.Close()

	_, err := client.Account(context.Background())
	if err == nil || strings.Contains(err.Error(), "exact-caller-key") {
		t.Fatalf("error was not safely redacted: %v", err)
	}
	result, err := client.Account(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := result["api_key"]; exists {
		t.Fatalf("response retained credential field: %#v", result)
	}
	nested := result["nested"].(map[string]any)
	if _, exists := nested["access_token"]; exists || strings.Contains(nested["note"].(string), "exact-caller-key") {
		t.Fatalf("nested response was not redacted: %#v", nested)
	}
}

func TestClientPreservesLargeJSONIntegers(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"identifier":9007199254740993}`))
	}))
	defer server.Close()

	result, err := client.Account(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := result["identifier"].(json.Number).String(); got != "9007199254740993" {
		t.Fatalf("identifier = %q", got)
	}
}

func TestClientPropagatesTimeoutCancellation(t *testing.T) {
	cancelled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
		close(cancelled)
	}))
	defer server.Close()
	baseURL, err := url.Parse(server.URL + "/api/v4/")
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(baseURL, "exact-caller-key", "203.0.113.9", &http.Client{Timeout: 50 * time.Millisecond})

	if _, err := client.Account(context.Background()); err == nil {
		t.Fatal("expected timeout error")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("upstream request context was not cancelled")
	}
}
