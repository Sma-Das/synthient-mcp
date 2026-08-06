package synthient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
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
