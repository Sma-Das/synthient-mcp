package synthient

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestParseRetryAfterNormalizesToSeconds(t *testing.T) {
	now := time.Date(2026, time.November, 26, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		value string
		want  string
	}{
		{"30", "30"},
		{" 0 ", "0"},
		{"999999999", "86400"},
		{now.Add(90 * time.Second).Format(http.TimeFormat), "90"},
		{now.Add(-time.Hour).Format(http.TimeFormat), "0"},
		{"-5", ""},
		{"soon; key=exact-caller-key", ""},
		{"", ""},
	} {
		if got := parseRetryAfter(test.value, now); got != test.want {
			t.Errorf("parseRetryAfter(%q) = %q; want %q", test.value, got, test.want)
		}
	}
}

func TestClientDoesNotRelayRawRetryAfterHeader(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Retry-After", "exact-caller-key")
		response.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	_, err := client.Account(context.Background())
	var apiError *APIError
	if !errors.As(err, &apiError) || apiError.RetryAfter != "" || strings.Contains(err.Error(), "exact-caller-key") {
		t.Fatalf("error = %#v", err)
	}
}

func TestClientRedactsCredentialFromPropertyNames(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"email":"a@example.com","echo":{"exact-caller-key":"value"}}`))
	}))
	defer server.Close()

	value, err := client.request(context.Background(), http.MethodGet, []string{"account", "me"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	echo, _ := value["echo"].(map[string]any)
	if _, leaked := echo["exact-caller-key"]; leaked || echo["[REDACTED]"] != "value" {
		t.Fatalf("echo = %#v", echo)
	}
}

func TestSampleStreamRejectsNonObjectEventsAndSendsUserAgent(t *testing.T) {
	userAgent := make(chan string, 1)
	client, server := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		userAgent <- request.Header.Get("User-Agent")
		_, _ = response.Write([]byte("null\n"))
	}))
	defer server.Close()

	if _, _, err := client.SampleStream(context.Background(), "proxies", 1, 1024, nil); err == nil {
		t.Fatal("null event was accepted")
	}
	if got := <-userAgent; !strings.HasPrefix(got, "synthient-mcp") {
		t.Fatalf("User-Agent = %q", got)
	}
}

func TestSampleStreamOutputLimitCountsSerializedEvents(t *testing.T) {
	// Whitespace-padded upstream lines must not count against the output
	// budget, and the redacted, serialized form must.
	client, server := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte("{  \"ip\" :   \"192.0.2.1\"  }\n{\"ip\":\"192.0.2.2\"}\n"))
	}))
	defer server.Close()

	events, truncated, err := client.SampleStream(context.Background(), "proxies", 5, len(`{"ip":"192.0.2.1"}`)*2+2, nil)
	if err != nil || truncated || len(events) != 2 {
		t.Fatalf("events=%#v truncated=%t error=%v", events, truncated, err)
	}
}

func TestSampleStreamUsesDedicatedStreamClient(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte("{\"ip\":\"192.0.2.1\"}\n"))
	}))
	defer server.Close()

	used := false
	client.WithStreamHTTPClient(doerFunc(func(request *http.Request) (*http.Response, error) {
		used = true
		return server.Client().Do(request)
	}))
	if _, _, err := client.SampleStream(context.Background(), "proxies", 1, 1024, nil); err != nil || !used {
		t.Fatalf("used=%t error=%v", used, err)
	}
}

type doerFunc func(*http.Request) (*http.Response, error)

func (function doerFunc) Do(request *http.Request) (*http.Response, error) { return function(request) }
