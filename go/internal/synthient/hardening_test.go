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
	if len(echo) != 0 {
		t.Fatalf("credential-bearing key survived: echo = %#v", echo)
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

func TestSampleStreamHandlesCRLFDelimiters(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte("{\"ip\":\"192.0.2.1\"}\r\n{\"ip\":\"192.0.2.2\"}\r\n"))
	}))
	defer server.Close()

	events, truncated, err := client.SampleStream(context.Background(), "proxies", 5, 1024, nil)
	if err != nil || truncated || len(events) != 2 {
		t.Fatalf("events=%#v truncated=%t error=%v", events, truncated, err)
	}
}

func TestSampleStreamReadBudgetCountsBytesFromTheConnection(t *testing.T) {
	previous := maxStreamReadBytes
	defer func() { maxStreamReadBytes = previous }()
	line := "{\"ip\":\"192.0.2.1\"}\r\n"
	for _, test := range []struct {
		name      string
		budget    int64
		events    int
		truncated bool
	}{
		{name: "budget above stream", budget: int64(len(line)*2 + 1), events: 2},
		{name: "budget cuts the second line", budget: int64(len(line) + 5), events: 1, truncated: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			maxStreamReadBytes = test.budget
			client, server := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				_, _ = response.Write([]byte(line + line))
			}))
			defer server.Close()
			events, truncated, err := client.SampleStream(context.Background(), "proxies", 5, 1024, nil)
			if err != nil || truncated != test.truncated || len(events) != test.events {
				t.Fatalf("events=%d truncated=%t error=%v", len(events), truncated, err)
			}
		})
	}
}

func TestSampleStreamClassifiesLinesAtTheReadBudget(t *testing.T) {
	previous := maxStreamReadBytes
	defer func() { maxStreamReadBytes = previous }()
	first := "{\"ip\":\"192.0.2.1\"}\n"
	for _, test := range []struct {
		name      string
		stream    string
		budget    int64
		count     int
		events    int
		truncated bool
		wantErr   bool
	}{
		// A complete malformed line is an upstream error even at the budget.
		{name: "complete non-object line at budget", stream: first + "[]\n", budget: int64(len(first) + 3), count: 5, events: 1, wantErr: true},
		// A cut-off line whose prefix happens to be valid JSON is discarded.
		{name: "cut line with valid prefix", stream: first + "{\"ip\":\"192.0.2.2\"}{\"x\":1}\n", budget: int64(len(first) + len(`{"ip":"192.0.2.2"}`)), count: 2, events: 1, truncated: true},
		// A stream that ends without a final newline still yields its event.
		{name: "natural end without newline", stream: first + `{"ip":"192.0.2.2"}`, budget: 1 << 20, count: 5, events: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			maxStreamReadBytes = test.budget
			client, server := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				_, _ = response.Write([]byte(test.stream))
			}))
			defer server.Close()
			events, truncated, err := client.SampleStream(context.Background(), "proxies", test.count, 1024, nil)
			if (err != nil) != test.wantErr || truncated != test.truncated || len(events) != test.events {
				t.Fatalf("events=%d truncated=%t error=%v", len(events), truncated, err)
			}
		})
	}
}

func TestSampleStreamRejectsOversizedEvents(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte("{\"pad\":\"" + strings.Repeat("x", maxStreamEventBytes) + "\"}\n"))
	}))
	defer server.Close()
	if _, _, err := client.SampleStream(context.Background(), "proxies", 1, 1<<20, nil); err == nil {
		t.Fatal("oversized event was accepted")
	}
}
