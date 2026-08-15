package synthient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestFeedSnapshotsAndMetadataPaths(t *testing.T) {
	requests := 0
	client, server := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		response.Header().Set("Content-Type", "application/json")
		switch requests {
		case 1:
			if request.URL.Path != "/api/v4/feeds/proxies/export" || request.URL.Query().Get("limit") != "25" || request.URL.Query().Get("cursor") != "next" {
				t.Errorf("snapshots request = %s", request.URL.String())
			}
			_ = json.NewEncoder(response).Encode(map[string]any{"stream": "proxies", "feeds": []any{}, "next_cursor": "after"})
		case 2:
			if request.URL.Path != "/api/v4/feeds/helio/dns/export/2026-08-14/12/meta" {
				t.Errorf("metadata path = %q", request.URL.Path)
			}
			_ = json.NewEncoder(response).Encode(map[string]any{"stream": "honeypot_dns", "id": "2026-08-14/12", "rows": 42})
		}
	}))
	defer server.Close()

	page, err := client.FeedSnapshots(context.Background(), "proxies", 25, "next")
	if err != nil || page.NextCursor != "after" {
		t.Fatalf("page=%#v error=%v", page, err)
	}
	meta, err := client.FeedSnapshotMeta(context.Background(), "honeypot_dns", []string{"2026-08-14", "12"})
	if err != nil || meta.Rows != 42 {
		t.Fatalf("meta=%#v error=%v", meta, err)
	}
}

func TestSampleStreamUsesTheOperationContextDeadline(t *testing.T) {
	upstream := newDelayedStreamServer(t, 75*time.Millisecond)
	defer upstream.Close()
	baseURL, err := url.Parse(upstream.URL + "/api/v4/")
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(baseURL, "test-key", "", &http.Client{Timeout: 10 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	events, _, err := client.SampleStream(ctx, "proxies", 1, 1024, nil)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%#v error=%v", events, err)
	}
}

func newDelayedStreamServer(t *testing.T, delay time.Duration) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		time.Sleep(delay)
		_, _ = response.Write([]byte("{\"ip\":\"192.0.2.1\"}\n"))
	}))
}

func TestSampleStreamFiltersAndBoundsEvents(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v4/feeds/proxies/stream" {
			t.Errorf("stream path = %q", request.URL.Path)
		}
		response.Header().Set("Content-Type", "application/x-ndjson")
		_, _ = response.Write([]byte("{\"ip\":\"192.0.2.1\",\"type\":\"DATACENTER_PROXY\"}\n"))
		_, _ = response.Write([]byte("{\"ip\":\"192.0.2.2\",\"type\":\"RESIDENTIAL_PROXY\"}\n"))
		_, _ = response.Write([]byte("{\"ip\":\"192.0.2.3\",\"type\":\"RESIDENTIAL_PROXY\"}\n"))
	}))
	defer server.Close()

	events, truncated, err := client.SampleStream(context.Background(), "proxies", 2, 1024, map[string]string{"type": "RESIDENTIAL_PROXY"})
	if err != nil || truncated || len(events) != 2 || events[0]["ip"] != "192.0.2.2" {
		t.Fatalf("events=%#v truncated=%t error=%v", events, truncated, err)
	}
}

func TestSampleStreamStopsAtOutputLimit(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte("{\"ip\":\"192.0.2.1\"}\n{\"ip\":\"192.0.2.2\"}\n"))
	}))
	defer server.Close()

	events, truncated, err := client.SampleStream(context.Background(), "proxies", 2, 24, nil)
	if err != nil || !truncated || len(events) != 1 {
		t.Fatalf("events=%#v truncated=%t error=%v", events, truncated, err)
	}
}
