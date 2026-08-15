package synthient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	synthientsdk "github.com/synthient/go-synthient/v2"
)

const (
	maxStreamEventBytes = 256 << 10
	maxStreamReadBytes  = 8 << 20
)

func (c *Client) FeedSnapshots(ctx context.Context, stream string, limit int, cursor string) (synthientsdk.FeedSnapshotsPage, error) {
	query := url.Values{}
	if limit > 0 {
		query.Set("limit", fmt.Sprint(limit))
	}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	return requestAsQuery[synthientsdk.FeedSnapshotsPage](ctx, c, http.MethodGet, append([]string{"feeds"}, append(feedPath(stream), "export")...), query, nil)
}

func (c *Client) FeedSnapshotMeta(ctx context.Context, stream string, snapshot []string) (synthientsdk.FeedSnapshotMeta, error) {
	path := append([]string{"feeds"}, feedPath(stream)...)
	path = append(path, "export")
	path = append(path, snapshot...)
	path = append(path, "meta")
	return requestAs[synthientsdk.FeedSnapshotMeta](ctx, c, http.MethodGet, path, nil)
}

func (c *Client) GRPCSchema(ctx context.Context, symbols []string) (synthientsdk.GRPCSchemaResult, error) {
	client := synthientsdk.NewClient(c.apiKey)
	return client.GRPCSchema(ctx, &synthientsdk.GRPCSchemaOptions{
		Endpoint: c.grpcEndpoint,
		Symbols:  symbols,
	})
}

func (c *Client) SampleStream(ctx context.Context, stream string, count int, outputLimit int, filters map[string]string) ([]map[string]any, bool, error) {
	path := append([]string{"feeds"}, feedPath(stream)...)
	path = append(path, "stream")
	request, err := c.newRequest(ctx, http.MethodGet, path)
	if err != nil {
		return nil, false, err
	}

	started := time.Now()
	doer := c.httpClient
	if client, ok := c.httpClient.(*http.Client); ok {
		streamClient := *client
		streamClient.Timeout = 0
		doer = &streamClient
	}
	response, err := doer.Do(request)
	if err != nil {
		c.observe(0, time.Since(started))
		return nil, false, fmt.Errorf("synthient stream request failed: %w", err)
	}
	defer func() { c.observe(response.StatusCode, time.Since(started)) }()
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		raw, _ := readBounded(response.Body, 64<<10)
		decoded, _ := decodeObject(raw)
		decoded = sanitizeObject(decoded, c.apiKey)
		return nil, false, &APIError{Status: response.StatusCode, Message: streamError(response.StatusCode, decoded)}
	}

	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 64<<10), maxStreamEventBytes)
	events := make([]map[string]any, 0, count)
	readBytes := 0
	outputBytes := 0
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		readBytes += len(line)
		if readBytes > maxStreamReadBytes {
			return events, true, nil
		}
		if len(line) == 0 {
			continue
		}
		var event map[string]any
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.UseNumber()
		if err := decoder.Decode(&event); err != nil {
			return events, false, fmt.Errorf("decode Synthient stream event: %w", err)
		}
		event = sanitizeObject(event, c.apiKey)
		if !matchesFilters(event, filters) {
			continue
		}
		if outputBytes+len(line) > outputLimit {
			return events, true, nil
		}
		outputBytes += len(line)
		events = append(events, event)
		if len(events) >= count {
			return events, false, nil
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return events, false, fmt.Errorf("read Synthient stream: %w", err)
	}
	return events, false, nil
}

func (c *Client) newRequest(ctx context.Context, method string, path []string) (*http.Request, error) {
	if c.baseURL == nil || c.httpClient == nil {
		return nil, fmt.Errorf("synthient API client is not configured")
	}
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimSuffix(endpoint.Path, "/")
	for _, segment := range path {
		if segment == "" {
			return nil, fmt.Errorf("synthient API path segment cannot be empty")
		}
		endpoint = *endpoint.JoinPath(url.PathEscape(segment))
	}
	basePrefix := strings.TrimSuffix(c.baseURL.EscapedPath(), "/") + "/"
	if endpoint.Scheme != c.baseURL.Scheme || endpoint.Host != c.baseURL.Host || !strings.HasPrefix(endpoint.EscapedPath(), basePrefix) {
		return nil, fmt.Errorf("synthient API path escaped the configured endpoint")
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create Synthient request: %w", err)
	}
	request.Header.Set("Accept", "application/x-ndjson, application/json")
	request.Header.Set("X-API-Key", c.apiKey)
	if c.forwardedFor != "" {
		request.Header.Set("X-Forwarded-For", c.forwardedFor)
	}
	return request, nil
}

func requestAsQuery[T any](ctx context.Context, client *Client, method string, path []string, query url.Values, body any) (T, error) {
	var zero T
	value, err := client.requestQuery(ctx, method, path, query, body)
	if err != nil {
		return zero, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return zero, fmt.Errorf("encode typed Synthient response: %w", err)
	}
	var typed T
	if err := json.Unmarshal(raw, &typed); err != nil {
		return zero, &APIError{Status: http.StatusBadGateway, Message: "Synthient API response did not match the expected contract"}
	}
	return typed, nil
}

func feedPath(stream string) []string {
	switch stream {
	case "honeypot_http":
		return []string{"helio", "http"}
	case "honeypot_https":
		return []string{"helio", "https"}
	case "honeypot_dns":
		return []string{"helio", "dns"}
	case "honeypot_adb":
		return []string{"helio", "adb"}
	default:
		return []string{stream}
	}
}

func matchesFilters(event map[string]any, filters map[string]string) bool {
	for path, expected := range filters {
		var value any = event
		for segment := range strings.SplitSeq(path, ".") {
			object, ok := value.(map[string]any)
			if !ok {
				return false
			}
			value, ok = object[segment]
			if !ok {
				return false
			}
		}
		if fmt.Sprint(value) != expected {
			return false
		}
	}
	return true
}

func readBounded(body interface{ Read([]byte) (int, error) }, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(body, limit))
}

func streamError(status int, decoded map[string]any) string {
	message := fmt.Sprintf("Synthient stream returned HTTP %d", status)
	if detail := errorDetail(decoded); detail != "" {
		message += ": " + detail
	}
	return message
}
