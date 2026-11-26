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
)

// maxStreamReadBytes bounds the bytes read from one live stream. It is a
// variable so tests can exercise the boundary.
var maxStreamReadBytes = int64(8 << 20)

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
	request, err := c.newRequest(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return nil, false, err
	}
	request.Header.Set("Accept", "application/x-ndjson, application/json")

	started := time.Now()
	doer := c.streamClient
	if doer == nil {
		doer = c.httpClient
		if client, ok := c.httpClient.(*http.Client); ok {
			streamClient := *client
			streamClient.Timeout = 0
			doer = &streamClient
		}
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

	// Enforce the read budget below the line reader, on bytes actually taken
	// from the connection, so read-ahead, CRLF delimiters, and padding count.
	body := &countingReader{reader: io.LimitReader(response.Body, maxStreamReadBytes)}
	lines := bufio.NewReaderSize(body, 64<<10)
	events := make([]map[string]any, 0, count)
	outputBytes := 0
	for {
		raw, terminated, err := readStreamLine(lines, maxStreamEventBytes)
		if err != nil && !errors.Is(err, io.EOF) {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return events, false, nil
			}
			return events, false, fmt.Errorf("read Synthient stream: %w", err)
		}
		budgetSpent := body.count >= maxStreamReadBytes
		if !terminated && budgetSpent {
			// The read budget ended this line early: discard the unfinished
			// fragment and report truncation, whatever it happens to contain.
			return events, true, nil
		}
		// A complete line, or the final unterminated line of a stream that
		// ended on its own, is a real event and must decode cleanly.
		if line := bytes.TrimSpace(raw); len(line) > 0 {
			event, decodeErr := decodeObject(line)
			if decodeErr != nil {
				return events, false, fmt.Errorf("decode Synthient stream event: %w", decodeErr)
			}
			event = sanitizeObject(event, c.apiKey)
			if matchesFilters(event, filters) {
				// Bound what is returned to the caller: the redacted event as
				// it will be serialized, plus a separator.
				encoded, encodeErr := json.Marshal(event)
				if encodeErr != nil {
					return events, false, fmt.Errorf("encode Synthient stream event: %w", encodeErr)
				}
				if outputBytes+len(encoded)+1 > outputLimit {
					return events, true, nil
				}
				outputBytes += len(encoded) + 1
				events = append(events, event)
				if len(events) >= count {
					return events, false, nil
				}
			}
		}
		if err != nil {
			// EOF: the stream ended, either naturally or at the read budget.
			return events, budgetSpent, nil
		}
	}
}

var errStreamEventTooLarge = errors.New("stream event exceeds the size limit")

// readStreamLine reads one newline-delimited line of at most limit bytes. It
// reports whether the line ended with a delimiter; an unterminated line is
// returned with the error (normally io.EOF) that ended it.
func readStreamLine(reader *bufio.Reader, limit int) ([]byte, bool, error) {
	var line []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		if len(line)+len(chunk) > limit+1 {
			return nil, false, errStreamEventTooLarge
		}
		line = append(line, chunk...)
		switch {
		case err == nil:
			return line[:len(line)-1], true, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return line, false, err
		}
	}
}

type countingReader struct {
	reader io.Reader
	count  int64
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	n, err := reader.reader.Read(buffer)
	reader.count += int64(n)
	return n, err
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
