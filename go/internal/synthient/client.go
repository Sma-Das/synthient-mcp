package synthient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const maxResponseBytes = 16 << 20

type Client struct {
	baseURL      *url.URL
	apiKey       string
	forwardedFor string
	httpClient   *http.Client
}

type APIError struct {
	Status     int
	RetryAfter string
	Message    string
}

func (e *APIError) Error() string {
	return e.Message
}

func NewClient(baseURL *url.URL, apiKey, forwardedFor string, httpClient *http.Client) *Client {
	return &Client{
		baseURL:      baseURL,
		apiKey:       apiKey,
		forwardedFor: forwardedFor,
		httpClient:   httpClient,
	}
}

func (c *Client) Account(ctx context.Context) (map[string]any, error) {
	return c.request(ctx, http.MethodGet, []string{"account", "me"}, nil)
}

func (c *Client) LookupIP(ctx context.Context, ip string) (map[string]any, error) {
	return c.request(ctx, http.MethodGet, []string{"lookup", "ip", ip}, nil)
}

func (c *Client) LookupIPs(ctx context.Context, ips []string) (map[string]any, error) {
	return c.request(ctx, http.MethodPost, []string{"lookup", "ips"}, map[string]any{"ips": ips})
}

func (c *Client) LookupDomain(ctx context.Context, domain string) (map[string]any, error) {
	return c.request(ctx, http.MethodGet, []string{"lookup", "domain", domain}, nil)
}

func (c *Client) request(ctx context.Context, method string, path []string, body any) (map[string]any, error) {
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimSuffix(endpoint.Path, "/")
	for _, segment := range path {
		endpoint = *endpoint.JoinPath(segment)
	}

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), reader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "synthient-mcp-go/0.1.0")
	request.Header.Set("X-API-Key", c.apiKey)
	request.Header.Set("X-Forwarded-For", c.forwardedFor)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("Synthient API request failed: %w", err)
	}
	defer response.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Synthient response: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return nil, &APIError{Status: http.StatusBadGateway, Message: "Synthient API response exceeded 16 MiB"}
	}

	var decoded map[string]any
	decodeErr := json.Unmarshal(raw, &decoded)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		detail := errorDetail(decoded, raw)
		message := fmt.Sprintf("Synthient API returned HTTP %d", response.StatusCode)
		if detail != "" {
			message += ": " + detail
		}
		if response.StatusCode == http.StatusTooManyRequests && response.Header.Get("Retry-After") != "" {
			message += ". Retry after " + response.Header.Get("Retry-After") + " seconds"
		}
		return nil, &APIError{
			Status:     response.StatusCode,
			RetryAfter: response.Header.Get("Retry-After"),
			Message:    message,
		}
	}
	if decodeErr != nil || decoded == nil {
		return nil, &APIError{Status: http.StatusBadGateway, Message: "Synthient API returned an invalid JSON object"}
	}
	return decoded, nil
}

func errorDetail(decoded map[string]any, raw []byte) string {
	for _, key := range []string{"message", "error", "detail"} {
		if value, ok := decoded[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	if len(raw) > 0 && len(raw) <= 500 {
		return strings.TrimSpace(string(raw))
	}
	return ""
}
