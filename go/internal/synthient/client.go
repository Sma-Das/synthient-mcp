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
	"time"

	synthientsdk "github.com/synthient/go-synthient/v2"

	"github.com/Sma-Das/synthient-mcp/go/internal/buildinfo"
)

const maxResponseBytes = 16 << 20

type Client struct {
	baseURL      *url.URL
	apiKey       string
	forwardedFor string
	httpClient   HTTPDoer
	observer     Observer
}

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type Observer interface {
	ObserveUpstream(status int, duration time.Duration)
}

type APIError struct {
	Status     int
	RetryAfter string
	Message    string
}

func (e *APIError) Error() string {
	return e.Message
}

func NewClient(baseURL *url.URL, apiKey, forwardedFor string, httpClient HTTPDoer, observers ...Observer) *Client {
	if standardClient, ok := httpClient.(*http.Client); ok {
		clone := *standardClient
		clone.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
		httpClient = &clone
	}
	client := &Client{
		baseURL:      baseURL,
		apiKey:       apiKey,
		forwardedFor: forwardedFor,
		httpClient:   httpClient,
	}
	if len(observers) > 0 {
		client.observer = observers[0]
	}
	return client
}

func (c *Client) Account(ctx context.Context) (synthientsdk.Account, error) {
	return requestAs[synthientsdk.Account](ctx, c, http.MethodGet, []string{"account", "me"}, nil)
}

func (c *Client) LookupIP(ctx context.Context, ip string) (synthientsdk.IP, error) {
	return requestAs[synthientsdk.IP](ctx, c, http.MethodGet, []string{"lookup", "ip", ip}, nil)
}

func (c *Client) LookupIPs(ctx context.Context, ips []string) ([]synthientsdk.IP, error) {
	response, err := requestAs[struct {
		Results []synthientsdk.IP `json:"results"`
	}](ctx, c, http.MethodPost, []string{"lookup", "ips"}, map[string]any{"ips": ips})
	if err != nil {
		return nil, err
	}
	return response.Results, nil
}

func (c *Client) LookupDomain(ctx context.Context, domain string) (synthientsdk.Domain, error) {
	return requestAs[synthientsdk.Domain](ctx, c, http.MethodGet, []string{"lookup", "domain", domain}, nil)
}

func requestAs[T any](ctx context.Context, client *Client, method string, path []string, body any) (T, error) {
	var zero T
	value, err := client.request(ctx, method, path, body)
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

func (c *Client) request(ctx context.Context, method string, path []string, body any) (map[string]any, error) {
	if c.baseURL == nil {
		return nil, fmt.Errorf("synthient API base URL is not configured")
	}
	if c.httpClient == nil {
		return nil, fmt.Errorf("synthient HTTP client is not configured")
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
	request.Header.Set("User-Agent", buildinfo.UserAgent())
	request.Header.Set("X-API-Key", c.apiKey)
	request.Header.Set("X-Forwarded-For", c.forwardedFor)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	started := time.Now()
	response, err := c.httpClient.Do(request)
	if err != nil {
		c.observe(0, time.Since(started))
		return nil, fmt.Errorf("synthient API request failed: %w", err)
	}
	defer func() { c.observe(response.StatusCode, time.Since(started)) }()
	defer response.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Synthient response: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return nil, &APIError{Status: http.StatusBadGateway, Message: "Synthient API response exceeded 16 MiB"}
	}

	decoded, decodeErr := decodeObject(raw)
	decoded = sanitizeObject(decoded, c.apiKey)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		detail := errorDetail(decoded)
		message := fmt.Sprintf("Synthient API returned HTTP %d", response.StatusCode)
		if detail != "" {
			message += ": " + detail
		}
		if response.StatusCode == http.StatusTooManyRequests && response.Header.Get("Retry-After") != "" {
			message += ". Retry-After: " + response.Header.Get("Retry-After")
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

func (c *Client) observe(status int, duration time.Duration) {
	if c.observer != nil {
		c.observer.ObserveUpstream(status, duration)
	}
}

func decodeObject(raw []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded map[string]any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	if decoded == nil {
		return nil, fmt.Errorf("JSON value is not an object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("JSON response contains trailing data")
	}
	return decoded, nil
}

func errorDetail(decoded map[string]any) string {
	for _, key := range []string{"message", "error", "detail"} {
		if value, ok := decoded[key].(string); ok && strings.TrimSpace(value) != "" {
			value = strings.Map(func(r rune) rune {
				if r < 0x20 || r == 0x7f {
					return ' '
				}
				return r
			}, strings.TrimSpace(value))
			runes := []rune(value)
			if len(runes) > 500 {
				value = string(runes[:500]) + "…"
			}
			return value
		}
	}
	return ""
}

func sanitizeObject(value map[string]any, secret string) map[string]any {
	if value == nil {
		return nil
	}
	cleaned, _ := sanitizeValue(value, secret).(map[string]any)
	return cleaned
}

func sanitizeValue(value any, secret string) any {
	switch value := value.(type) {
	case map[string]any:
		cleaned := make(map[string]any, len(value))
		for key, item := range value {
			if sensitiveKey(key) {
				continue
			}
			cleaned[key] = sanitizeValue(item, secret)
		}
		return cleaned
	case []any:
		cleaned := make([]any, len(value))
		for index, item := range value {
			cleaned[index] = sanitizeValue(item, secret)
		}
		return cleaned
	case string:
		if secret != "" {
			return strings.ReplaceAll(value, secret, "[REDACTED]")
		}
		return value
	default:
		return value
	}
}

func sensitiveKey(key string) bool {
	normalized := strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, key)
	return normalized == "apikey" || normalized == "authorization" || normalized == "accesstoken" || normalized == "token" || normalized == "secret"
}
