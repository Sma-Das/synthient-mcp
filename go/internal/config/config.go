package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var defaultAllowedHosts = []string{"localhost", "127.0.0.1", "::1"}

type Config struct {
	Host             string
	Port             int
	AllowedHosts     []string
	AllowedOrigins   []string
	TrustProxyHops   int
	SynthientBaseURL *url.URL
	RequestTimeout   time.Duration
	MaxRequestBody   int64
}

func Load() (Config, error) {
	return LoadFrom(os.LookupEnv)
}

func LoadFrom(lookup func(string) (string, bool)) (Config, error) {
	host := get(lookup, "HOST", "0.0.0.0")
	port, err := integer(lookup, "PORT", 3000, 1, 65535)
	if err != nil {
		return Config{}, err
	}

	allowedHosts, err := list(lookup, "ALLOWED_HOSTS", defaultAllowedHosts)
	if err != nil {
		return Config{}, err
	}
	allowedOrigins, err := list(lookup, "ALLOWED_ORIGINS", allowedHosts)
	if err != nil {
		return Config{}, err
	}
	trustProxyHops, err := integer(lookup, "TRUST_PROXY_HOPS", 0, 0, 10)
	if err != nil {
		return Config{}, err
	}
	timeoutMS, err := integer(lookup, "REQUEST_TIMEOUT_MS", 15000, 100, 120000)
	if err != nil {
		return Config{}, err
	}

	baseURL, err := url.Parse(get(lookup, "SYNTHIENT_API_BASE_URL", "https://api.synthient.com/api/v4/"))
	if err != nil {
		return Config{}, fmt.Errorf("SYNTHIENT_API_BASE_URL: %w", err)
	}
	if baseURL.Scheme != "https" && !isLoopbackHost(baseURL.Hostname()) {
		return Config{}, fmt.Errorf("SYNTHIENT_API_BASE_URL must use HTTPS unless it targets localhost")
	}
	if !strings.HasSuffix(baseURL.Path, "/") {
		baseURL.Path += "/"
	}

	return Config{
		Host:             host,
		Port:             port,
		AllowedHosts:     allowedHosts,
		AllowedOrigins:   allowedOrigins,
		TrustProxyHops:   trustProxyHops,
		SynthientBaseURL: baseURL,
		RequestTimeout:   time.Duration(timeoutMS) * time.Millisecond,
		MaxRequestBody:   1 << 20,
	}, nil
}

func (c Config) Address() string {
	return net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
}

func get(lookup func(string) (string, bool), name, fallback string) string {
	if value, ok := lookup(name); ok {
		return value
	}
	return fallback
}

func integer(lookup func(string) (string, bool), name string, fallback, min, max int) (int, error) {
	value, ok := lookup(name)
	if !ok || value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < min || parsed > max {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", name, min, max)
	}
	return parsed, nil
}

func list(lookup func(string) (string, bool), name string, fallback []string) ([]string, error) {
	value, ok := lookup(name)
	if !ok {
		return append([]string(nil), fallback...), nil
	}
	var result []string
	for item := range strings.SplitSeq(value, ",") {
		item = normalizeHostname(item)
		if item != "" {
			result = append(result, item)
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("%s cannot be empty", name)
	}
	return result, nil
}

func normalizeHostname(host string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
