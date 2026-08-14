package config

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var defaultAllowedHosts = []string{"localhost", "127.0.0.1", "::1"}

type Config struct {
	Host                  string
	Port                  int
	AllowedHosts          []string
	AllowedOrigins        []string
	TrustProxyHops        int
	TrustedProxyCIDRs     []netip.Prefix
	SynthientBaseURL      *url.URL
	RequestTimeout        time.Duration
	ReadTimeout           time.Duration
	WriteTimeout          time.Duration
	IdleTimeout           time.Duration
	ShutdownTimeout       time.Duration
	MaxRequestBody        int64
	MaxHeaderBytes        int
	MaxConcurrentRequests int
	MaxAPIKeyLength       int
	MetricsEnabled        bool
	LogLevel              slog.Level
	LogJSON               bool
}

func Load() (Config, error) {
	return LoadFrom(os.LookupEnv)
}

func LoadFrom(lookup func(string) (string, bool)) (Config, error) {
	host := normalizeHostname(get(lookup, "HOST", "127.0.0.1"))
	if err := validateListenHost(host); err != nil {
		return Config{}, err
	}
	port, err := integer(lookup, "PORT", 3000, 1, 65535)
	if err != nil {
		return Config{}, err
	}

	allowedHosts, err := list(lookup, "ALLOWED_HOSTS", defaultAllowedHosts)
	if err != nil {
		return Config{}, err
	}
	allowedOrigins, err := origins(lookup, "ALLOWED_ORIGINS")
	if err != nil {
		return Config{}, err
	}
	trustProxyHops, err := integer(lookup, "TRUST_PROXY_HOPS", 0, 0, 10)
	if err != nil {
		return Config{}, err
	}
	trustedProxyCIDRs, err := prefixes(lookup, "TRUSTED_PROXY_CIDRS")
	if err != nil {
		return Config{}, err
	}
	if trustProxyHops > 0 && len(trustedProxyCIDRs) == 0 {
		return Config{}, fmt.Errorf("TRUSTED_PROXY_CIDRS is required when TRUST_PROXY_HOPS is greater than zero")
	}

	timeoutMS, err := integer(lookup, "REQUEST_TIMEOUT_MS", 15000, 100, 120000)
	if err != nil {
		return Config{}, err
	}
	readTimeoutMS, err := integer(lookup, "READ_TIMEOUT_MS", timeoutMS+5000, 1000, 180000)
	if err != nil {
		return Config{}, err
	}
	writeTimeoutMS, err := integer(lookup, "WRITE_TIMEOUT_MS", timeoutMS+5000, 1000, 180000)
	if err != nil {
		return Config{}, err
	}
	idleTimeoutMS, err := integer(lookup, "IDLE_TIMEOUT_MS", 60000, 1000, 300000)
	if err != nil {
		return Config{}, err
	}
	shutdownTimeoutMS, err := integer(lookup, "SHUTDOWN_TIMEOUT_MS", 10000, 1000, 120000)
	if err != nil {
		return Config{}, err
	}
	maxHeaderBytes, err := integer(lookup, "MAX_HEADER_BYTES", 32768, 8192, 1048576)
	if err != nil {
		return Config{}, err
	}
	maxConcurrentRequests, err := integer(lookup, "MAX_CONCURRENT_REQUESTS", 8, 1, 1024)
	if err != nil {
		return Config{}, err
	}
	metricsEnabled, err := boolean(lookup, "METRICS_ENABLED", false)
	if err != nil {
		return Config{}, err
	}

	baseURL, err := url.Parse(get(lookup, "SYNTHIENT_API_BASE_URL", "https://api.synthient.com/api/v4/"))
	if err != nil {
		return Config{}, fmt.Errorf("SYNTHIENT_API_BASE_URL: %w", err)
	}
	if err := validateBaseURL(baseURL); err != nil {
		return Config{}, err
	}
	if !strings.HasSuffix(baseURL.Path, "/") {
		baseURL.Path += "/"
	}

	logLevel, err := parseLogLevel(get(lookup, "LOG_LEVEL", "info"))
	if err != nil {
		return Config{}, err
	}
	logFormat := strings.ToLower(strings.TrimSpace(get(lookup, "LOG_FORMAT", "text")))
	if logFormat != "text" && logFormat != "json" {
		return Config{}, fmt.Errorf("LOG_FORMAT must be text or json")
	}

	return Config{
		Host:                  host,
		Port:                  port,
		AllowedHosts:          allowedHosts,
		AllowedOrigins:        allowedOrigins,
		TrustProxyHops:        trustProxyHops,
		TrustedProxyCIDRs:     trustedProxyCIDRs,
		SynthientBaseURL:      baseURL,
		RequestTimeout:        time.Duration(timeoutMS) * time.Millisecond,
		ReadTimeout:           time.Duration(readTimeoutMS) * time.Millisecond,
		WriteTimeout:          time.Duration(writeTimeoutMS) * time.Millisecond,
		IdleTimeout:           time.Duration(idleTimeoutMS) * time.Millisecond,
		ShutdownTimeout:       time.Duration(shutdownTimeoutMS) * time.Millisecond,
		MaxRequestBody:        1 << 20,
		MaxHeaderBytes:        maxHeaderBytes,
		MaxConcurrentRequests: maxConcurrentRequests,
		MaxAPIKeyLength:       1024,
		MetricsEnabled:        metricsEnabled,
		LogLevel:              logLevel,
		LogJSON:               logFormat == "json",
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

func boolean(lookup func(string) (string, bool), name string, fallback bool) (bool, error) {
	value, ok := lookup(name)
	if !ok || value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", name)
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
			if err := validateListenHost(item); err != nil {
				return nil, fmt.Errorf("%s contains invalid host %q", name, item)
			}
			result = append(result, item)
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("%s cannot be empty", name)
	}
	return result, nil
}

func origins(lookup func(string) (string, bool), name string) ([]string, error) {
	value, ok := lookup(name)
	if !ok || strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var result []string
	for item := range strings.SplitSeq(value, ",") {
		origin, err := canonicalOrigin(strings.TrimSpace(item))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		result = append(result, origin)
	}
	return result, nil
}

func canonicalOrigin(value string) (string, error) {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed == nil {
		return "", fmt.Errorf("origin %q must be an absolute HTTP(S) origin", value)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if parsed.Hostname() == "" || (scheme != "http" && scheme != "https") {
		return "", fmt.Errorf("origin %q must be an absolute HTTP(S) origin", value)
	}
	if parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("origin %q must not contain credentials, a path, query, or fragment", value)
	}
	return (&url.URL{Scheme: scheme, Host: strings.ToLower(parsed.Host)}).String(), nil
}

func prefixes(lookup func(string) (string, bool), name string) ([]netip.Prefix, error) {
	value, ok := lookup(name)
	if !ok || strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var result []netip.Prefix
	for item := range strings.SplitSeq(value, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err != nil {
			return nil, fmt.Errorf("%s contains invalid CIDR %q", name, strings.TrimSpace(item))
		}
		result = append(result, prefix.Masked())
	}
	return result, nil
}

func normalizeHostname(host string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
}

func validateListenHost(host string) error {
	if host == "" || strings.ContainsAny(host, " /\\\t\r\n") {
		return fmt.Errorf("HOST must be a hostname or IP address without a port")
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return fmt.Errorf("HOST must not include a port")
	}
	return nil
}

func validateBaseURL(baseURL *url.URL) error {
	if baseURL == nil || !baseURL.IsAbs() || baseURL.Hostname() == "" {
		return fmt.Errorf("SYNTHIENT_API_BASE_URL must be an absolute URL with a host")
	}
	if baseURL.Scheme != "https" && baseURL.Scheme != "http" {
		return fmt.Errorf("SYNTHIENT_API_BASE_URL must use HTTP or HTTPS")
	}
	if baseURL.Scheme == "http" && !isLoopbackHost(baseURL.Hostname()) {
		return fmt.Errorf("SYNTHIENT_API_BASE_URL must use HTTPS unless it targets localhost")
	}
	if baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" || baseURL.Opaque != "" || baseURL.RawPath != "" {
		return fmt.Errorf("SYNTHIENT_API_BASE_URL must not contain credentials, a query, fragment, opaque data, or an encoded path")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func parseLogLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("LOG_LEVEL must be debug, info, warn, or error")
	}
}
