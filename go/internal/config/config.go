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
	SynthientGRPCEndpoint string
	SynthientAPIKey       string
	AuthMode              string
	OAuthIssuerURL        string
	OAuthJWKSURL          string
	OAuthAudience         string
	MCPResourceURL        string
	OAuthRequiredScopes   []string
	ForwardClientIP       bool
	CORSEnabled           bool
	LegacyToolNames       bool
	RequestTimeout        time.Duration
	StreamTimeout         time.Duration
	ReadTimeout           time.Duration
	WriteTimeout          time.Duration
	IdleTimeout           time.Duration
	ShutdownTimeout       time.Duration
	MaxRequestBody        int64
	MaxHeaderBytes        int
	MaxConcurrentRequests int
	MaxConcurrentPerUser  int
	MaxRequestsPerMinute  int
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
	streamTimeoutMS, err := integer(lookup, "STREAM_TIMEOUT_MS", 15000, 1000, 30000)
	if err != nil {
		return Config{}, err
	}
	operationTimeoutMS := max(timeoutMS, streamTimeoutMS)
	readTimeoutMS, err := integer(lookup, "READ_TIMEOUT_MS", operationTimeoutMS+5000, 1000, 180000)
	if err != nil {
		return Config{}, err
	}
	writeTimeoutMS, err := integer(lookup, "WRITE_TIMEOUT_MS", operationTimeoutMS+5000, 1000, 180000)
	if err != nil {
		return Config{}, err
	}
	if writeTimeoutMS <= streamTimeoutMS {
		return Config{}, fmt.Errorf("WRITE_TIMEOUT_MS must exceed STREAM_TIMEOUT_MS")
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
	maxConcurrentPerUser, err := integer(lookup, "MAX_CONCURRENT_PER_PRINCIPAL", 2, 1, 1024)
	if err != nil {
		return Config{}, err
	}
	if maxConcurrentPerUser > maxConcurrentRequests {
		return Config{}, fmt.Errorf("MAX_CONCURRENT_PER_PRINCIPAL must not exceed MAX_CONCURRENT_REQUESTS")
	}
	maxRequestsPerMinute, err := integer(lookup, "MAX_REQUESTS_PER_MINUTE", 120, 0, 100000)
	if err != nil {
		return Config{}, err
	}
	forwardClientIP, err := boolean(lookup, "FORWARD_CLIENT_IP", false)
	if err != nil {
		return Config{}, err
	}
	corsEnabled, err := boolean(lookup, "CORS_ENABLED", false)
	if err != nil {
		return Config{}, err
	}
	legacyToolNames, err := boolean(lookup, "LEGACY_TOOL_NAMES", false)
	if err != nil {
		return Config{}, err
	}
	if corsEnabled && len(allowedOrigins) == 0 {
		return Config{}, fmt.Errorf("ALLOWED_ORIGINS is required when CORS_ENABLED is true")
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
	grpcEndpoint := strings.TrimSpace(get(lookup, "SYNTHIENT_GRPC_ENDPOINT", "grpc.synthient.com:443"))
	if err := validateGRPCEndpoint(grpcEndpoint); err != nil {
		return Config{}, err
	}

	authMode := strings.ToLower(strings.TrimSpace(get(lookup, "AUTH_MODE", "api_key")))
	if authMode != "api_key" && authMode != "oauth" {
		return Config{}, fmt.Errorf("AUTH_MODE must be api_key or oauth")
	}
	var synthientAPIKey, oauthIssuerURL, oauthJWKSURL, oauthAudience, mcpResourceURL string
	var oauthRequiredScopes []string
	if authMode == "oauth" {
		synthientAPIKey = strings.TrimSpace(get(lookup, "SYNTHIENT_API_KEY", ""))
		if synthientAPIKey == "" || len(synthientAPIKey) > 1024 {
			return Config{}, fmt.Errorf("SYNTHIENT_API_KEY must contain a bounded server credential in oauth mode")
		}
		oauthIssuerURL = strings.TrimSpace(get(lookup, "OAUTH_ISSUER_URL", ""))
		oauthJWKSURL = strings.TrimSpace(get(lookup, "OAUTH_JWKS_URL", ""))
		oauthAudience = strings.TrimSpace(get(lookup, "OAUTH_AUDIENCE", ""))
		mcpResourceURL = strings.TrimSpace(get(lookup, "MCP_RESOURCE_URL", ""))
		for name, value := range map[string]string{
			"OAUTH_ISSUER_URL": oauthIssuerURL,
			"OAUTH_JWKS_URL":   oauthJWKSURL,
			"MCP_RESOURCE_URL": mcpResourceURL,
		} {
			if err := validateSecureURL(name, value); err != nil {
				return Config{}, err
			}
		}
		if oauthAudience == "" || len(oauthAudience) > 2048 {
			return Config{}, fmt.Errorf("OAUTH_AUDIENCE is required in oauth mode and must not exceed 2048 characters")
		}
		oauthRequiredScopes, err = scopeList(get(lookup, "OAUTH_REQUIRED_SCOPES", "mcp:tools"))
		if err != nil {
			return Config{}, err
		}
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
		SynthientGRPCEndpoint: grpcEndpoint,
		SynthientAPIKey:       synthientAPIKey,
		AuthMode:              authMode,
		OAuthIssuerURL:        oauthIssuerURL,
		OAuthJWKSURL:          oauthJWKSURL,
		OAuthAudience:         oauthAudience,
		MCPResourceURL:        mcpResourceURL,
		OAuthRequiredScopes:   oauthRequiredScopes,
		ForwardClientIP:       forwardClientIP,
		CORSEnabled:           corsEnabled,
		LegacyToolNames:       legacyToolNames,
		RequestTimeout:        time.Duration(timeoutMS) * time.Millisecond,
		StreamTimeout:         time.Duration(streamTimeoutMS) * time.Millisecond,
		ReadTimeout:           time.Duration(readTimeoutMS) * time.Millisecond,
		WriteTimeout:          time.Duration(writeTimeoutMS) * time.Millisecond,
		IdleTimeout:           time.Duration(idleTimeoutMS) * time.Millisecond,
		ShutdownTimeout:       time.Duration(shutdownTimeoutMS) * time.Millisecond,
		MaxRequestBody:        1 << 20,
		MaxHeaderBytes:        maxHeaderBytes,
		MaxConcurrentRequests: maxConcurrentRequests,
		MaxConcurrentPerUser:  maxConcurrentPerUser,
		MaxRequestsPerMinute:  maxRequestsPerMinute,
		MaxAPIKeyLength:       1024,
		MetricsEnabled:        metricsEnabled,
		LogLevel:              logLevel,
		LogJSON:               logFormat == "json",
	}, nil
}

func validateSecureURL(name, value string) error {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed == nil || !parsed.IsAbs() || parsed.Hostname() == "" {
		return fmt.Errorf("%s must be an absolute HTTPS URL", name)
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return fmt.Errorf("%s must use HTTPS unless it targets localhost", name)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return fmt.Errorf("%s must not contain credentials, a query, fragment, or opaque data", name)
	}
	return nil
}

func scopeList(value string) ([]string, error) {
	var scopes []string
	for scope := range strings.SplitSeq(value, ",") {
		scope = strings.TrimSpace(scope)
		if scope == "" || len(scope) > 128 || strings.ContainsAny(scope, " \t\r\n\"") {
			return nil, fmt.Errorf("OAUTH_REQUIRED_SCOPES must contain comma-separated scope tokens")
		}
		scopes = append(scopes, scope)
	}
	if len(scopes) == 0 || len(scopes) > 20 {
		return nil, fmt.Errorf("OAUTH_REQUIRED_SCOPES must contain between 1 and 20 scopes")
	}
	return scopes, nil
}

func validateGRPCEndpoint(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || port == "" || strings.ContainsAny(value, "/\\\t\r\n") {
		return fmt.Errorf("SYNTHIENT_GRPC_ENDPOINT must be a host:port without a URL scheme or path")
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return fmt.Errorf("SYNTHIENT_GRPC_ENDPOINT must contain a port between 1 and 65535")
	}
	return nil
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
