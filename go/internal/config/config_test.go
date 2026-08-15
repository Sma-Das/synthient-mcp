package config

import (
	"reflect"
	"testing"
	"time"
)

func lookupValues(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func TestLoadFromDefaults(t *testing.T) {
	cfg, err := LoadFrom(func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "127.0.0.1" || cfg.Port != 3000 || cfg.TrustProxyHops != 0 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if got := cfg.SynthientBaseURL.String(); got != "https://api.synthient.com/api/v4/" {
		t.Fatalf("base URL = %q", got)
	}
	if cfg.SynthientGRPCEndpoint != "grpc.synthient.com:443" {
		t.Fatalf("gRPC endpoint = %q", cfg.SynthientGRPCEndpoint)
	}
	if cfg.MaxConcurrentRequests != 8 || cfg.MaxHeaderBytes != 32768 || cfg.ReadTimeout <= cfg.RequestTimeout {
		t.Fatalf("unexpected limits: %+v", cfg)
	}
	if cfg.AuthMode != "api_key" || cfg.ForwardClientIP || cfg.CORSEnabled || cfg.LegacyToolNames || cfg.MaxConcurrentPerUser != 2 {
		t.Fatalf("unexpected security defaults: %+v", cfg)
	}
	if cfg.StreamTimeout != 15*time.Second || cfg.WriteTimeout != 20*time.Second {
		t.Fatalf("unexpected operation timeouts: %+v", cfg)
	}
}

func TestLoadFromUsesSeparateStreamTimeout(t *testing.T) {
	cfg, err := LoadFrom(lookupValues(map[string]string{"STREAM_TIMEOUT_MS": "30000"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StreamTimeout != 30*time.Second || cfg.WriteTimeout != 35*time.Second || cfg.ReadTimeout != 35*time.Second {
		t.Fatalf("operation timeouts = %+v", cfg)
	}
	if _, err := LoadFrom(lookupValues(map[string]string{"STREAM_TIMEOUT_MS": "30000", "WRITE_TIMEOUT_MS": "30000"})); err == nil {
		t.Fatal("write timeout that cannot complete a stream succeeded")
	}
}

func TestLoadFromOAuthMode(t *testing.T) {
	cfg, err := LoadFrom(lookupValues(map[string]string{
		"AUTH_MODE":             "oauth",
		"SYNTHIENT_API_KEY":     "server-synthient-key",
		"OAUTH_ISSUER_URL":      "https://id.example.com/",
		"OAUTH_JWKS_URL":        "https://id.example.com/.well-known/jwks.json",
		"OAUTH_AUDIENCE":        "https://mcp.example.com/mcp",
		"MCP_RESOURCE_URL":      "https://mcp.example.com/mcp",
		"OAUTH_REQUIRED_SCOPES": "mcp:tools,synthient:read",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthMode != "oauth" || cfg.SynthientAPIKey != "server-synthient-key" || len(cfg.OAuthRequiredScopes) != 2 {
		t.Fatalf("oauth config = %+v", cfg)
	}
}

func TestLoadFromRejectsIncompleteOAuthMode(t *testing.T) {
	base := map[string]string{
		"AUTH_MODE":         "oauth",
		"SYNTHIENT_API_KEY": "server-synthient-key",
		"OAUTH_ISSUER_URL":  "https://id.example.com/",
		"OAUTH_JWKS_URL":    "https://id.example.com/jwks.json",
		"OAUTH_AUDIENCE":    "https://mcp.example.com/mcp",
		"MCP_RESOURCE_URL":  "https://mcp.example.com/mcp",
	}
	for _, name := range []string{"SYNTHIENT_API_KEY", "OAUTH_ISSUER_URL", "OAUTH_JWKS_URL", "OAUTH_AUDIENCE", "MCP_RESOURCE_URL"} {
		values := map[string]string{}
		for key, value := range base {
			values[key] = value
		}
		delete(values, name)
		if _, err := LoadFrom(lookupValues(values)); err == nil {
			t.Errorf("missing %s succeeded", name)
		}
	}
}

func TestLoadFromRequiresOriginsForCORS(t *testing.T) {
	if _, err := LoadFrom(lookupValues(map[string]string{"CORS_ENABLED": "true"})); err == nil {
		t.Fatal("CORS without origins succeeded")
	}
	cfg, err := LoadFrom(lookupValues(map[string]string{"CORS_ENABLED": "true", "ALLOWED_ORIGINS": "https://app.example.com"}))
	if err != nil || !cfg.CORSEnabled {
		t.Fatalf("config=%+v error=%v", cfg, err)
	}
}

func TestLoadFromValidatesGRPCEndpoint(t *testing.T) {
	for _, value := range []string{"", "grpc.synthient.com", "https://grpc.synthient.com:443", "grpc.synthient.com:0", "grpc.synthient.com:70000"} {
		_, err := LoadFrom(lookupValues(map[string]string{"SYNTHIENT_GRPC_ENDPOINT": value}))
		if err == nil {
			t.Errorf("expected %q to be rejected", value)
		}
	}
	config, err := LoadFrom(lookupValues(map[string]string{"SYNTHIENT_GRPC_ENDPOINT": "schema.example.com:443"}))
	if err != nil || config.SynthientGRPCEndpoint != "schema.example.com:443" {
		t.Fatalf("config=%#v error=%v", config, err)
	}
}

func TestLoadFromRejectsInsecureRemoteEndpoint(t *testing.T) {
	values := map[string]string{"SYNTHIENT_API_BASE_URL": "http://api.example.com/api/v4/"}
	_, err := LoadFrom(lookupValues(values))
	if err == nil {
		t.Fatal("expected insecure endpoint error")
	}
}

func TestLoadFromValidatesProxyHops(t *testing.T) {
	values := map[string]string{"TRUST_PROXY_HOPS": "-1"}
	_, err := LoadFrom(lookupValues(values))
	if err == nil {
		t.Fatal("expected proxy hop validation error")
	}
}

func TestLoadFromRequiresTrustedProxyCIDRs(t *testing.T) {
	_, err := LoadFrom(lookupValues(map[string]string{"TRUST_PROXY_HOPS": "1"}))
	if err == nil {
		t.Fatal("expected trusted proxy CIDR error")
	}

	cfg, err := LoadFrom(lookupValues(map[string]string{
		"TRUST_PROXY_HOPS":    "1",
		"TRUSTED_PROXY_CIDRS": "192.0.2.0/24,2001:db8::/32",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TrustedProxyCIDRs) != 2 {
		t.Fatalf("trusted CIDRs = %#v", cfg.TrustedProxyCIDRs)
	}
}

func TestLoadFromValidatesBaseURLShape(t *testing.T) {
	for _, value := range []string{
		"https:///api/v4/",
		"ftp://127.0.0.1/api/v4/",
		"https://user:pass@api.example.com/api/v4/",
		"https://api.example.com/api/v4/?token=value",
		"https://api.example.com/api/v4/#fragment",
	} {
		t.Run(value, func(t *testing.T) {
			_, err := LoadFrom(lookupValues(map[string]string{"SYNTHIENT_API_BASE_URL": value}))
			if err == nil {
				t.Fatalf("expected %q to be rejected", value)
			}
		})
	}
}

func TestLoadFromCanonicalizesExactOrigins(t *testing.T) {
	cfg, err := LoadFrom(lookupValues(map[string]string{
		"ALLOWED_ORIGINS": "HTTPS://Example.COM:8443/,http://localhost:3000",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://example.com:8443", "http://localhost:3000"}
	if !reflect.DeepEqual(cfg.AllowedOrigins, want) {
		t.Fatalf("origins = %#v; want %#v", cfg.AllowedOrigins, want)
	}
}

func TestLoadFromRejectsOriginWithPath(t *testing.T) {
	_, err := LoadFrom(lookupValues(map[string]string{"ALLOWED_ORIGINS": "https://example.com/path"}))
	if err == nil {
		t.Fatal("expected origin path error")
	}
}

func TestLoadFromRejectsAllowedHostWithPort(t *testing.T) {
	_, err := LoadFrom(lookupValues(map[string]string{"ALLOWED_HOSTS": "example.com:443"}))
	if err == nil {
		t.Fatal("expected allowed host port error")
	}
}
