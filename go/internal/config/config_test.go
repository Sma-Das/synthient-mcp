package config

import "testing"

func TestLoadFromDefaults(t *testing.T) {
	cfg, err := LoadFrom(func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "0.0.0.0" || cfg.Port != 3000 || cfg.TrustProxyHops != 0 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if got := cfg.SynthientBaseURL.String(); got != "https://api.synthient.com/api/v4/" {
		t.Fatalf("base URL = %q", got)
	}
}

func TestLoadFromRejectsInsecureRemoteEndpoint(t *testing.T) {
	values := map[string]string{"SYNTHIENT_API_BASE_URL": "http://api.example.com/api/v4/"}
	_, err := LoadFrom(func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	})
	if err == nil {
		t.Fatal("expected insecure endpoint error")
	}
}

func TestLoadFromValidatesProxyHops(t *testing.T) {
	values := map[string]string{"TRUST_PROXY_HOPS": "-1"}
	_, err := LoadFrom(func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	})
	if err == nil {
		t.Fatal("expected proxy hop validation error")
	}
}
