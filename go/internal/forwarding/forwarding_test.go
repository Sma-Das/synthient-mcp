package forwarding

import (
	"net/http/httptest"
	"testing"
)

func TestCanonicalClientIPIgnoresUntrustedForwardedFor(t *testing.T) {
	request := httptest.NewRequest("POST", "http://localhost/mcp", nil)
	request.RemoteAddr = "192.0.2.10:4321"
	request.Header.Set("X-Forwarded-For", "198.51.100.77")

	got, err := CanonicalClientIP(request, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got != "192.0.2.10" {
		t.Fatalf("client IP = %q", got)
	}
}

func TestCanonicalClientIPTrustsConfiguredProxyHop(t *testing.T) {
	request := httptest.NewRequest("POST", "http://localhost/mcp", nil)
	request.RemoteAddr = "192.0.2.10:4321"
	request.Header.Set("X-Forwarded-For", "198.51.100.77")

	got, err := CanonicalClientIP(request, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got != "198.51.100.77" {
		t.Fatalf("client IP = %q", got)
	}
}

func TestCanonicalClientIPSelectsLastUntrustedAddress(t *testing.T) {
	request := httptest.NewRequest("POST", "http://localhost/mcp", nil)
	request.RemoteAddr = "192.0.2.30:4321"
	request.Header.Set("X-Forwarded-For", "198.51.100.77, 192.0.2.20")

	got, err := CanonicalClientIP(request, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got != "192.0.2.20" {
		t.Fatalf("client IP = %q", got)
	}
}
