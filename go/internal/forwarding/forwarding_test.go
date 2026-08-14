package forwarding

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

var testProxyCIDRs = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}

func TestCanonicalClientIPIgnoresUntrustedForwardedFor(t *testing.T) {
	request := httptest.NewRequest("POST", "http://localhost/mcp", nil)
	request.RemoteAddr = "192.0.2.10:4321"
	request.Header.Set("X-Forwarded-For", "198.51.100.77")

	got, err := CanonicalClientIP(request, 0, nil)
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

	got, err := CanonicalClientIP(request, 1, testProxyCIDRs)
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

	got, err := CanonicalClientIP(request, 1, testProxyCIDRs)
	if err != nil {
		t.Fatal(err)
	}
	if got != "192.0.2.20" {
		t.Fatalf("client IP = %q", got)
	}
}

func TestCanonicalClientIPRejectsUntrustedDirectPeer(t *testing.T) {
	request := httptest.NewRequest("POST", "http://localhost/mcp", nil)
	request.RemoteAddr = "203.0.113.10:4321"
	request.Header.Set("X-Forwarded-For", "198.51.100.77")

	if _, err := CanonicalClientIP(request, 1, testProxyCIDRs); err == nil {
		t.Fatal("expected untrusted peer error")
	}
}

func TestCanonicalClientIPRejectsShortChain(t *testing.T) {
	request := httptest.NewRequest("POST", "http://localhost/mcp", nil)
	request.RemoteAddr = "192.0.2.10:4321"

	if _, err := CanonicalClientIP(request, 1, testProxyCIDRs); err == nil {
		t.Fatal("expected short chain error")
	}
}

func TestCanonicalClientIPReadsAllForwardedHeaderLines(t *testing.T) {
	request := httptest.NewRequest("POST", "http://localhost/mcp", nil)
	request.RemoteAddr = "192.0.2.30:4321"
	request.Header["X-Forwarded-For"] = []string{"198.51.100.77", "192.0.2.20"}

	got, err := CanonicalClientIP(request, 2, testProxyCIDRs)
	if err != nil {
		t.Fatal(err)
	}
	if got != "198.51.100.77" {
		t.Fatalf("client IP = %q", got)
	}
}
