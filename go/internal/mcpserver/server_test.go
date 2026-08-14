package mcpserver

import (
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	synthientsdk "github.com/synthient/go-synthient/v2"
)

func TestUsefulTextSummaries(t *testing.T) {
	var account synthientsdk.Account
	account.Email = "caller@example.com"
	account.Organization.Name = "Example Org"
	account.LookupQuota.Credits = 42
	account.LookupQuota.ResetsIn = 60
	if got := accountSummary(account); !strings.Contains(got, "42 lookup credits") || !strings.Contains(got, "Example Org") {
		t.Fatalf("account summary = %q", got)
	}

	var ip synthientsdk.IP
	ip.IP = "8.8.8.8"
	ip.Network.Asn = 15169
	ip.Location.Country = "US"
	ip.Intelligence.RiskScore = 7
	if got := ipSummary([]synthientsdk.IP{ip}); !strings.Contains(got, "risk score 7") || !strings.Contains(got, "ASN 15169") {
		t.Fatalf("IP summary = %q", got)
	}

	var domain synthientsdk.Domain
	domain.Domain = "example.com"
	domain.Status = "active"
	domain.Stats.Events24H = 12
	if got := domainSummary(domain); !strings.Contains(got, "12 events") || !strings.Contains(got, "active") {
		t.Fatalf("domain summary = %q", got)
	}
}

func TestNormalizeIP(t *testing.T) {
	for input, want := range map[string]string{
		" 8.8.8.8 ":      "8.8.8.8",
		"2001:0db8::1":   "2001:db8::1",
		"::ffff:8.8.8.8": "8.8.8.8",
	} {
		got, err := normalizeIP(input)
		if err != nil || got != want {
			t.Errorf("normalizeIP(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"../../account/me", "127.0.0.1/24", "fe80::1%eth0", "not-an-ip"} {
		if _, err := normalizeIP(input); err == nil {
			t.Errorf("normalizeIP(%q) succeeded", input)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	for input, want := range map[string]string{
		" Example.COM. ":   "example.com",
		"xn--bcher-kva.de": "xn--bcher-kva.de",
	} {
		got, err := normalizeDomain(input)
		if err != nil || got != want {
			t.Errorf("normalizeDomain(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"../../account/me", "bad_label.example", "-bad.example", "bad-.example", "bücher.de", "example.com/path"} {
		if _, err := normalizeDomain(input); err == nil {
			t.Errorf("normalizeDomain(%q) succeeded", input)
		}
	}
}

func TestToolSchemasAndMeteringAnnotations(t *testing.T) {
	account := tool("account", "Account", "Account", false, emptyInputSchema())
	if !account.Annotations.ReadOnlyHint || !account.Annotations.IdempotentHint || *account.Annotations.DestructiveHint {
		t.Fatalf("account annotations = %#v", account.Annotations)
	}
	lookup := tool("lookup", "Lookup", "Lookup", true, ipsInputSchema())
	if lookup.Annotations.ReadOnlyHint || lookup.Annotations.IdempotentHint || !*lookup.Annotations.DestructiveHint {
		t.Fatalf("lookup annotations = %#v", lookup.Annotations)
	}
	schema, ok := lookup.InputSchema.(*jsonschema.Schema)
	if !ok || schema.Properties["ips"].MinItems == nil || *schema.Properties["ips"].MinItems != 1 || *schema.Properties["ips"].MaxItems != 1000 {
		t.Fatalf("batch schema = %#v", lookup.InputSchema)
	}
}

func FuzzNormalizePathInputs(f *testing.F) {
	for _, seed := range []string{"8.8.8.8", "2001:db8::1", "example.com", "../../account/me", "%2e%2e/account"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if ip, err := normalizeIP(value); err == nil && strings.ContainsAny(ip, "/\\?#%") {
			t.Fatalf("unsafe normalized IP %q", ip)
		}
		if domain, err := normalizeDomain(value); err == nil && strings.ContainsAny(domain, "/\\?#%") {
			t.Fatalf("unsafe normalized domain %q", domain)
		}
	})
}
