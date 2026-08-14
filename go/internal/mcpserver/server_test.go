package mcpserver

import (
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
)

func TestAccountOutputOmitsEchoedCredential(t *testing.T) {
	upstream := map[string]any{
		"api_key": "must-not-leave-the-server",
		"email":   "caller@example.com",
		"credits": float64(42),
		"nested": map[string]any{
			"access-token": "must-not-leave-the-server",
			"safe":         true,
		},
	}

	output := accountOutput(upstream)
	if _, exists := output["api_key"]; exists {
		t.Fatal("account output contains api_key")
	}
	if output["email"] != upstream["email"] || output["credits"] != upstream["credits"] {
		t.Fatalf("account output lost safe fields: %#v", output)
	}
	if upstream["api_key"] == nil {
		t.Fatal("sanitization mutated the upstream response")
	}
	nested := output["nested"].(Output)
	if _, exists := nested["access-token"]; exists || nested["safe"] != true {
		t.Fatalf("nested sanitization failed: %#v", nested)
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
	account := tool("account", "Account", "Account", false, emptyInputSchema(), accountOutputSchema())
	if !account.Annotations.ReadOnlyHint || !account.Annotations.IdempotentHint || *account.Annotations.DestructiveHint {
		t.Fatalf("account annotations = %#v", account.Annotations)
	}
	lookup := tool("lookup", "Lookup", "Lookup", true, ipsInputSchema(), ipsOutputSchema())
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
