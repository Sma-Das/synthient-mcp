package mcpserver

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	synthientsdk "github.com/synthient/go-synthient/v2"
)

type stubAPI struct{}

func (stubAPI) Account(context.Context) (synthientsdk.Account, error) {
	return synthientsdk.Account{}, nil
}
func (stubAPI) LookupIP(context.Context, string) (synthientsdk.IP, error) {
	return synthientsdk.IP{}, nil
}
func (stubAPI) LookupIPs(context.Context, []string) ([]synthientsdk.IP, error) { return nil, nil }
func (stubAPI) LookupDomain(context.Context, string) (synthientsdk.Domain, error) {
	return synthientsdk.Domain{}, nil
}
func (stubAPI) FeedSnapshots(context.Context, string, int, string) (synthientsdk.FeedSnapshotsPage, error) {
	return synthientsdk.FeedSnapshotsPage{}, nil
}
func (stubAPI) FeedSnapshotMeta(context.Context, string, []string) (synthientsdk.FeedSnapshotMeta, error) {
	return synthientsdk.FeedSnapshotMeta{}, nil
}
func (stubAPI) SampleStream(context.Context, string, int, int, map[string]string) ([]map[string]any, bool, error) {
	return nil, false, nil
}
func (stubAPI) GRPCSchema(context.Context, []string) (synthientsdk.GRPCSchemaResult, error) {
	return synthientsdk.GRPCSchemaResult{}, nil
}

func TestLegacyToolNamesAreOptIn(t *testing.T) {
	for _, test := range []struct {
		name    string
		options []Options
		want    []string
	}{
		{name: "canonical", want: []string{"feed_snapshot_meta", "get_account", "grpc_schema", "list_feed_snapshots", "list_feed_streams", "lookup_domain", "lookup_ip", "sample_stream"}},
		{name: "legacy aliases", options: []Options{{LegacyToolNames: true}}, want: []string{"feed_snapshot_meta", "get_account", "grpc_schema", "list_feed_snapshots", "list_feed_streams", "lookup_domain", "lookup_ip", "sample_stream", "synthient_account", "synthient_lookup_domain", "synthient_lookup_ip", "synthient_lookup_ips"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			serverTransport, clientTransport := mcp.NewInMemoryTransports()
			server := New(stubAPI{}, mcp.NewSchemaCache(), test.options...)
			if _, err := server.Connect(ctx, serverTransport, nil); err != nil {
				t.Fatal(err)
			}
			client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
			session, err := client.Connect(ctx, clientTransport, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			result, err := session.ListTools(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]string, len(result.Tools))
			for index, tool := range result.Tools {
				got[index] = tool.Name
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("tools = %#v; want %#v", got, test.want)
			}
		})
	}
}

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
