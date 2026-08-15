package httpserver

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestResourceMetadataLocationPreservesResourcePath(t *testing.T) {
	resource := "https://mcp.example.com/team/synthient/mcp"
	wantURL := "https://mcp.example.com/.well-known/oauth-protected-resource/team/synthient/mcp"
	if got := resourceMetadataURL(resource); got != wantURL {
		t.Fatalf("metadata URL = %q; want %q", got, wantURL)
	}
	if got := resourceMetadataPath(resource); got != "/.well-known/oauth-protected-resource/team/synthient/mcp" {
		t.Fatalf("metadata path = %q", got)
	}
}

func TestScopeClaimsAcceptOAuthAndProviderForms(t *testing.T) {
	if got := scopeClaim(json.RawMessage(`"mcp:tools synthient:read"`)); !reflect.DeepEqual(got, []string{"mcp:tools", "synthient:read"}) {
		t.Fatalf("scope = %#v", got)
	}
	if got := scopeClaim(json.RawMessage(`["mcp:tools","synthient:read"]`)); !reflect.DeepEqual(got, []string{"mcp:tools", "synthient:read"}) {
		t.Fatalf("scp = %#v", got)
	}
	if got := uniqueStrings([]string{"mcp:tools", "mcp:tools", " synthient:read "}); !reflect.DeepEqual(got, []string{"mcp:tools", "synthient:read"}) {
		t.Fatalf("unique scopes = %#v", got)
	}
}
