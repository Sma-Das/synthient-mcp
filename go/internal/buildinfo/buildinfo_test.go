package buildinfo

import "testing"

func TestUserAgentUsesBuildVersion(t *testing.T) {
	original := Version
	t.Cleanup(func() { Version = original })
	Version = "1.2.3"
	if got := UserAgent(); got != "synthient-mcp-go/1.2.3" {
		t.Fatalf("UserAgent() = %q", got)
	}
	Version = " "
	if got := UserAgent(); got != "synthient-mcp-go/dev" {
		t.Fatalf("UserAgent() fallback = %q", got)
	}
}
