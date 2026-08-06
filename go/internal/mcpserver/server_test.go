package mcpserver

import "testing"

func TestAccountOutputOmitsEchoedCredential(t *testing.T) {
	upstream := map[string]any{
		"api_key": "must-not-leave-the-server",
		"email":   "caller@example.com",
		"credits": float64(42),
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
}
