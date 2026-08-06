package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Sma-Das/synthient-mcp/go/internal/synthient"
)

type EmptyInput struct{}

type IPInput struct {
	IP string `json:"ip" jsonschema:"IPv4 or IPv6 address to enrich"`
}

type IPsInput struct {
	IPs []string `json:"ips" jsonschema:"IPv4 or IPv6 addresses to enrich, up to 1000 entries"`
}

type DomainInput struct {
	Domain string `json:"domain" jsonschema:"Domain name to inspect, such as example.com"`
}

type Output map[string]any

func New(client *synthient.Client, schemaCache *mcp.SchemaCache) *mcp.Server {
	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "synthient-mcp-go",
			Title:   "Synthient Intelligence",
			Version: "0.1.0",
		},
		&mcp.ServerOptions{
			Instructions: "Use these read-only tools to enrich IP addresses, inspect domain honeypot activity, and check the caller's Synthient account scopes and quota.",
			Capabilities: &mcp.ServerCapabilities{},
			SchemaCache:  schemaCache,
		},
	)

	mcp.AddTool(server, tool(
		"synthient_account",
		"Get Synthient account",
		"Return account ownership, granted API scopes, remaining lookup credits, and quota reset timing for the supplied Synthient API key.",
	), func(ctx context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, Output, error) {
		value, err := client.Account(ctx)
		return nil, accountOutput(value), err
	})

	mcp.AddTool(server, tool(
		"synthient_lookup_ip",
		"Look up IP intelligence",
		"Enrich one IPv4 or IPv6 address with network, location, risk, behavior, anonymizer category, device, and provider intelligence from Synthient.",
	), func(ctx context.Context, _ *mcp.CallToolRequest, input IPInput) (*mcp.CallToolResult, Output, error) {
		input.IP = strings.TrimSpace(input.IP)
		if len(input.IP) < 2 || len(input.IP) > 45 {
			return nil, nil, fmt.Errorf("ip must contain an IPv4 or IPv6 address")
		}
		value, err := client.LookupIP(ctx, input.IP)
		return nil, Output(value), err
	})

	mcp.AddTool(server, tool(
		"synthient_lookup_ips",
		"Look up multiple IPs",
		"Enrich 1 to 1,000 IPv4 or IPv6 addresses in one discounted Synthient batch lookup. Invalid and duplicate IPs are excluded from billing by Synthient.",
	), func(ctx context.Context, _ *mcp.CallToolRequest, input IPsInput) (*mcp.CallToolResult, Output, error) {
		if len(input.IPs) < 1 || len(input.IPs) > 1000 {
			return nil, nil, fmt.Errorf("ips must contain between 1 and 1000 entries")
		}
		value, err := client.LookupIPs(ctx, input.IPs)
		return nil, Output(value), err
	})

	mcp.AddTool(server, tool(
		"synthient_lookup_domain",
		"Look up domain intelligence",
		"Return Synthient Helios honeypot intelligence for a domain, including observation status, event statistics, time series, top subdomains and ports, and recent events.",
	), func(ctx context.Context, _ *mcp.CallToolRequest, input DomainInput) (*mcp.CallToolResult, Output, error) {
		input.Domain = strings.TrimSpace(input.Domain)
		if input.Domain == "" || len(input.Domain) > 253 {
			return nil, nil, fmt.Errorf("domain must contain a domain name up to 253 characters")
		}
		value, err := client.LookupDomain(ctx, input.Domain)
		return nil, Output(value), err
	})

	return server
}

func accountOutput(value map[string]any) Output {
	output := Output{}
	for key, item := range value {
		if key != "api_key" && key != "apiKey" {
			output[key] = item
		}
	}
	return output
}

func tool(name, title, description string) *mcp.Tool {
	readOnly := true
	notDestructive := false
	return &mcp.Tool{
		Name:        name,
		Title:       title,
		Description: description,
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: &notDestructive,
			IdempotentHint:  true,
			OpenWorldHint:   &readOnly,
		},
	}
}
