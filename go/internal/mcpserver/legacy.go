package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	synthientsdk "github.com/synthient/go-synthient/v2"
)

type LegacyIPInput struct {
	IP string `json:"ip" jsonschema:"IPv4 or IPv6 address to enrich"`
}

type LegacyIPsInput struct {
	IPs []string `json:"ips" jsonschema:"IPv4 or IPv6 addresses to enrich, up to 1000 entries"`
}

type LegacyIPsOutput struct {
	Results []synthientsdk.IP `json:"results"`
}

func registerLegacyTools(server *mcp.Server, client API) {
	mcp.AddTool(server, tool("synthient_account", "Get Synthient account (legacy)", "Legacy compatibility alias for get_account.", false, emptyInputSchema()),
		func(ctx context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, synthientsdk.Account, error) {
			account, err := client.Account(ctx)
			if err != nil {
				return nil, synthientsdk.Account{}, err
			}
			return successResult(accountSummary(account)), account, nil
		})

	mcp.AddTool(server, tool("synthient_lookup_ip", "Look up one IP (legacy)", "Legacy single-address compatibility alias; prefer lookup_ip with an ips array.", true, nil),
		func(ctx context.Context, _ *mcp.CallToolRequest, input LegacyIPInput) (*mcp.CallToolResult, synthientsdk.IP, error) {
			ip, err := normalizeIP(input.IP)
			if err != nil {
				return nil, synthientsdk.IP{}, err
			}
			value, err := client.LookupIP(ctx, ip)
			if err != nil {
				return nil, synthientsdk.IP{}, err
			}
			return successResult(ipSummary([]synthientsdk.IP{value})), value, nil
		})

	mcp.AddTool(server, tool("synthient_lookup_ips", "Look up multiple IPs (legacy)", "Legacy batch compatibility alias; prefer lookup_ip with an ips array.", true, nil),
		func(ctx context.Context, _ *mcp.CallToolRequest, input LegacyIPsInput) (*mcp.CallToolResult, LegacyIPsOutput, error) {
			if len(input.IPs) < 1 || len(input.IPs) > 1000 {
				return nil, LegacyIPsOutput{}, fmt.Errorf("ips must contain between 1 and 1000 entries")
			}
			ips := make([]string, len(input.IPs))
			for index, item := range input.IPs {
				ip, err := normalizeIP(item)
				if err != nil {
					return nil, LegacyIPsOutput{}, fmt.Errorf("ips[%d]: %w", index, err)
				}
				ips[index] = ip
			}
			values, err := client.LookupIPs(ctx, ips)
			if err != nil {
				return nil, LegacyIPsOutput{}, err
			}
			return successResult(ipSummary(values)), LegacyIPsOutput{Results: values}, nil
		})

	mcp.AddTool(server, tool("synthient_lookup_domain", "Look up a domain (legacy)", "Legacy compatibility alias for lookup_domain.", true, nil),
		func(ctx context.Context, _ *mcp.CallToolRequest, input DomainInput) (*mcp.CallToolResult, synthientsdk.Domain, error) {
			domain, err := normalizeDomain(input.Domain)
			if err != nil {
				return nil, synthientsdk.Domain{}, err
			}
			value, err := client.LookupDomain(ctx, domain)
			if err != nil {
				return nil, synthientsdk.Domain{}, err
			}
			return successResult(domainSummary(value)), value, nil
		})
}
