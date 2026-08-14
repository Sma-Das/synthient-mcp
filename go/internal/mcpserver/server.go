package mcpserver

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	synthientsdk "github.com/synthient/go-synthient/v2"

	"github.com/Sma-Das/synthient-mcp/go/internal/buildinfo"
)

type EmptyInput struct{}

type IPLookupInput struct {
	IPs []string `json:"ips" jsonschema:"IPv4 or IPv6 addresses to enrich, up to 1000 entries"`
}

type DomainInput struct {
	Domain string `json:"domain" jsonschema:"Domain name to inspect, such as example.com"`
}

type IPLookupOutput struct {
	IPs []synthientsdk.IP `json:"ips"`
}

type API interface {
	Account(context.Context) (synthientsdk.Account, error)
	LookupIP(context.Context, string) (synthientsdk.IP, error)
	LookupIPs(context.Context, []string) ([]synthientsdk.IP, error)
	LookupDomain(context.Context, string) (synthientsdk.Domain, error)
}

func New(client API, schemaCache *mcp.SchemaCache) *mcp.Server {
	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "synthient-mcp-go",
			Title:   "Synthient Intelligence",
			Version: buildinfo.Version,
		},
		&mcp.ServerOptions{
			Instructions: "Use these tools to enrich IP addresses, inspect domain honeypot activity, and check the caller's Synthient account scopes and quota. Intelligence lookups are metered and can consume account credit.",
			Capabilities: &mcp.ServerCapabilities{},
			SchemaCache:  schemaCache,
		},
	)

	mcp.AddTool(server, tool(
		"get_account",
		"Get Synthient account",
		"Return account ownership, granted API scopes, remaining lookup credits, and quota reset timing for the supplied Synthient API key.",
		false,
		emptyInputSchema(),
	), func(ctx context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, synthientsdk.Account, error) {
		value, err := client.Account(ctx)
		if err != nil {
			return nil, synthientsdk.Account{}, err
		}
		return successResult(accountSummary(value)), value, nil
	})

	mcp.AddTool(server, tool(
		"lookup_ip",
		"Look up IP intelligence",
		"Enrich 1 to 1,000 IPv4 or IPv6 addresses with Synthient intelligence. A successful lookup consumes lookup credit; multiple addresses use discounted batch billing.",
		true,
		ipsInputSchema(),
	), func(ctx context.Context, _ *mcp.CallToolRequest, input IPLookupInput) (*mcp.CallToolResult, IPLookupOutput, error) {
		if len(input.IPs) < 1 || len(input.IPs) > 1000 {
			return nil, IPLookupOutput{}, fmt.Errorf("ips must contain between 1 and 1000 entries")
		}
		ips := make([]string, len(input.IPs))
		for index, item := range input.IPs {
			ip, err := normalizeIP(item)
			if err != nil {
				return nil, IPLookupOutput{}, fmt.Errorf("ips[%d]: %w", index, err)
			}
			ips[index] = ip
		}

		var values []synthientsdk.IP
		if len(ips) == 1 {
			value, err := client.LookupIP(ctx, ips[0])
			if err != nil {
				return nil, IPLookupOutput{}, err
			}
			values = []synthientsdk.IP{value}
		} else {
			var err error
			values, err = client.LookupIPs(ctx, ips)
			if err != nil {
				return nil, IPLookupOutput{}, err
			}
		}
		return successResult(ipSummary(values)), IPLookupOutput{IPs: values}, nil
	})

	mcp.AddTool(server, tool(
		"lookup_domain",
		"Look up domain intelligence",
		"Return Synthient Helios honeypot intelligence for a domain. A successful lookup consumes lookup credit.",
		true,
		domainInputSchema(),
	), func(ctx context.Context, _ *mcp.CallToolRequest, input DomainInput) (*mcp.CallToolResult, synthientsdk.Domain, error) {
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

	return server
}

func tool(name, title, description string, metered bool, inputSchema *jsonschema.Schema) *mcp.Tool {
	readOnly := !metered
	destructive := metered
	openWorld := true
	return &mcp.Tool{
		Name:        name,
		Title:       title,
		Description: description,
		InputSchema: inputSchema,
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    readOnly,
			DestructiveHint: &destructive,
			IdempotentHint:  !metered,
			OpenWorldHint:   &openWorld,
		},
	}
}

func accountSummary(account synthientsdk.Account) string {
	identity := strings.TrimSpace(strings.Join([]string{account.FirstName, account.LastName}, " "))
	if identity == "" {
		identity = account.Email
	}
	organization := account.Organization.Name
	if organization == "" {
		organization = "no organization"
	}
	return fmt.Sprintf("Synthient account %s (%s): %d lookup credits remain; quota resets in %d seconds.", identity, organization, account.LookupQuota.Credits, account.LookupQuota.ResetsIn)
}

func ipSummary(ips []synthientsdk.IP) string {
	if len(ips) != 1 {
		return fmt.Sprintf("Retrieved Synthient intelligence for %d IP addresses.", len(ips))
	}
	ip := ips[0]
	return fmt.Sprintf("%s: risk score %d, ASN %d, country %s.", ip.IP, ip.Intelligence.RiskScore, ip.Network.Asn, fallback(ip.Location.Country, "unknown"))
}

func domainSummary(domain synthientsdk.Domain) string {
	return fmt.Sprintf("%s: status %s, %d events in the last 24 hours, %d unique IPs in the last 24 hours.", domain.Domain, fallback(domain.Status, "unknown"), domain.Stats.Events24H, domain.UniqueIPs.Value24H)
}

func fallback(value, replacement string) string {
	if strings.TrimSpace(value) == "" {
		return replacement
	}
	return value
}

func successResult(message string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: message}}}
}

func normalizeIP(value string) (string, error) {
	value = strings.TrimSpace(value)
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" {
		return "", fmt.Errorf("ip must contain an IPv4 or IPv6 address")
	}
	return address.Unmap().String(), nil
}

func normalizeDomain(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".")
	if value == "" || len(value) > 253 {
		return "", fmt.Errorf("domain must contain an ASCII or punycode domain name up to 253 characters")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || !asciiLetterOrDigit(label[0]) || !asciiLetterOrDigit(label[len(label)-1]) {
			return "", fmt.Errorf("domain must contain valid DNS labels")
		}
		for index := 1; index < len(label)-1; index++ {
			if !asciiLetterOrDigit(label[index]) && label[index] != '-' {
				return "", fmt.Errorf("domain must contain valid DNS labels")
			}
		}
	}
	return value, nil
}

func asciiLetterOrDigit(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func emptyInputSchema() *jsonschema.Schema {
	return &jsonschema.Schema{Type: "object", AdditionalProperties: rejectSchema()}
}

func ipsInputSchema() *jsonschema.Schema {
	minimum, maximum := 1, 1000
	return objectInputSchema(map[string]*jsonschema.Schema{
		"ips": {Type: "array", Items: ipStringSchema(), MinItems: &minimum, MaxItems: &maximum},
	}, []string{"ips"})
}

func domainInputSchema() *jsonschema.Schema {
	minimum, maximum := 1, 254
	return objectInputSchema(map[string]*jsonschema.Schema{
		"domain": {Type: "string", MinLength: &minimum, MaxLength: &maximum, Pattern: `^[A-Za-z0-9.-]+$`, Description: "ASCII or punycode domain name"},
	}, []string{"domain"})
}

func ipStringSchema() *jsonschema.Schema {
	minimum, maximum := 2, 45
	return &jsonschema.Schema{Type: "string", MinLength: &minimum, MaxLength: &maximum, Pattern: `^[0-9A-Fa-f:.]+$`, Description: "IPv4 or IPv6 address"}
}

func objectInputSchema(properties map[string]*jsonschema.Schema, required []string) *jsonschema.Schema {
	return &jsonschema.Schema{Type: "object", Properties: properties, Required: required, AdditionalProperties: rejectSchema()}
}

func rejectSchema() *jsonschema.Schema {
	return &jsonschema.Schema{Not: &jsonschema.Schema{}}
}
