package mcpserver

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Sma-Das/synthient-mcp/go/internal/buildinfo"
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

type API interface {
	Account(context.Context) (map[string]any, error)
	LookupIP(context.Context, string) (map[string]any, error)
	LookupIPs(context.Context, []string) (map[string]any, error)
	LookupDomain(context.Context, string) (map[string]any, error)
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
		"synthient_account",
		"Get Synthient account",
		"Return account ownership, granted API scopes, remaining lookup credits, and quota reset timing for the supplied Synthient API key.",
		false,
		emptyInputSchema(),
		accountOutputSchema(),
	), func(ctx context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, Output, error) {
		value, err := client.Account(ctx)
		if err != nil {
			return nil, nil, err
		}
		return successResult("Account information retrieved; see structured content."), accountOutput(value), nil
	})

	mcp.AddTool(server, tool(
		"synthient_lookup_ip",
		"Look up IP intelligence",
		"Enrich one IPv4 or IPv6 address with Synthient intelligence. A successful lookup consumes lookup credit.",
		true,
		ipInputSchema(),
		ipOutputSchema(),
	), func(ctx context.Context, _ *mcp.CallToolRequest, input IPInput) (*mcp.CallToolResult, Output, error) {
		ip, err := normalizeIP(input.IP)
		if err != nil {
			return nil, nil, err
		}
		value, err := client.LookupIP(ctx, ip)
		if err != nil {
			return nil, nil, err
		}
		return successResult("IP intelligence retrieved; see structured content."), Output(value), nil
	})

	mcp.AddTool(server, tool(
		"synthient_lookup_ips",
		"Look up multiple IPs",
		"Enrich 1 to 1,000 IPv4 or IPv6 addresses in one discounted Synthient batch lookup. Successful batch calls consume lookup credits; duplicates are preserved in the request.",
		true,
		ipsInputSchema(),
		ipsOutputSchema(),
	), func(ctx context.Context, _ *mcp.CallToolRequest, input IPsInput) (*mcp.CallToolResult, Output, error) {
		if len(input.IPs) < 1 || len(input.IPs) > 1000 {
			return nil, nil, fmt.Errorf("ips must contain between 1 and 1000 entries")
		}
		ips := make([]string, len(input.IPs))
		for index, item := range input.IPs {
			ip, err := normalizeIP(item)
			if err != nil {
				return nil, nil, fmt.Errorf("ips[%d]: %w", index, err)
			}
			ips[index] = ip
		}
		value, err := client.LookupIPs(ctx, ips)
		if err != nil {
			return nil, nil, err
		}
		return successResult("Batch IP intelligence retrieved; see structured content."), Output(value), nil
	})

	mcp.AddTool(server, tool(
		"synthient_lookup_domain",
		"Look up domain intelligence",
		"Return Synthient Helios honeypot intelligence for a domain. A successful lookup consumes lookup credit.",
		true,
		domainInputSchema(),
		domainOutputSchema(),
	), func(ctx context.Context, _ *mcp.CallToolRequest, input DomainInput) (*mcp.CallToolResult, Output, error) {
		domain, err := normalizeDomain(input.Domain)
		if err != nil {
			return nil, nil, err
		}
		value, err := client.LookupDomain(ctx, domain)
		if err != nil {
			return nil, nil, err
		}
		return successResult("Domain intelligence retrieved; see structured content."), Output(value), nil
	})

	return server
}

func accountOutput(value map[string]any) Output {
	output := Output{}
	for key, item := range value {
		if sensitiveAccountField(key) {
			continue
		}
		output[key] = sanitizeAccountValue(item)
	}
	return output
}

func sanitizeAccountValue(value any) any {
	switch value := value.(type) {
	case map[string]any:
		return accountOutput(value)
	case []any:
		cleaned := make([]any, len(value))
		for index, item := range value {
			cleaned[index] = sanitizeAccountValue(item)
		}
		return cleaned
	default:
		return value
	}
}

func sensitiveAccountField(key string) bool {
	normalized := strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, key)
	return normalized == "apikey" || normalized == "authorization" || normalized == "accesstoken" || normalized == "token" || normalized == "secret"
}

func tool(name, title, description string, metered bool, inputSchema, outputSchema *jsonschema.Schema) *mcp.Tool {
	readOnly := !metered
	destructive := metered
	openWorld := true
	return &mcp.Tool{
		Name:         name,
		Title:        title,
		Description:  description,
		InputSchema:  inputSchema,
		OutputSchema: outputSchema,
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    readOnly,
			DestructiveHint: &destructive,
			IdempotentHint:  !metered,
			OpenWorldHint:   &openWorld,
		},
	}
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

func ipInputSchema() *jsonschema.Schema {
	return objectInputSchema(map[string]*jsonschema.Schema{"ip": ipStringSchema()}, []string{"ip"})
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

func accountOutputSchema() *jsonschema.Schema {
	return openObjectSchema(map[string]*jsonschema.Schema{
		"first_name":   {Type: "string"},
		"last_name":    {Type: "string"},
		"email":        {Type: "string"},
		"organization": openObjectSchema(nil),
		"scopes":       {Type: "array", Items: &jsonschema.Schema{Type: "string"}},
		"lookup_quota": openObjectSchema(nil),
	})
}

func ipOutputSchema() *jsonschema.Schema {
	return openObjectSchema(map[string]*jsonschema.Schema{
		"ip":           {Type: "string"},
		"network":      openObjectSchema(nil),
		"location":     openObjectSchema(nil),
		"intelligence": openObjectSchema(nil),
	})
}

func ipsOutputSchema() *jsonschema.Schema {
	return openObjectSchema(map[string]*jsonschema.Schema{
		"results": {Type: "array", Items: openObjectSchema(nil)},
	})
}

func domainOutputSchema() *jsonschema.Schema {
	return openObjectSchema(map[string]*jsonschema.Schema{
		"type": {Type: "string"},
		"data": openObjectSchema(nil),
	})
}

func openObjectSchema(properties map[string]*jsonschema.Schema) *jsonschema.Schema {
	return &jsonschema.Schema{Type: "object", Properties: properties, AdditionalProperties: &jsonschema.Schema{}}
}

func rejectSchema() *jsonschema.Schema {
	return &jsonschema.Schema{Not: &jsonschema.Schema{}}
}
