package mcpserver

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	synthientsdk "github.com/synthient/go-synthient/v2"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/descriptorpb"
)

const (
	defaultSampleCount   = 10
	maxSampleCount       = 50
	defaultSampleTimeout = 10
	maxSampleTimeout     = 15
	maxSampleOutputBytes = 1 << 20
	maxDescriptorBytes   = 1 << 20
)

type FeedStream struct {
	Name          string   `json:"name"`
	Aliases       []string `json:"aliases"`
	Description   string   `json:"description"`
	RequiredScope string   `json:"required_scope"`
	Live          bool     `json:"live"`
}

var feedStreams = []FeedStream{
	{Name: "proxies", Aliases: []string{"proxy"}, Description: "Proxy IP observations across residential, datacenter, and mobile networks.", RequiredScope: "PROXY_FEEDS", Live: true},
	{Name: "anonymizers", Aliases: []string{"anonymizer"}, Description: "VPN, Tor, private relay, and other anonymizer ranges.", RequiredScope: "ANONYMIZERS_FEED", Live: true},
	{Name: "torrents", Aliases: []string{"torrent"}, Description: "DHT and tracker peer sightings with metadata and observed peers.", RequiredScope: "TORRENTS_FEED", Live: true},
	{Name: "honeypot_http", Aliases: []string{"helios_http", "http"}, Description: "HTTP request captures from Helios honeypot sensors.", RequiredScope: "HONEYPOT_HTTP_FEED", Live: true},
	{Name: "honeypot_https", Aliases: []string{"helios_https", "https", "tls"}, Description: "TLS ClientHello captures from Helios honeypot sensors.", RequiredScope: "HONEYPOT_HTTPS_FEED", Live: true},
	{Name: "honeypot_dns", Aliases: []string{"helios_dns", "dns"}, Description: "DNS resolution observations from Helios honeypot tunnels.", RequiredScope: "HONEYPOT_DNS_FEED", Live: false},
	{Name: "honeypot_adb", Aliases: []string{"helios_adb", "adb"}, Description: "Android Debug Bridge shell commands captured by Helios sensors.", RequiredScope: "HONEYPOT_ADB_FEED", Live: false},
}

type ListFeedStreamsOutput struct {
	Streams []FeedStream `json:"streams"`
}

type ListFeedSnapshotsInput struct {
	Stream string `json:"stream" jsonschema:"feed stream name"`
	Limit  int    `json:"limit,omitempty" jsonschema:"page size from 1 to 500; defaults to 100"`
	Cursor string `json:"cursor,omitempty" jsonschema:"pagination token from next_cursor"`
}

type FeedSnapshotMetaInput struct {
	Stream string `json:"stream" jsonschema:"feed stream name"`
	Date   string `json:"date" jsonschema:"latest, YYYY-MM-DD, or YYYY-MM-DD/HH"`
}

type SampleStreamInput struct {
	Stream         string            `json:"stream" jsonschema:"live feed stream name"`
	Count          int               `json:"count,omitempty" jsonschema:"matching events to collect; defaults to 10 and maximum 50"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty" jsonschema:"deadline in seconds; defaults to 10 and maximum 15"`
	Filters        map[string]string `json:"filters,omitempty" jsonschema:"up to 10 exact-match field filters; nested fields use dot notation"`
}

type SampleStreamOutput struct {
	Stream    string           `json:"stream"`
	Count     int              `json:"count"`
	Events    []map[string]any `json:"events"`
	Truncated bool             `json:"truncated"`
}

type GRPCSchemaInput struct {
	Symbols           []string `json:"symbols,omitempty" jsonschema:"up to 25 fully-qualified service or message names; omit to list exposed services"`
	IncludeDescriptor bool     `json:"include_descriptor,omitempty" jsonschema:"include descriptor JSON when it is at most 1 MiB"`
}

type GRPCFile struct {
	Name    string `json:"name"`
	Package string `json:"package"`
}

type GRPCMethod struct {
	Name   string `json:"name"`
	Input  string `json:"input"`
	Output string `json:"output"`
}

type GRPCService struct {
	Name    string       `json:"name"`
	Methods []GRPCMethod `json:"methods"`
}

type GRPCSchemaOutput struct {
	Endpoint       string        `json:"endpoint"`
	Symbols        []string      `json:"symbols"`
	Files          []GRPCFile    `json:"files"`
	Services       []GRPCService `json:"services"`
	DescriptorJSON string        `json:"descriptor_json,omitempty"`
}

func registerFeedTools(server *mcp.Server, client API, options Options) {
	mcp.AddTool(server, tool("list_feed_streams", "List Synthient feeds", "List supported Synthient snapshot and live feed streams, aliases, and required scopes.", false, nil),
		func(context.Context, *mcp.CallToolRequest, EmptyInput) (*mcp.CallToolResult, ListFeedStreamsOutput, error) {
			return successResult(fmt.Sprintf("Synthient exposes %d feed streams; %d support live sampling.", len(feedStreams), liveStreamCount())), ListFeedStreamsOutput{Streams: feedStreams}, nil
		})

	mcp.AddTool(server, tool("list_feed_snapshots", "List feed snapshots", "List daily and hourly Parquet snapshots for a Synthient feed, newest first, with cursor pagination.", false, nil),
		func(ctx context.Context, _ *mcp.CallToolRequest, input ListFeedSnapshotsInput) (*mcp.CallToolResult, synthientsdk.FeedSnapshotsPage, error) {
			stream, err := normalizeFeedStream(input.Stream, false)
			if err != nil {
				return nil, synthientsdk.FeedSnapshotsPage{}, err
			}
			limit := input.Limit
			if limit == 0 {
				limit = 100
			}
			if limit < 1 || limit > 500 {
				return nil, synthientsdk.FeedSnapshotsPage{}, fmt.Errorf("limit must be between 1 and 500")
			}
			if len(input.Cursor) > 2048 {
				return nil, synthientsdk.FeedSnapshotsPage{}, fmt.Errorf("cursor must not exceed 2048 characters")
			}
			page, err := client.FeedSnapshots(ctx, stream.Name, limit, input.Cursor)
			if err != nil {
				return nil, synthientsdk.FeedSnapshotsPage{}, err
			}
			return successResult(fmt.Sprintf("Found %d %s snapshots; next cursor present: %t.", len(page.Feeds), stream.Name, page.NextCursor != "")), page, nil
		})

	mcp.AddTool(server, tool("feed_snapshot_meta", "Get feed snapshot metadata", "Get checksum, byte size, row count, schema, and canonical time for one Synthient Parquet snapshot.", false, nil),
		func(ctx context.Context, _ *mcp.CallToolRequest, input FeedSnapshotMetaInput) (*mcp.CallToolResult, synthientsdk.FeedSnapshotMeta, error) {
			stream, err := normalizeFeedStream(input.Stream, false)
			if err != nil {
				return nil, synthientsdk.FeedSnapshotMeta{}, err
			}
			segments, err := snapshotSegments(input.Date)
			if err != nil {
				return nil, synthientsdk.FeedSnapshotMeta{}, err
			}
			meta, err := client.FeedSnapshotMeta(ctx, stream.Name, segments)
			if err != nil {
				return nil, synthientsdk.FeedSnapshotMeta{}, err
			}
			return successResult(fmt.Sprintf("%s snapshot %s: %d rows, %d bytes, checksum %s.", stream.Name, meta.ID, meta.Rows, meta.Size, meta.Checksum)), meta, nil
		})

	mcp.AddTool(server, tool("sample_stream", "Sample a live feed", "Collect a small, bounded, optionally filtered sample from a real-time Synthient feed.", false, nil),
		func(ctx context.Context, _ *mcp.CallToolRequest, input SampleStreamInput) (*mcp.CallToolResult, SampleStreamOutput, error) {
			stream, err := normalizeFeedStream(input.Stream, true)
			if err != nil {
				return nil, SampleStreamOutput{}, err
			}
			count := input.Count
			if count == 0 {
				count = defaultSampleCount
			}
			if count < 1 || count > maxSampleCount {
				return nil, SampleStreamOutput{}, fmt.Errorf("count must be between 1 and %d", maxSampleCount)
			}
			maximumTimeout := maxSampleTimeout
			if options.SampleTimeout > 0 {
				maximumTimeout = int(options.SampleTimeout / time.Second)
				if maximumTimeout < 1 {
					maximumTimeout = 1
				}
			}
			timeout := input.TimeoutSeconds
			if timeout == 0 {
				timeout = min(defaultSampleTimeout, maximumTimeout)
			}
			if timeout < 1 || timeout > maximumTimeout {
				return nil, SampleStreamOutput{}, fmt.Errorf("timeout_seconds must be between 1 and %d", maximumTimeout)
			}
			if err := validateFilters(input.Filters); err != nil {
				return nil, SampleStreamOutput{}, err
			}
			sampleCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
			defer cancel()
			events, truncated, err := client.SampleStream(sampleCtx, stream.Name, count, maxSampleOutputBytes, input.Filters)
			if err != nil {
				return nil, SampleStreamOutput{}, err
			}
			output := SampleStreamOutput{Stream: stream.Name, Count: len(events), Events: events, Truncated: truncated}
			return successResult(fmt.Sprintf("Collected %d matching %s events; truncated: %t.", len(events), stream.Name, truncated)), output, nil
		})

	mcp.AddTool(server, tool("grpc_schema", "Inspect Synthient gRPC schema", "Fetch an allowlisted Synthient protobuf schema through TLS gRPC reflection and return a bounded service summary.", false, nil),
		func(ctx context.Context, _ *mcp.CallToolRequest, input GRPCSchemaInput) (*mcp.CallToolResult, GRPCSchemaOutput, error) {
			if err := validateSymbols(input.Symbols); err != nil {
				return nil, GRPCSchemaOutput{}, err
			}
			schemaCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			result, err := client.GRPCSchema(schemaCtx, input.Symbols)
			if err != nil {
				return nil, GRPCSchemaOutput{}, err
			}
			output, err := grpcSchemaOutput(result, input.IncludeDescriptor)
			if err != nil {
				return nil, GRPCSchemaOutput{}, err
			}
			return successResult(fmt.Sprintf("Synthient gRPC reflection returned %d services across %d files.", len(output.Services), len(output.Files))), output, nil
		})
}

func normalizeFeedStream(value string, requireLive bool) (FeedStream, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, stream := range feedStreams {
		if value == stream.Name || contains(stream.Aliases, value) {
			if requireLive && !stream.Live {
				return FeedStream{}, fmt.Errorf("stream %q supports snapshots but not live sampling", stream.Name)
			}
			return stream, nil
		}
	}
	return FeedStream{}, fmt.Errorf("unknown feed stream %q", value)
}

func snapshotSegments(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if value == "latest" {
		return []string{"latest"}, nil
	}
	date, hour, hasHour := strings.Cut(value, "/")
	if _, err := time.Parse("2006-01-02", date); err != nil {
		return nil, fmt.Errorf("date must be latest, YYYY-MM-DD, or YYYY-MM-DD/HH")
	}
	if !hasHour {
		return []string{date}, nil
	}
	parsedHour, err := strconv.Atoi(hour)
	if err != nil || parsedHour < 0 || parsedHour > 23 || strconv.Itoa(parsedHour) != hour {
		return nil, fmt.Errorf("snapshot hour must be an integer from 0 to 23 without padding")
	}
	return []string{date, hour}, nil
}

func validateFilters(filters map[string]string) error {
	if len(filters) > 10 {
		return fmt.Errorf("filters must contain at most 10 entries")
	}
	for key, value := range filters {
		if key == "" || len(key) > 128 || len(value) > 256 {
			return fmt.Errorf("filter names must be 1-128 characters and values at most 256 characters")
		}
		for _, r := range key {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
				return fmt.Errorf("filter name %q contains unsupported characters", key)
			}
		}
	}
	return nil
}

func validateSymbols(symbols []string) error {
	if len(symbols) > 25 {
		return fmt.Errorf("symbols must contain at most 25 entries")
	}
	for index, symbol := range symbols {
		if symbol == "" || len(symbol) > 256 || strings.HasPrefix(symbol, ".") || strings.HasSuffix(symbol, ".") {
			return fmt.Errorf("symbols[%d] must be a fully-qualified protobuf name up to 256 characters", index)
		}
		for _, r := range symbol {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.') {
				return fmt.Errorf("symbols[%d] contains unsupported characters", index)
			}
		}
	}
	return nil
}

func grpcSchemaOutput(result synthientsdk.GRPCSchemaResult, includeDescriptor bool) (GRPCSchemaOutput, error) {
	if result.DescriptorSet == nil {
		return GRPCSchemaOutput{}, fmt.Errorf("synthient gRPC reflection returned no descriptor set")
	}
	output := GRPCSchemaOutput{Endpoint: result.Endpoint, Symbols: result.Symbols, Services: summarizeServices(result.DescriptorSet)}
	for _, file := range result.DescriptorSet.GetFile() {
		output.Files = append(output.Files, GRPCFile{Name: file.GetName(), Package: file.GetPackage()})
	}
	if includeDescriptor {
		descriptor, err := protojson.Marshal(result.DescriptorSet)
		if err != nil {
			return GRPCSchemaOutput{}, fmt.Errorf("encode descriptor set: %w", err)
		}
		if len(descriptor) > maxDescriptorBytes {
			return GRPCSchemaOutput{}, fmt.Errorf("descriptor JSON exceeds the 1 MiB MCP output limit; request specific symbols or omit include_descriptor")
		}
		output.DescriptorJSON = string(descriptor)
	}
	return output, nil
}

func summarizeServices(set *descriptorpb.FileDescriptorSet) []GRPCService {
	services := []GRPCService{}
	for _, file := range set.GetFile() {
		for _, service := range file.GetService() {
			name := service.GetName()
			if file.GetPackage() != "" {
				name = file.GetPackage() + "." + name
			}
			summary := GRPCService{Name: name}
			for _, method := range service.GetMethod() {
				summary.Methods = append(summary.Methods, GRPCMethod{Name: method.GetName(), Input: strings.TrimPrefix(method.GetInputType(), "."), Output: strings.TrimPrefix(method.GetOutputType(), ".")})
			}
			services = append(services, summary)
		}
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	return services
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func liveStreamCount() int {
	count := 0
	for _, stream := range feedStreams {
		if stream.Live {
			count++
		}
	}
	return count
}
