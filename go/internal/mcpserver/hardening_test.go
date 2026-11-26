package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	synthientsdk "github.com/synthient/go-synthient/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/descriptorpb"
)

type legacyAPI struct{ stubAPI }

func (legacyAPI) LookupIP(context.Context, string) (synthientsdk.IP, error) {
	return synthientsdk.IP{IP: "192.0.2.1"}, nil
}

func TestLegacyAliasesReturnJSONText(t *testing.T) {
	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	server := New(legacyAPI{}, mcp.NewSchemaCache(), Options{LegacyToolNames: true})
	if _, err := server.Connect(ctx, serverTransport, nil); err != nil {
		t.Fatal(err)
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "synthient_lookup_ip", Arguments: map[string]any{"ip": "192.0.2.1"}})
	if err != nil || result.IsError || len(result.Content) != 1 {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	var decoded map[string]any
	if err := json.Unmarshal([]byte(text), &decoded); err != nil || decoded["ip"] != "192.0.2.1" {
		t.Fatalf("legacy text is not the JSON payload: %q (%v)", text, err)
	}
}

func TestSafeGRPCErrorDoesNotEchoUpstreamMessages(t *testing.T) {
	for _, err := range []error{
		status.Error(codes.PermissionDenied, "key exact-caller-key lacks scope"),
		errors.New("dial tcp: secret detail"),
		context.DeadlineExceeded,
	} {
		if got := safeGRPCError(err).Error(); strings.Contains(got, "secret") || strings.Contains(got, "exact-caller-key") {
			t.Fatalf("safeGRPCError(%v) = %q", err, got)
		}
	}
	if got := safeGRPCError(status.Error(codes.PermissionDenied, "x")).Error(); !strings.Contains(got, "PermissionDenied") {
		t.Fatalf("status code not reported: %q", got)
	}
}

func TestGRPCSchemaOutputEnforcesFileBudget(t *testing.T) {
	set := &descriptorpb.FileDescriptorSet{}
	for range maxSchemaFiles + 1 {
		set.File = append(set.File, &descriptorpb.FileDescriptorProto{Name: stringPointer("f.proto")})
	}
	if _, err := grpcSchemaOutput(synthientsdk.GRPCSchemaResult{DescriptorSet: set}, false); err == nil {
		t.Fatal("oversized schema was accepted")
	}
}

func TestGRPCSchemaOutputEnforcesServiceAndSizeBudgets(t *testing.T) {
	file := &descriptorpb.FileDescriptorProto{Name: stringPointer("big.proto")}
	for range maxSchemaServices + 1 {
		file.Service = append(file.Service, &descriptorpb.ServiceDescriptorProto{Name: stringPointer("S")})
	}
	if _, err := grpcSchemaOutput(synthientsdk.GRPCSchemaResult{DescriptorSet: &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{file}}}, false); err == nil {
		t.Fatal("service budget was not enforced")
	}

	huge := &descriptorpb.FileDescriptorProto{Name: stringPointer(strings.Repeat("n", maxDescriptorBytes))}
	if _, err := grpcSchemaOutput(synthientsdk.GRPCSchemaResult{DescriptorSet: &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{huge}}}, false); err == nil {
		t.Fatal("serialized summary budget was not enforced")
	}
}
