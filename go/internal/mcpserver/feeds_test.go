package mcpserver

import (
	"strings"
	"testing"

	synthientsdk "github.com/synthient/go-synthient/v2"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestNormalizeFeedStream(t *testing.T) {
	stream, err := normalizeFeedStream(" TLS ", true)
	if err != nil || stream.Name != "honeypot_https" {
		t.Fatalf("stream=%#v error=%v", stream, err)
	}
	if _, err := normalizeFeedStream("dns", true); err == nil || !strings.Contains(err.Error(), "not live") {
		t.Fatalf("DNS live error = %v", err)
	}
	if _, err := normalizeFeedStream("unknown", false); err == nil {
		t.Fatal("unknown stream succeeded")
	}
}

func TestSnapshotSegments(t *testing.T) {
	for input, wantLength := range map[string]int{"latest": 1, "2026-08-14": 1, "2026-08-14/0": 2, "2026-08-14/23": 2} {
		segments, err := snapshotSegments(input)
		if err != nil || len(segments) != wantLength {
			t.Errorf("snapshotSegments(%q)=%#v,%v", input, segments, err)
		}
	}
	for _, input := range []string{"", "2026-02-30", "2026-08-14/01", "2026-08-14/24", "../account"} {
		if _, err := snapshotSegments(input); err == nil {
			t.Errorf("snapshotSegments(%q) succeeded", input)
		}
	}
}

func TestValidateFiltersAndSymbols(t *testing.T) {
	if err := validateFilters(map[string]string{"details.method": "GET"}); err != nil {
		t.Fatal(err)
	}
	if err := validateFilters(map[string]string{"bad/path": "GET"}); err == nil {
		t.Fatal("unsafe filter name succeeded")
	}
	if err := validateSymbols([]string{"synthient.v1.SynthientService"}); err != nil {
		t.Fatal(err)
	}
	if err := validateSymbols([]string{"https://attacker.example"}); err == nil {
		t.Fatal("unsafe symbol succeeded")
	}
}

func TestGRPCSchemaOutputIsSummarizedAndDescriptorIsOptional(t *testing.T) {
	method := &descriptorpb.MethodDescriptorProto{
		Name:       stringPointer("StreamProxies"),
		InputType:  stringPointer(".synthient.v1.Request"),
		OutputType: stringPointer(".synthient.v1.ProxyEvent"),
	}
	service := &descriptorpb.ServiceDescriptorProto{
		Name:   stringPointer("SynthientService"),
		Method: []*descriptorpb.MethodDescriptorProto{method},
	}
	file := &descriptorpb.FileDescriptorProto{
		Name:    stringPointer("synthient.proto"),
		Package: stringPointer("synthient.v1"),
		Service: []*descriptorpb.ServiceDescriptorProto{service},
	}
	result := synthientsdk.GRPCSchemaResult{
		Endpoint:      "grpc.synthient.com:443",
		Symbols:       []string{"synthient.v1.SynthientService"},
		DescriptorSet: &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{file}},
	}
	output, err := grpcSchemaOutput(result, false)
	if err != nil || len(output.Services) != 1 || output.DescriptorJSON != "" {
		t.Fatalf("output=%#v error=%v", output, err)
	}
	output, err = grpcSchemaOutput(result, true)
	if err != nil || output.DescriptorJSON == "" {
		t.Fatalf("descriptor output=%#v error=%v", output, err)
	}
}

func stringPointer(value string) *string { return &value }
