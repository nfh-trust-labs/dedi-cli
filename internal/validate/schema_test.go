package validate

import (
	"encoding/json"
	"testing"

	"github.com/nfh-trust-labs/dedi-cli/internal/protocol"
)

func TestCompileInlineSchema_Valid(t *testing.T) {
	schema, err := CompileInlineSchema(json.RawMessage(`{"type":"object"}`))
	if err != nil {
		t.Fatalf("CompileInlineSchema() error = %v", err)
	}
	if schema == nil {
		t.Fatal("expected a non-nil schema")
	}
}

func TestCompileInlineSchema_Invalid(t *testing.T) {
	// "type" must be a string or array of strings, not a number — a
	// structurally invalid JSON Schema, not just invalid JSON.
	_, err := CompileInlineSchema(json.RawMessage(`{"type":123}`))
	if err == nil {
		t.Fatal("expected error for an invalid JSON Schema")
	}
}

func TestValidateRecords_Valid(t *testing.T) {
	schema, err := CompileInlineSchema(json.RawMessage(`{"type":"object","required":["name"]}`))
	if err != nil {
		t.Fatalf("CompileInlineSchema() error = %v", err)
	}
	records := []protocol.Record{
		{RecordName: "r1", Details: json.RawMessage(`{"name":"Alice"}`)},
	}
	if err := ValidateRecords(records, schema); err != nil {
		t.Errorf("ValidateRecords() error = %v, want nil", err)
	}
}

func TestValidateRecords_ViolatesSchema(t *testing.T) {
	schema, err := CompileInlineSchema(json.RawMessage(`{"type":"object","required":["name"]}`))
	if err != nil {
		t.Fatalf("CompileInlineSchema() error = %v", err)
	}
	records := []protocol.Record{
		{RecordName: "r1", Details: json.RawMessage(`{"missing_name":true}`)},
	}
	if err := ValidateRecords(records, schema); err == nil {
		t.Fatal("expected a schema violation error")
	}
}

func TestValidateRecords_MalformedDetails(t *testing.T) {
	schema, err := CompileInlineSchema(json.RawMessage(`{"type":"object"}`))
	if err != nil {
		t.Fatalf("CompileInlineSchema() error = %v", err)
	}
	// Constructed directly (bypassing protocol.ParseDeDiFile, which would
	// never produce invalid JSON in Details) to exercise this defensive path.
	records := []protocol.Record{
		{RecordName: "r1", Details: json.RawMessage(`not valid json`)},
	}
	if err := ValidateRecords(records, schema); err == nil {
		t.Fatal("expected an unmarshal error")
	}
}
