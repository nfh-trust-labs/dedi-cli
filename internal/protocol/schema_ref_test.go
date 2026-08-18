package protocol

import (
	"encoding/json"
	"testing"
)

func TestSchemaRef_URL_RoundTrip(t *testing.T) {
	raw := []byte(`"https://example.org/schemas/membership.json"`)

	var s SchemaRef
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !s.IsURL() {
		t.Fatal("expected IsURL() == true")
	}
	if s.URL != "https://example.org/schemas/membership.json" {
		t.Errorf("URL = %q", s.URL)
	}

	out, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if string(out) != string(raw) {
		t.Errorf("Marshal() = %s, want %s", out, raw)
	}
}

func TestSchemaRef_Inline_RoundTrip(t *testing.T) {
	raw := []byte(`{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}`)

	var s SchemaRef
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if s.IsURL() {
		t.Fatal("expected IsURL() == false")
	}
	if len(s.Inline) == 0 {
		t.Fatal("expected Inline to be populated")
	}

	out, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var reparsed map[string]interface{}
	if err := json.Unmarshal(out, &reparsed); err != nil {
		t.Fatalf("re-parse Marshal() output: %v", err)
	}
	if reparsed["type"] != "object" {
		t.Errorf("expected inline schema to survive round trip, got %v", reparsed)
	}
}

func TestSchemaRef_EmptyValue(t *testing.T) {
	var s SchemaRef
	if err := json.Unmarshal([]byte(``), &s); err == nil {
		t.Fatal("expected error for empty value")
	}
}

func TestSchemaRef_Marshal_Unset(t *testing.T) {
	var s SchemaRef
	if _, err := json.Marshal(s); err == nil {
		t.Fatal("expected error marshaling an unset SchemaRef")
	}
}
