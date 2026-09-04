package protocol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// realisticDeDiFile mirrors the protocol repo's own examples/dedi.public-keys.json
// (structurally — the jws value is a placeholder, matching the spec's own examples,
// since this test is about wire-format parsing, not signature verification).
const realisticDeDiFile = `{
  "dedi_version": "0.1",
  "type": "dedi-file",
  "source_url": "https://example.org/dedi/dedi.public-keys.json",
  "next_update": "2026-07-15T10:00:00Z",
  "publisher": {
    "domain": "example.org",
    "key": {"kid": "key-1", "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
  },
  "namespace": "example.org",
  "registry": {
    "name": "public-keys",
    "schema": "https://example.org/schemas/Public_key.json",
    "state": "live",
    "updated_at": "2026-07-08T10:00:00Z"
  },
  "records": [
    {
      "record_name": "auth-service",
      "details": {"public_key_id": "example.org:auth", "keyType": "ed25519"}
    },
    {
      "record_name": "signing-service",
      "details": {"public_key_id": "example.org:signing", "keyType": "ed25519"}
    }
  ],
  "proof": {
    "verification_method": "key-1",
    "canonicalization": "JCS",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PLACEHOLDER"
  }
}`

func TestParseDeDiFile(t *testing.T) {
	f, err := ParseDeDiFile([]byte(realisticDeDiFile))
	if err != nil {
		t.Fatalf("ParseDeDiFile() error = %v", err)
	}

	if f.DediVersion != "0.1" {
		t.Errorf("DediVersion = %q", f.DediVersion)
	}
	if f.Type != TypeDeDiFile {
		t.Errorf("Type = %q, want %q", f.Type, TypeDeDiFile)
	}
	if f.SourceURL != "https://example.org/dedi/dedi.public-keys.json" {
		t.Errorf("SourceURL = %q", f.SourceURL)
	}
	wantNextUpdate := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	if !f.NextUpdate.Equal(wantNextUpdate) {
		t.Errorf("NextUpdate = %v, want %v", f.NextUpdate, wantNextUpdate)
	}
	if f.Publisher.Domain != "example.org" {
		t.Errorf("Publisher.Domain = %q", f.Publisher.Domain)
	}
	if f.Publisher.Key.Kid != "key-1" {
		t.Errorf("Publisher.Key.Kid = %q", f.Publisher.Key.Kid)
	}
	if f.Namespace != "example.org" {
		t.Errorf("Namespace = %q", f.Namespace)
	}
	if f.Registry.Name != "public-keys" {
		t.Errorf("Registry.Name = %q", f.Registry.Name)
	}
	if !f.Registry.Schema.IsURL() || f.Registry.Schema.URL != "https://example.org/schemas/Public_key.json" {
		t.Errorf("Registry.Schema = %+v", f.Registry.Schema)
	}
	if f.Registry.State != RegistryStateLive {
		t.Errorf("Registry.State = %q", f.Registry.State)
	}
	if len(f.Records) != 2 {
		t.Fatalf("len(Records) = %d, want 2", len(f.Records))
	}
	if f.Records[0].RecordName != "auth-service" {
		t.Errorf("Records[0].RecordName = %q", f.Records[0].RecordName)
	}
	var details map[string]interface{}
	if err := json.Unmarshal(f.Records[0].Details, &details); err != nil {
		t.Fatalf("unmarshal Details: %v", err)
	}
	if details["public_key_id"] != "example.org:auth" {
		t.Errorf("Details = %v", details)
	}
	if f.Proof.VerificationMethod != "key-1" {
		t.Errorf("Proof.VerificationMethod = %q", f.Proof.VerificationMethod)
	}
	if f.Proof.Canonicalization != CanonicalizationJCS {
		t.Errorf("Proof.Canonicalization = %q", f.Proof.Canonicalization)
	}
}

func TestDeDiFile_MarshalUnmarshalRoundTrip(t *testing.T) {
	original, err := ParseDeDiFile([]byte(realisticDeDiFile))
	if err != nil {
		t.Fatalf("ParseDeDiFile() error = %v", err)
	}

	out, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	roundTripped, err := ParseDeDiFile(out)
	if err != nil {
		t.Fatalf("re-ParseDeDiFile() error = %v", err)
	}

	if roundTripped.SourceURL != original.SourceURL ||
		roundTripped.Registry.Name != original.Registry.Name ||
		len(roundTripped.Records) != len(original.Records) ||
		roundTripped.Proof.JWS != original.Proof.JWS {
		t.Errorf("round trip lost data: got %+v, want %+v", roundTripped, original)
	}
}

func TestParseDeDiFile_RegistryAndRecordWithoutDescriptionOrMeta(t *testing.T) {
	// realisticDeDiFile predates decentralized-directory-protocol PR #33 —
	// confirms a file with neither field still parses fine, with both
	// left at their zero values.
	f, err := ParseDeDiFile([]byte(realisticDeDiFile))
	if err != nil {
		t.Fatalf("ParseDeDiFile() error = %v", err)
	}
	if f.Registry.Description != "" {
		t.Errorf("Registry.Description = %q, want empty", f.Registry.Description)
	}
	if len(f.Registry.Meta) != 0 {
		t.Errorf("Registry.Meta = %s, want empty", f.Registry.Meta)
	}
	if f.Records[0].Description != "" {
		t.Errorf("Records[0].Description = %q, want empty", f.Records[0].Description)
	}
	if len(f.Records[0].Meta) != 0 {
		t.Errorf("Records[0].Meta = %s, want empty", f.Records[0].Meta)
	}
}

// realisticDeDiFileWithMeta mirrors PR #33's own example
// (examples/dedi.public-keys.json, as amended by the PR) — registry and
// record description/meta both present.
const realisticDeDiFileWithMeta = `{
  "dedi_version": "0.1",
  "type": "dedi-file",
  "source_url": "https://example.org/dedi/dedi.public-keys.json",
  "next_update": "2026-07-15T10:00:00Z",
  "publisher": {
    "domain": "example.org",
    "key": {"kid": "key-1", "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
  },
  "namespace": "example.org",
  "registry": {
    "name": "public-keys",
    "schema": "https://example.org/schemas/Public_key.json",
    "state": "live",
    "updated_at": "2026-07-08T10:00:00Z",
    "description": "Current signing keys for example.org services",
    "meta": { "display_name": "Example Org signing keys", "contact": "trust@example.org" }
  },
  "records": [
    {
      "record_name": "auth-service",
      "details": {"public_key_id": "example.org:auth", "keyType": "ed25519"},
      "meta": { "rotation_policy": "https://example.org/policies/key-rotation" }
    }
  ],
  "proof": {
    "verification_method": "key-1",
    "canonicalization": "JCS",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PLACEHOLDER"
  }
}`

func TestParseDeDiFile_RegistryAndRecordWithDescriptionAndMeta(t *testing.T) {
	f, err := ParseDeDiFile([]byte(realisticDeDiFileWithMeta))
	if err != nil {
		t.Fatalf("ParseDeDiFile() error = %v", err)
	}
	if f.Registry.Description != "Current signing keys for example.org services" {
		t.Errorf("Registry.Description = %q, unexpected", f.Registry.Description)
	}
	var registryMeta map[string]string
	if err := json.Unmarshal(f.Registry.Meta, &registryMeta); err != nil {
		t.Fatalf("unmarshal Registry.Meta: %v", err)
	}
	if registryMeta["display_name"] != "Example Org signing keys" || registryMeta["contact"] != "trust@example.org" {
		t.Errorf("Registry.Meta = %v, unexpected", registryMeta)
	}
	// The PR's own example leaves records[0].description unset — only meta.
	if f.Records[0].Description != "" {
		t.Errorf("Records[0].Description = %q, want empty (not set in this fixture)", f.Records[0].Description)
	}
	var recordMeta map[string]string
	if err := json.Unmarshal(f.Records[0].Meta, &recordMeta); err != nil {
		t.Fatalf("unmarshal Records[0].Meta: %v", err)
	}
	if recordMeta["rotation_policy"] != "https://example.org/policies/key-rotation" {
		t.Errorf("Records[0].Meta = %v, unexpected", recordMeta)
	}
}

func TestParseDeDiFile_MalformedJSON(t *testing.T) {
	_, err := ParseDeDiFile([]byte(`{not valid`))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if !strings.Contains(err.Error(), "line 1, column") {
		t.Errorf("ParseDeDiFile() error = %q, want it to mention a line/column", err.Error())
	}
}

func TestParseDeDiFile_InlineSchema(t *testing.T) {
	raw := `{
      "dedi_version": "0.1",
      "type": "dedi-file",
      "source_url": "https://example.org/.well-known/dedi.index.json",
      "next_update": "2026-07-15T10:00:00Z",
      "publisher": {"domain": "example.org", "key": {"kid": "key-1", "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}},
      "namespace": "example.org",
      "registry": {
        "name": "trust-anchors",
        "schema": {"type": "object", "required": ["anchor_id"], "properties": {"anchor_id": {"type": "string"}}},
        "state": "live",
        "updated_at": "2026-07-01T09:00:00Z"
      },
      "records": [{"record_name": "lfdt-root", "details": {"anchor_id": "example.org:lfdt-root"}}],
      "proof": {"verification_method": "key-1", "canonicalization": "JCS", "jws": "PLACEHOLDER"}
    }`

	f, err := ParseDeDiFile([]byte(raw))
	if err != nil {
		t.Fatalf("ParseDeDiFile() error = %v", err)
	}
	if f.Registry.Schema.IsURL() {
		t.Fatal("expected an inline schema, got a URL")
	}
	var schema map[string]interface{}
	if err := json.Unmarshal(f.Registry.Schema.Inline, &schema); err != nil {
		t.Fatalf("unmarshal inline schema: %v", err)
	}
	if schema["type"] != "object" {
		t.Errorf("inline schema = %v", schema)
	}
}
