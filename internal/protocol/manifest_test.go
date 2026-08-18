package protocol

import (
	"encoding/json"
	"testing"
	"time"
)

// realisticManifest mirrors the protocol repo's own examples/dedi.index.json —
// one referenced files[] entry and one inline files[] entry, matching the
// oneOf union the real manifest schema declares.
const realisticManifest = `{
  "dedi_version": "0.1",
  "type": "dedi-manifest",
  "domain": "example.org",
  "name": "Example Org Trust Services",
  "keys": [
    {"kid": "key-1", "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
  ],
  "updated_at": "2026-07-01T09:00:00Z",
  "next_update": "2026-07-15T10:00:00Z",
  "files": [
    {
      "registry": "public-keys",
      "url": "https://example.org/dedi/dedi.public-keys.json",
      "digest": "sha-256:9f2c1d4e7a8b0c3d5e6f70819293a4b5c6d7e8f90a1b2c3d4e5f60718293aeba",
      "schema": "https://example.org/schemas/Public_key.json"
    },
    ` + realisticDeDiFile + `
  ],
  "proof": {
    "verification_method": "key-1",
    "canonicalization": "JCS",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PLACEHOLDER"
  }
}`

func TestParseManifest(t *testing.T) {
	m, err := ParseManifest([]byte(realisticManifest))
	if err != nil {
		t.Fatalf("ParseManifest() error = %v", err)
	}

	if m.Type != TypeManifest {
		t.Errorf("Type = %q, want %q", m.Type, TypeManifest)
	}
	if m.Domain != "example.org" {
		t.Errorf("Domain = %q", m.Domain)
	}
	if m.Name != "Example Org Trust Services" {
		t.Errorf("Name = %q", m.Name)
	}
	if len(m.Keys) != 1 || m.Keys[0].Kid != "key-1" {
		t.Errorf("Keys = %+v", m.Keys)
	}
	wantUpdatedAt := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	if !m.UpdatedAt.Equal(wantUpdatedAt) {
		t.Errorf("UpdatedAt = %v, want %v", m.UpdatedAt, wantUpdatedAt)
	}
	if len(m.Files) != 2 {
		t.Fatalf("len(Files) = %d, want 2", len(m.Files))
	}
	if m.Files[0].IsInline() {
		t.Error("Files[0] expected referenced, got inline")
	}
	if m.Files[0].Referenced.Registry != "public-keys" {
		t.Errorf("Files[0].Referenced.Registry = %q", m.Files[0].Referenced.Registry)
	}
	if !m.Files[1].IsInline() {
		t.Error("Files[1] expected inline, got referenced")
	}
	if m.Files[1].Inline.Registry.Name != "public-keys" {
		t.Errorf("Files[1].Inline.Registry.Name = %q", m.Files[1].Inline.Registry.Name)
	}
	if m.Proof.VerificationMethod != "key-1" {
		t.Errorf("Proof.VerificationMethod = %q", m.Proof.VerificationMethod)
	}
}

func TestManifest_MarshalUnmarshalRoundTrip(t *testing.T) {
	original, err := ParseManifest([]byte(realisticManifest))
	if err != nil {
		t.Fatalf("ParseManifest() error = %v", err)
	}

	out, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	roundTripped, err := ParseManifest(out)
	if err != nil {
		t.Fatalf("re-ParseManifest() error = %v", err)
	}

	if roundTripped.Domain != original.Domain ||
		len(roundTripped.Keys) != len(original.Keys) ||
		len(roundTripped.Files) != len(original.Files) ||
		roundTripped.Files[0].IsInline() != original.Files[0].IsInline() ||
		roundTripped.Files[1].IsInline() != original.Files[1].IsInline() ||
		roundTripped.Proof.JWS != original.Proof.JWS {
		t.Errorf("round trip lost data: got %+v, want %+v", roundTripped, original)
	}
}

func TestParseManifest_MalformedJSON(t *testing.T) {
	if _, err := ParseManifest([]byte(`{not valid`)); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestParseManifest_DescriptionAbsentByDefault(t *testing.T) {
	// realisticManifest predates decentralized-directory-protocol PR #33.
	m, err := ParseManifest([]byte(realisticManifest))
	if err != nil {
		t.Fatalf("ParseManifest() error = %v", err)
	}
	if m.Description != "" {
		t.Errorf("Description = %q, want empty", m.Description)
	}
}

func TestParseManifest_WithDescription(t *testing.T) {
	raw := `{
      "dedi_version": "0.1",
      "domain": "example.org",
      "description": "Trust registries of Example Org",
      "keys": [{"kid": "key-1", "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}],
      "updated_at": "2026-07-01T09:00:00Z",
      "next_update": "2026-07-15T10:00:00Z",
      "files": [],
      "proof": {"verification_method": "key-1", "canonicalization": "JCS", "jws": "PLACEHOLDER"}
    }`
	m, err := ParseManifest([]byte(raw))
	if err != nil {
		t.Fatalf("ParseManifest() error = %v", err)
	}
	if m.Description != "Trust registries of Example Org" {
		t.Errorf("Description = %q, unexpected", m.Description)
	}
}

func TestParseManifest_OptionalNameAbsent(t *testing.T) {
	raw := `{
      "dedi_version": "0.1",
      "domain": "example.org",
      "keys": [{"kid": "key-1", "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}],
      "updated_at": "2026-07-01T09:00:00Z",
      "next_update": "2026-07-15T10:00:00Z",
      "files": [],
      "proof": {"verification_method": "key-1", "canonicalization": "JCS", "jws": "PLACEHOLDER"}
    }`
	m, err := ParseManifest([]byte(raw))
	if err != nil {
		t.Fatalf("ParseManifest() error = %v", err)
	}
	if m.Name != "" {
		t.Errorf("expected empty Name, got %q", m.Name)
	}
	if m.Type != "" {
		t.Errorf("expected empty Type, got %q", m.Type)
	}
}
