package validate

import (
	"strings"
	"testing"
)

// These fixtures deliberately mirror a *signed* document's shape (proof
// present, keys non-empty) — that's what ValidateManifestEnvelope/
// ValidateDeDiFileEnvelope actually check in practice, since sign runs
// this validation post-sign, not against the unsigned pre-sign input
// (which never has "proof" yet).

const validManifestJSON = `{
	"dedi_version": "0.1",
	"type": "dedi-manifest",
	"domain": "example.org",
	"keys": [{"kid": "key-1", "kty": "OKP", "crv": "Ed25519", "x": "abc"}],
	"updated_at": "2026-07-01T09:00:00Z",
	"next_update": "2099-01-01T00:00:00Z",
	"files": [],
	"proof": {"verification_method": "key-1", "canonicalization": "JCS", "jws": "PLACEHOLDER"}
}`

const validDeDiFileJSON = `{
	"dedi_version": "0.1",
	"type": "dedi-file",
	"source_url": "https://example.org/dedi/dedi.trust-anchors.json",
	"next_update": "2099-01-01T00:00:00Z",
	"publisher": {"domain": "example.org", "key": {"kid": "key-1", "kty": "OKP", "crv": "Ed25519", "x": "abc"}},
	"namespace": "example.org",
	"registry": {
		"name": "trust-anchors",
		"schema": "https://example.org/schemas/trust-anchor.json",
		"state": "live",
		"updated_at": "2026-07-01T09:00:00Z"
	},
	"records": [
		{"record_name": "r1", "details": {"anchor_id": "example.org:r1"}}
	],
	"proof": {"verification_method": "key-1", "canonicalization": "JCS", "jws": "PLACEHOLDER"}
}`

func TestValidateManifestEnvelope_Valid(t *testing.T) {
	if err := ValidateManifestEnvelope([]byte(validManifestJSON)); err != nil {
		t.Errorf("ValidateManifestEnvelope() error = %v, want nil", err)
	}
}

func TestValidateDeDiFileEnvelope_Valid(t *testing.T) {
	if err := ValidateDeDiFileEnvelope([]byte(validDeDiFileJSON)); err != nil {
		t.Errorf("ValidateDeDiFileEnvelope() error = %v, want nil", err)
	}
}

func TestValidateManifestEnvelope_UnknownField(t *testing.T) {
	raw := strings.Replace(validManifestJSON, `"files": [],`, `"files": [], "bogus_field": true,`, 1)
	if err := ValidateManifestEnvelope([]byte(raw)); err == nil {
		t.Fatal("expected error for unknown top-level field")
	}
}

func TestValidateManifestEnvelope_MissingRequiredField(t *testing.T) {
	raw := strings.Replace(validManifestJSON, `"domain": "example.org",`, "", 1)
	if err := ValidateManifestEnvelope([]byte(raw)); err == nil {
		t.Fatal("expected error for missing required field")
	}
}

func TestValidateManifestEnvelope_InvalidTypeConst(t *testing.T) {
	raw := strings.Replace(validManifestJSON, `"dedi-manifest"`, `"not-a-manifest"`, 1)
	if err := ValidateManifestEnvelope([]byte(raw)); err == nil {
		t.Fatal("expected error for invalid type const")
	}
}

func TestValidateManifestEnvelope_MalformedJSON(t *testing.T) {
	if err := ValidateManifestEnvelope([]byte(`not json`)); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestValidateDeDiFileEnvelope_UnknownField(t *testing.T) {
	raw := strings.Replace(validDeDiFileJSON, `"namespace": "example.org",`, `"namespace": "example.org", "bogus_field": true,`, 1)
	if err := ValidateDeDiFileEnvelope([]byte(raw)); err == nil {
		t.Fatal("expected error for unknown top-level field")
	}
}

func TestValidateDeDiFileEnvelope_InvalidStateEnum(t *testing.T) {
	raw := strings.Replace(validDeDiFileJSON, `"state": "live"`, `"state": "not-a-real-state"`, 1)
	if err := ValidateDeDiFileEnvelope([]byte(raw)); err == nil {
		t.Fatal("expected error for invalid registry.state enum")
	}
}

func TestValidateDeDiFileEnvelope_MissingRequiredField(t *testing.T) {
	raw := strings.Replace(validDeDiFileJSON, `"namespace": "example.org",`, "", 1)
	if err := ValidateDeDiFileEnvelope([]byte(raw)); err == nil {
		t.Fatal("expected error for missing required field")
	}
}

func TestValidateDeDiFileEnvelope_MalformedJSON(t *testing.T) {
	if err := ValidateDeDiFileEnvelope([]byte(`not json`)); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}
