package protocol

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestFilesEntry_Referenced_RoundTrip(t *testing.T) {
	raw := []byte(`{
      "registry": "public-keys",
      "url": "https://example.org/dedi/dedi.public-keys.json",
      "digest": "sha-256:9f2c1d4e7a8b0c3d5e6f70819293a4b5c6d7e8f90a1b2c3d4e5f60718293aeba",
      "schema": "https://example.org/schemas/Public_key.json"
    }`)

	var f FilesEntry
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if f.IsInline() {
		t.Fatal("expected a referenced entry, got inline")
	}
	if f.Referenced == nil {
		t.Fatal("Referenced is nil")
	}
	if f.Referenced.Registry != "public-keys" {
		t.Errorf("Referenced.Registry = %q", f.Referenced.Registry)
	}
	if f.Referenced.Digest != "sha-256:9f2c1d4e7a8b0c3d5e6f70819293a4b5c6d7e8f90a1b2c3d4e5f60718293aeba" {
		t.Errorf("Referenced.Digest = %q", f.Referenced.Digest)
	}
	if f.Referenced.Schema == nil || !f.Referenced.Schema.IsURL() {
		t.Errorf("Referenced.Schema = %+v", f.Referenced.Schema)
	}

	out, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var roundTripped FilesEntry
	if err := json.Unmarshal(out, &roundTripped); err != nil {
		t.Fatalf("re-Unmarshal() error = %v", err)
	}
	if roundTripped.IsInline() || roundTripped.Referenced.Registry != f.Referenced.Registry {
		t.Errorf("round trip mismatch: got %+v", roundTripped)
	}
}

func TestFilesEntry_Inline_RoundTrip(t *testing.T) {
	raw := []byte(realisticDeDiFile) // a full DeDiFile is a valid inline files[] entry

	var f FilesEntry
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !f.IsInline() {
		t.Fatal("expected an inline entry, got referenced")
	}
	if f.Inline == nil {
		t.Fatal("Inline is nil")
	}
	if f.Inline.Namespace != "example.org" {
		t.Errorf("Inline.Namespace = %q", f.Inline.Namespace)
	}

	out, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var roundTripped FilesEntry
	if err := json.Unmarshal(out, &roundTripped); err != nil {
		t.Fatalf("re-Unmarshal() error = %v", err)
	}
	if !roundTripped.IsInline() || roundTripped.Inline.Namespace != f.Inline.Namespace {
		t.Errorf("round trip mismatch: got %+v", roundTripped)
	}
}

// TestFilesEntry_Inline_RawInlinePreservesExactBytes pins a real bug: an
// inline entry's next_update using a non-Z-normalized timestamp
// (here "+00:00") re-serializes as a bare "Z" after a json.Marshal(Inline)
// round trip — a silent byte change that would make a genuinely valid
// inline file's signature fail verification, since JCS treats this string
// field as opaque rather than reparsing it. RawInline must reproduce the
// original bytes exactly, unlike the old json.Marshal(Inline) path.
func TestFilesEntry_Inline_RawInlinePreservesExactBytes(t *testing.T) {
	raw := []byte(`{
      "dedi_version": "0.1",
      "type": "dedi-file",
      "source_url": "https://example.org/dedi/dedi.public-keys.json",
      "next_update": "2026-07-15T10:00:00+00:00",
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
      "records": [],
      "proof": {
        "verification_method": "key-1",
        "canonicalization": "JCS",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PLACEHOLDER"
      }
    }`)

	var f FilesEntry
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !f.IsInline() {
		t.Fatal("expected an inline entry")
	}

	// RawInline must preserve the original bytes exactly, "+00:00" and all.
	if string(f.RawInline) != string(raw) {
		t.Errorf("RawInline = %s, want it to equal the original bytes exactly", f.RawInline)
	}

	// The fix: FilesEntry's own MarshalJSON must use RawInline, so the
	// offset survives all the way through a Marshal(f) call too.
	// (encoding/json compacts whatever bytes a custom MarshalJSON returns,
	// so this checks for the substring rather than full byte-equality —
	// that compaction is expected, unrelated to this fix.)
	got, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !bytes.Contains(got, []byte(`"next_update":"2026-07-15T10:00:00+00:00"`)) {
		t.Errorf("Marshal(f) = %s, want it to preserve the original +00:00 offset", got)
	}

	// The bug this regression-tests: re-marshaling the *parsed* Inline
	// struct directly (bypassing RawInline) silently drops the "+00:00"
	// offset in favor of "Z" — proving RawInline is actually necessary,
	// not just redundant with what Marshal(Inline) would already produce.
	viaParsedStruct, err := json.Marshal(f.Inline)
	if err != nil {
		t.Fatalf("Marshal(f.Inline) error = %v", err)
	}
	if bytes.Contains(viaParsedStruct, []byte("+00:00")) {
		t.Fatal("expected json.Marshal(f.Inline) to normalize the offset to \"Z\" (the bug this test pins) — " +
			"if this now fails, the underlying encoding/json behavior changed and this test's premise should be revisited")
	}
}

func TestFilesEntry_Marshal_Unset(t *testing.T) {
	var f FilesEntry
	if _, err := json.Marshal(f); err == nil {
		t.Fatal("expected error marshaling an unset FilesEntry")
	}
}

func TestFilesEntry_MalformedJSON(t *testing.T) {
	var f FilesEntry
	if err := json.Unmarshal([]byte(`{not valid`), &f); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}
