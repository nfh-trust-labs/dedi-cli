package crypto

import (
	"encoding/json"
	"testing"
)

func TestStripProof_RemovesExistingProof(t *testing.T) {
	doc := []byte(`{"domain":"example.org","proof":{"jws":"abc"},"name":"Example"}`)

	stripped, err := StripProof(doc)
	if err != nil {
		t.Fatalf("StripProof() error = %v", err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(stripped, &fields); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if _, ok := fields["proof"]; ok {
		t.Error("expected \"proof\" field to be removed")
	}
	if _, ok := fields["domain"]; !ok {
		t.Error("expected \"domain\" field to survive")
	}
	if _, ok := fields["name"]; !ok {
		t.Error("expected \"name\" field to survive")
	}
}

func TestStripProof_NoOpWhenProofAbsent(t *testing.T) {
	doc := []byte(`{"domain":"example.org","name":"Example"}`)

	stripped, err := StripProof(doc)
	if err != nil {
		t.Fatalf("StripProof() error = %v", err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(stripped, &fields); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if len(fields) != 2 {
		t.Errorf("expected 2 fields to survive untouched, got %d: %+v", len(fields), fields)
	}
}

func TestStripProof_MalformedJSON(t *testing.T) {
	_, err := StripProof([]byte(`{not valid json`))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestCanonicalize_ReordersKeys(t *testing.T) {
	got, err := Canonicalize([]byte(`{"b":1,"a":2}`))
	if err != nil {
		t.Fatalf("Canonicalize() error = %v", err)
	}
	want := `{"a":2,"b":1}`
	if string(got) != want {
		t.Errorf("Canonicalize() = %q, want %q", got, want)
	}
}

func TestCanonicalize_NonASCII(t *testing.T) {
	// JCS requires non-ASCII characters to be emitted as literal UTF-8, not
	// \uXXXX escapes (unlike Go's default json.Marshal, which escapes them).
	got, err := Canonicalize([]byte(`{"name":"café"}`))
	if err != nil {
		t.Fatalf("Canonicalize() error = %v", err)
	}
	want := "{\"name\":\"café\"}"
	if string(got) != want {
		t.Errorf("Canonicalize() = %q, want %q", got, want)
	}
}

func TestCanonicalize_MalformedJSON(t *testing.T) {
	_, err := Canonicalize([]byte(`{not valid json`))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestSigningInput_StripsThenCanonicalizes(t *testing.T) {
	doc := []byte(`{"b":1,"proof":{"jws":"abc"},"a":2}`)

	got, err := SigningInput(doc)
	if err != nil {
		t.Fatalf("SigningInput() error = %v", err)
	}
	want := `{"a":2,"b":1}`
	if string(got) != want {
		t.Errorf("SigningInput() = %q, want %q", got, want)
	}
}
