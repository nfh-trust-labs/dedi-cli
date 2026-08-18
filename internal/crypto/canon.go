// Package crypto implements the DeDi protocol's canonicalization and
// detached-signature scheme: RFC 8785 JSON Canonicalization (JCS) and a
// fixed-profile detached EdDSA JWS. See canon.go and jws.go.
package crypto

import (
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"
)

// StripProof returns doc with its top-level "proof" property removed. It
// decodes doc as a shallow map[string]json.RawMessage, deletes "proof", and
// re-encodes — deliberately not a full struct round-trip, so no other field
// (numbers, unknown JWK members, non-ASCII strings) is ever reformatted by
// Go's encoder before JCS gets a chance to canonicalize it itself. It is a
// no-op (beyond re-encoding) if doc has no "proof" field to begin with.
func StripProof(doc []byte) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(doc, &fields); err != nil {
		return nil, fmt.Errorf("strip proof: unmarshal: %w", err)
	}
	delete(fields, "proof")
	stripped, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("strip proof: marshal: %w", err)
	}
	return stripped, nil
}

// Canonicalize applies RFC 8785 JSON Canonicalization (JCS) via
// github.com/gowebpki/jcs.
func Canonicalize(doc []byte) ([]byte, error) {
	canonical, err := jcs.Transform(doc)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}
	return canonical, nil
}

// SigningInput returns Canonicalize(StripProof(doc)) — the exact bytes that
// get signed and verified. Every signer and verifier of this protocol should
// call this and nothing else, so they can never disagree about what got
// signed.
func SigningInput(doc []byte) ([]byte, error) {
	stripped, err := StripProof(doc)
	if err != nil {
		return nil, err
	}
	return Canonicalize(stripped)
}
