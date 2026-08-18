package sign

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nfh-trust-labs/dedi-cli/internal/crypto"
	"github.com/nfh-trust-labs/dedi-cli/internal/protocol"
)

func unsignedManifest(kid string, pubKey protocol.Key) protocol.Manifest {
	return protocol.Manifest{
		Type:        protocol.TypeManifest,
		DediVersion: "0.1",
		Domain:      "example.test",
		Keys:        []protocol.Key{pubKey},
		UpdatedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NextUpdate:  time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		Files:       []protocol.FilesEntry{},
	}
}

func unsignedDeDiFile(pubKey protocol.Key) protocol.DeDiFile {
	return protocol.DeDiFile{
		DediVersion: "0.1",
		Type:        protocol.TypeDeDiFile,
		SourceURL:   "https://example.test/dedi/dedi.membership.json",
		NextUpdate:  time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		Publisher:   protocol.Publisher{Domain: "example.test", Key: pubKey},
		Namespace:   "example.test",
		Registry: protocol.Registry{
			Name:      "membership",
			Schema:    mustSchemaRef(`{"type":"object"}`),
			State:     protocol.RegistryStateLive,
			UpdatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		Records: []protocol.Record{
			{RecordName: "member-1", Details: json.RawMessage(`{"name":"Alice"}`)},
		},
	}
}

func mustSchemaRef(inlineJSON string) protocol.SchemaRef {
	var s protocol.SchemaRef
	if err := json.Unmarshal([]byte(inlineJSON), &s); err != nil {
		panic(err)
	}
	return s
}

// verifyIndependently re-derives the signing input from the signed struct's
// own marshaled bytes and checks it directly against internal/crypto,
// bypassing internal/sign's own code paths — confirming internal/sign and
// internal/crypto agree with each other.
func verifyIndependently(t *testing.T, signedJSON []byte, pubKey protocol.Key, jwsStr string) {
	t.Helper()
	pub, err := pubKey.Ed25519PublicKey()
	if err != nil {
		t.Fatalf("Ed25519PublicKey() error = %v", err)
	}
	signingInput, err := crypto.SigningInput(signedJSON)
	if err != nil {
		t.Fatalf("crypto.SigningInput() error = %v", err)
	}
	if err := crypto.Verify(pub, signingInput, jwsStr); err != nil {
		t.Errorf("crypto.Verify() error = %v, want nil", err)
	}
}

func TestSignManifest(t *testing.T) {
	k, err := GenerateKey("key-1")
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	priv, err := k.PrivateKey()
	if err != nil {
		t.Fatalf("PrivateKey() error = %v", err)
	}
	pubKey := k.PublicKey()

	m := unsignedManifest("key-1", pubKey)
	signed, err := SignManifest(m, priv, "key-1")
	if err != nil {
		t.Fatalf("SignManifest() error = %v", err)
	}

	if signed.Proof.VerificationMethod != "key-1" {
		t.Errorf("Proof.VerificationMethod = %q, want key-1", signed.Proof.VerificationMethod)
	}
	if signed.Proof.Canonicalization != protocol.CanonicalizationJCS {
		t.Errorf("Proof.Canonicalization = %q", signed.Proof.Canonicalization)
	}
	if signed.Proof.JWS == "" {
		t.Fatal("expected a non-empty JWS")
	}

	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	verifyIndependently(t, raw, pubKey, signed.Proof.JWS)
}

func TestSignDeDiFile(t *testing.T) {
	k, err := GenerateKey("key-1")
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	priv, err := k.PrivateKey()
	if err != nil {
		t.Fatalf("PrivateKey() error = %v", err)
	}
	pubKey := k.PublicKey()

	f := unsignedDeDiFile(pubKey)
	signed, err := SignDeDiFile(f, priv)
	if err != nil {
		t.Fatalf("SignDeDiFile() error = %v", err)
	}

	if signed.Proof.VerificationMethod != pubKey.Kid {
		t.Errorf("Proof.VerificationMethod = %q, want %q", signed.Proof.VerificationMethod, pubKey.Kid)
	}
	if signed.Proof.Canonicalization != protocol.CanonicalizationJCS {
		t.Errorf("Proof.Canonicalization = %q", signed.Proof.Canonicalization)
	}
	if signed.Proof.JWS == "" {
		t.Fatal("expected a non-empty JWS")
	}

	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	verifyIndependently(t, raw, pubKey, signed.Proof.JWS)
}

func TestSignDeDiFile_TamperDetected(t *testing.T) {
	k, err := GenerateKey("key-1")
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	priv, err := k.PrivateKey()
	if err != nil {
		t.Fatalf("PrivateKey() error = %v", err)
	}
	pubKey := k.PublicKey()

	f := unsignedDeDiFile(pubKey)
	signed, err := SignDeDiFile(f, priv)
	if err != nil {
		t.Fatalf("SignDeDiFile() error = %v", err)
	}

	// Tamper with a record's details after signing.
	signed.Records[0].Details = json.RawMessage(`{"name":"Mallory"}`)

	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	pub, err := pubKey.Ed25519PublicKey()
	if err != nil {
		t.Fatalf("Ed25519PublicKey() error = %v", err)
	}
	signingInput, err := crypto.SigningInput(raw)
	if err != nil {
		t.Fatalf("crypto.SigningInput() error = %v", err)
	}
	if err := crypto.Verify(pub, signingInput, signed.Proof.JWS); err == nil {
		t.Fatal("expected tampering to be detected, but Verify() succeeded")
	}
}

func TestSignManifest_DifferentKeysProduceDifferentSignatures(t *testing.T) {
	k1, _ := GenerateKey("key-1")
	k2, _ := GenerateKey("key-2")
	priv1, _ := k1.PrivateKey()
	priv2, _ := k2.PrivateKey()

	m := unsignedManifest("key-1", k1.PublicKey())
	signed1, err := SignManifest(m, priv1, "key-1")
	if err != nil {
		t.Fatalf("SignManifest() error = %v", err)
	}
	signed2, err := SignManifest(m, priv2, "key-1")
	if err != nil {
		t.Fatalf("SignManifest() error = %v", err)
	}
	if signed1.Proof.JWS == signed2.Proof.JWS {
		t.Error("expected different keys to produce different signatures")
	}
}
