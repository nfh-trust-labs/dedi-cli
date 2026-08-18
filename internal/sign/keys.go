// Package sign implements key generation and signing for the DeDi
// protocol, used by cmd/dedi-cli.
package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/nfh-trust-labs/dedi-cli/internal/protocol"
)

// PrivateJWK is the on-disk keypair shape (RFC 8037: d = base64url of the
// 32-byte Ed25519 seed, not the 64-byte expanded key). Never part of the
// wire protocol — protocol.Key only ever carries public material.
type PrivateJWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	D   string `json:"d"` // sensitive — never logged
}

// GenerateKey creates a new Ed25519 keypair with the given kid.
func GenerateKey(kid string) (PrivateJWK, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return PrivateJWK{}, fmt.Errorf("generate key: %w", err)
	}
	return PrivateJWK{
		Kid: kid,
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
		D:   base64.RawURLEncoding.EncodeToString(priv.Seed()),
	}, nil
}

// PrivateKey decodes the JWK's seed ("d") into an ed25519.PrivateKey,
// verifying the derived public key matches "x" — catching a hand-edited or
// corrupted key file rather than silently signing with the wrong key.
func (k PrivateJWK) PrivateKey() (ed25519.PrivateKey, error) {
	if k.Kty != "OKP" || k.Crv != "Ed25519" {
		return nil, fmt.Errorf("private jwk %q: not an OKP/Ed25519 key (kty=%q, crv=%q)", k.Kid, k.Kty, k.Crv)
	}
	seed, err := base64.RawURLEncoding.DecodeString(k.D)
	if err != nil {
		return nil, fmt.Errorf("private jwk %q: decode d: %w", k.Kid, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("private jwk %q: d decodes to %d bytes, want %d", k.Kid, len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	wantPub, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("private jwk %q: decode x: %w", k.Kid, err)
	}
	if !priv.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(wantPub)) {
		return nil, fmt.Errorf("private jwk %q: x does not match the public key derived from d", k.Kid)
	}
	return priv, nil
}

// PublicKey returns the public JWK (protocol.Key) for this keypair,
// stripping the private "d" field.
func (k PrivateJWK) PublicKey() protocol.Key {
	return protocol.Key{
		Kid: k.Kid,
		Kty: k.Kty,
		Crv: k.Crv,
		X:   k.X,
	}
}

// LoadPrivateJWK reads a PrivateJWK from a JSON file.
func LoadPrivateJWK(path string) (PrivateJWK, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return PrivateJWK{}, fmt.Errorf("load private jwk: %w", err)
	}
	var k PrivateJWK
	if err := json.Unmarshal(raw, &k); err != nil {
		return PrivateJWK{}, fmt.Errorf("load private jwk: parse: %w", err)
	}
	return k, nil
}

// SavePrivateJWK writes k to path as JSON, mode 0o600 (private key material).
func SavePrivateJWK(path string, k PrivateJWK) error {
	raw, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return fmt.Errorf("save private jwk: %w", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("save private jwk: %w", err)
	}
	return nil
}
