package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// Key is an RFC 7517 JWK, per both schemas' `keys[]`/`publisher.key` shape
// (additionalProperties: true — only kid+kty are required). Only the
// OKP/Ed25519 shape (kid, kty="OKP", crv="Ed25519", x) is understood by
// this crawler for actually verifying signatures; other kty values parse
// fine but Ed25519PublicKey rejects them.
type Key struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// Ed25519PublicKey decodes the key's "x" coordinate as a raw Ed25519 public
// key, per RFC 8037. It errors if this key isn't an OKP/Ed25519 key at all,
// or if "x" isn't validly base64url-encoded 32 bytes.
func (k Key) Ed25519PublicKey() (ed25519.PublicKey, error) {
	if k.Kty != "OKP" || k.Crv != "Ed25519" {
		return nil, fmt.Errorf("key %q: not an OKP/Ed25519 key (kty=%q, crv=%q)", k.Kid, k.Kty, k.Crv)
	}
	raw, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("key %q: decode x: %w", k.Kid, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("key %q: x decodes to %d bytes, want %d", k.Kid, len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}
