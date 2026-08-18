package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// jwsHeader is the DeDi protocol's one fixed JOSE header shape:
// {"alg":"EdDSA","b64":false,"crit":["b64"]} — RFC 7797's "unencoded
// payload option," always used with a detached payload. No other alg or
// profile is supported; there is no `alg` parameter to Sign/Verify because
// of it — the algorithm is fixed by the function signature itself, which
// rules out algorithm-confusion bugs by construction.
type jwsHeader struct {
	Alg  string   `json:"alg"`
	B64  *bool    `json:"b64"`
	Crit []string `json:"crit"`
}

var fixedHeaderB64 = base64.RawURLEncoding.EncodeToString(mustMarshalFixedHeader())

func mustMarshalFixedHeader() []byte {
	f := false
	b, err := json.Marshal(jwsHeader{Alg: "EdDSA", B64: &f, Crit: []string{"b64"}})
	if err != nil {
		panic(err) // unreachable: fixed literal struct
	}
	return b
}

// Sign produces "BASE64URL(header)..BASE64URL(sig)" over payload (bytes
// this file treats as opaque — no JSON/canonicalization knowledge needed
// here beyond what canon.go already produced) using priv.
func Sign(priv ed25519.PrivateKey, payload []byte) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("sign: invalid private key size %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	signingInput := append([]byte(fixedHeaderB64+"."), payload...)
	sig := ed25519.Sign(priv, signingInput)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return fixedHeaderB64 + ".." + sigB64, nil
}

// Verify checks jwsStr is a validly-formed detached JWS over payload, under
// this exact fixed profile, signed by the key matching pub.
func Verify(pub ed25519.PublicKey, payload []byte, jwsStr string) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("verify: invalid public key size %d, want %d", len(pub), ed25519.PublicKeySize)
	}

	parts := strings.Split(jwsStr, ".")
	if len(parts) != 3 {
		return fmt.Errorf("verify: malformed compact JWS: expected 3 segments, got %d", len(parts))
	}
	headerB64, payloadSeg, sigB64 := parts[0], parts[1], parts[2]
	if payloadSeg != "" {
		return errors.New("verify: expected a detached JWS (empty payload segment), got a non-empty one")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return fmt.Errorf("verify: decode header: %w", err)
	}
	if err := validateHeader(headerBytes); err != nil {
		return err
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("verify: decode signature: %w", err)
	}

	signingInput := append([]byte(headerB64+"."), payload...)
	if !ed25519.Verify(pub, signingInput, sig) {
		return errors.New("verify: signature does not match payload (wrong key, or the document was modified after signing)")
	}
	return nil
}

func validateHeader(headerBytes []byte) error {
	dec := json.NewDecoder(bytes.NewReader(headerBytes))
	dec.DisallowUnknownFields()
	var h jwsHeader
	if err := dec.Decode(&h); err != nil {
		return fmt.Errorf("verify: decode header JSON: %w", err)
	}
	if h.Alg != "EdDSA" {
		return fmt.Errorf("verify: unsupported alg %q, want EdDSA", h.Alg)
	}
	if h.B64 == nil || *h.B64 {
		return errors.New("verify: header must set b64:false")
	}
	if len(h.Crit) != 1 || h.Crit[0] != "b64" {
		return fmt.Errorf(`verify: header crit must be exactly ["b64"], got %v`, h.Crit)
	}
	return nil
}
