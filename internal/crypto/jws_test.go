package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func generateTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	return pub, priv
}

func TestSignVerify_RoundTrip(t *testing.T) {
	pub, priv := generateTestKey(t)
	payload := []byte(`{"a":2,"b":1}`)

	jwsStr, err := Sign(priv, payload)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if err := Verify(pub, payload, jwsStr); err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
}

func TestSign_ProducesDetachedCompactForm(t *testing.T) {
	_, priv := generateTestKey(t)
	jwsStr, err := Sign(priv, []byte(`{}`))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	parts := strings.Split(jwsStr, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 segments, got %d: %q", len(parts), jwsStr)
	}
	if parts[1] != "" {
		t.Errorf("expected empty (detached) payload segment, got %q", parts[1])
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var h jwsHeader
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if h.Alg != "EdDSA" {
		t.Errorf("Alg = %q, want EdDSA", h.Alg)
	}
	if h.B64 == nil || *h.B64 {
		t.Error("expected b64:false")
	}
	if len(h.Crit) != 1 || h.Crit[0] != "b64" {
		t.Errorf("Crit = %v, want [\"b64\"]", h.Crit)
	}
}

func TestVerify_TamperedPayload(t *testing.T) {
	pub, priv := generateTestKey(t)
	payload := []byte(`{"a":2,"b":1}`)

	jwsStr, err := Sign(priv, payload)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	tampered := []byte(`{"a":2,"b":2}`)
	if err := Verify(pub, tampered, jwsStr); err == nil {
		t.Fatal("expected Verify() to fail for tampered payload")
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	pub, priv := generateTestKey(t)
	payload := []byte(`{"a":2}`)

	jwsStr, err := Sign(priv, payload)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	parts := strings.Split(jwsStr, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	sig[0] ^= 0xFF // flip bits in the first byte
	tamperedJWS := parts[0] + ".." + base64.RawURLEncoding.EncodeToString(sig)

	if err := Verify(pub, payload, tamperedJWS); err == nil {
		t.Fatal("expected Verify() to fail for tampered signature")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	_, priv := generateTestKey(t)
	otherPub, _ := generateTestKey(t)
	payload := []byte(`{"a":2}`)

	jwsStr, err := Sign(priv, payload)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if err := Verify(otherPub, payload, jwsStr); err == nil {
		t.Fatal("expected Verify() to fail when verifying against the wrong public key")
	}
}

func TestVerify_MalformedCompactString(t *testing.T) {
	pub, _ := generateTestKey(t)
	cases := []struct {
		name string
		jws  string
	}{
		{"too few segments", "onlyonepart"},
		{"too many segments", "a.b.c.d"},
		{"non-empty payload segment", fixedHeaderB64 + ".not-empty.sig"},
		{"garbage header base64", "!!!not-base64!!!.." + base64.RawURLEncoding.EncodeToString([]byte("sig"))},
		{"garbage signature base64", fixedHeaderB64 + "..!!!not-base64!!!"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Verify(pub, []byte(`{}`), tc.jws); err == nil {
				t.Errorf("expected Verify() to reject %q", tc.jws)
			}
		})
	}
}

func TestVerify_RejectsWrongHeaderProfile(t *testing.T) {
	pub, priv := generateTestKey(t)
	payload := []byte(`{}`)

	makeJWS := func(header map[string]interface{}) string {
		t.Helper()
		headerBytes, err := json.Marshal(header)
		if err != nil {
			t.Fatalf("marshal header: %v", err)
		}
		headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)
		signingInput := append([]byte(headerB64+"."), payload...)
		sig := ed25519.Sign(priv, signingInput)
		return headerB64 + ".." + base64.RawURLEncoding.EncodeToString(sig)
	}

	cases := []struct {
		name   string
		header map[string]interface{}
	}{
		{"wrong alg", map[string]interface{}{"alg": "RS256", "b64": false, "crit": []string{"b64"}}},
		{"b64 true", map[string]interface{}{"alg": "EdDSA", "b64": true, "crit": []string{"b64"}}},
		{"b64 missing", map[string]interface{}{"alg": "EdDSA", "crit": []string{"b64"}}},
		{"crit missing b64", map[string]interface{}{"alg": "EdDSA", "b64": false, "crit": []string{}}},
		{"crit has extra entries", map[string]interface{}{"alg": "EdDSA", "b64": false, "crit": []string{"b64", "other"}}},
		{"unknown field", map[string]interface{}{"alg": "EdDSA", "b64": false, "crit": []string{"b64"}, "extra": "nope"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jwsStr := makeJWS(tc.header)
			if err := Verify(pub, payload, jwsStr); err == nil {
				t.Errorf("expected Verify() to reject header %+v", tc.header)
			}
		})
	}
}

func TestSign_InvalidKeySize(t *testing.T) {
	_, err := Sign(ed25519.PrivateKey([]byte("too-short")), []byte("{}"))
	if err == nil {
		t.Fatal("expected error for invalid private key size, got nil (must not panic)")
	}
}

func TestVerify_InvalidKeySize(t *testing.T) {
	err := Verify(ed25519.PublicKey([]byte("too-short")), []byte("{}"), fixedHeaderB64+"..sig")
	if err == nil {
		t.Fatal("expected error for invalid public key size, got nil (must not panic)")
	}
}
