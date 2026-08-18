package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestKey_UnmarshalRoundTrip(t *testing.T) {
	raw := []byte(`{"kid":"key-1","kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`)

	var k Key
	if err := json.Unmarshal(raw, &k); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if k.Kid != "key-1" || k.Kty != "OKP" || k.Crv != "Ed25519" {
		t.Errorf("unexpected fields: %+v", k)
	}

	out, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var roundTripped Key
	if err := json.Unmarshal(out, &roundTripped); err != nil {
		t.Fatalf("re-Unmarshal() error = %v", err)
	}
	if roundTripped != k {
		t.Errorf("round trip mismatch: got %+v, want %+v", roundTripped, k)
	}
}

func TestKey_Ed25519PublicKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	k := Key{
		Kid: "test",
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}

	got, err := k.Ed25519PublicKey()
	if err != nil {
		t.Fatalf("Ed25519PublicKey() error = %v", err)
	}
	if !got.Equal(pub) {
		t.Error("decoded public key does not match the original")
	}
}

func TestKey_Ed25519PublicKey_Errors(t *testing.T) {
	cases := []struct {
		name string
		key  Key
	}{
		{"wrong kty", Key{Kid: "k", Kty: "RSA", Crv: "Ed25519", X: "AAAA"}},
		{"wrong crv", Key{Kid: "k", Kty: "OKP", Crv: "P-256", X: "AAAA"}},
		{"malformed base64", Key{Kid: "k", Kty: "OKP", Crv: "Ed25519", X: "not-valid-base64!!!"}},
		{"wrong length", Key{Kid: "k", Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString([]byte("tooshort"))}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.key.Ed25519PublicKey(); err == nil {
				t.Errorf("expected error for %+v", tc.key)
			}
		})
	}
}
