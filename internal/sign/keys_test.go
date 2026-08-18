package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	k, err := GenerateKey("test-1")
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if k.Kid != "test-1" {
		t.Errorf("Kid = %q", k.Kid)
	}
	if k.Kty != "OKP" || k.Crv != "Ed25519" {
		t.Errorf("Kty/Crv = %q/%q", k.Kty, k.Crv)
	}
	if k.X == "" || k.D == "" {
		t.Error("expected both X and D to be populated")
	}
}

func TestPrivateJWK_PrivateKeyRoundTrip(t *testing.T) {
	k, err := GenerateKey("test-1")
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	priv, err := k.PrivateKey()
	if err != nil {
		t.Fatalf("PrivateKey() error = %v", err)
	}

	wantPub, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		t.Fatalf("decode X: %v", err)
	}
	gotPub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("priv.Public() returned %T, want ed25519.PublicKey", priv.Public())
	}
	if !gotPub.Equal(ed25519.PublicKey(wantPub)) {
		t.Error("public key derived from PrivateKey() does not match X")
	}
}

func TestPrivateJWK_PrivateKey_RejectsMismatchedX(t *testing.T) {
	k, err := GenerateKey("test-1")
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	other, err := GenerateKey("test-2")
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	k.X = other.X // corrupt: d no longer matches x

	if _, err := k.PrivateKey(); err == nil {
		t.Fatal("expected error for mismatched x/d")
	}
}

func TestPrivateJWK_PrivateKey_InvalidSeed(t *testing.T) {
	cases := []struct {
		name string
		k    PrivateJWK
	}{
		{"wrong kty", PrivateJWK{Kid: "k", Kty: "RSA", Crv: "Ed25519", X: "AAAA", D: "AAAA"}},
		{"malformed base64", PrivateJWK{Kid: "k", Kty: "OKP", Crv: "Ed25519", X: "AAAA", D: "not-valid-base64!!!"}},
		{"wrong seed length", PrivateJWK{Kid: "k", Kty: "OKP", Crv: "Ed25519", X: "AAAA", D: base64.RawURLEncoding.EncodeToString([]byte("short"))}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.k.PrivateKey(); err == nil {
				t.Errorf("expected error for %+v", tc.k)
			}
		})
	}
}

func TestPrivateJWK_PublicKey_StripsD(t *testing.T) {
	k, err := GenerateKey("test-1")
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	pub := k.PublicKey()
	if pub.Kid != k.Kid || pub.Kty != k.Kty || pub.Crv != k.Crv || pub.X != k.X {
		t.Errorf("PublicKey() = %+v, want fields matching %+v", pub, k)
	}
	if _, err := pub.Ed25519PublicKey(); err != nil {
		t.Errorf("resulting protocol.Key should decode as a valid Ed25519 public key: %v", err)
	}
}

func TestSaveLoadPrivateJWK_RoundTrip(t *testing.T) {
	k, err := GenerateKey("test-1")
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	path := filepath.Join(t.TempDir(), "key.json")
	if err := SavePrivateJWK(path, k); err != nil {
		t.Fatalf("SavePrivateJWK() error = %v", err)
	}

	loaded, err := LoadPrivateJWK(path)
	if err != nil {
		t.Fatalf("LoadPrivateJWK() error = %v", err)
	}
	if loaded != k {
		t.Errorf("round trip mismatch: got %+v, want %+v", loaded, k)
	}
}

func TestSavePrivateJWK_FileMode(t *testing.T) {
	k, err := GenerateKey("test-1")
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "key.json")
	if err := SavePrivateJWK(path, k); err != nil {
		t.Fatalf("SavePrivateJWK() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %o, want 0600", perm)
	}
}

func TestLoadPrivateJWK_MissingFile(t *testing.T) {
	if _, err := LoadPrivateJWK(filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Fatal("expected error for missing file")
	}
}
