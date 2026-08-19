package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nfh-trust-labs/dedi-cli/internal/sign"
)

func TestVerify_RequiredFlags(t *testing.T) {
	_, err := runCLI(t, "verify")
	if err == nil || !strings.Contains(err.Error(), "--in is required") {
		t.Errorf("err = %v, want required-flags error", err)
	}
}

func TestVerify_MissingInputFile(t *testing.T) {
	_, err := runCLI(t, "verify", "--in", filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil || !strings.Contains(err.Error(), "read input") {
		t.Errorf("err = %v, want a read-input error", err)
	}
}

// signManifestFixture is a small helper shared by verify tests: it signs
// unsignedManifestJSON() with a fresh key and writes the result to dir/name,
// returning the path and the path to the public JWK matching that key.
func signManifestFixture(t *testing.T, dir, name string) (signedPath, keyPath string) {
	t.Helper()
	keyPath = generateKeyFile(t, dir, "key-1")
	in := filepath.Join(dir, "unsigned-"+name)
	if err := os.WriteFile(in, unsignedManifestJSON(), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	signedPath = filepath.Join(dir, name)
	if _, err := runCLI(t, "sign", "--key", keyPath, "--in", in, "--out", signedPath); err != nil {
		t.Fatalf("sign error = %v", err)
	}
	return signedPath, keyPath
}

func TestVerify_EmbeddedKey(t *testing.T) {
	dir := t.TempDir()
	signedPath, _ := signManifestFixture(t, dir, "signed.json")

	output, err := runCLI(t, "verify", "--in", signedPath)
	if err != nil {
		t.Fatalf("verify error = %v (output: %s)", err, output)
	}
	if !strings.Contains(output, "OK") {
		t.Errorf("output = %q, want OK", output)
	}
	if !strings.Contains(output, "note:") {
		t.Errorf("output = %q, want a note about trusting the embedded key", output)
	}
}

func TestVerify_TrustedKey(t *testing.T) {
	dir := t.TempDir()
	signedPath, keyPath := signManifestFixture(t, dir, "signed.json")

	priv, err := sign.LoadPrivateJWK(keyPath)
	if err != nil {
		t.Fatalf("LoadPrivateJWK() error = %v", err)
	}
	pubPath := filepath.Join(dir, "pub.json")
	pubJSON, err := json.Marshal(priv.PublicKey())
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := os.WriteFile(pubPath, pubJSON, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	output, err := runCLI(t, "verify", "--in", signedPath, "--key", pubPath)
	if err != nil {
		t.Fatalf("verify --key error = %v (output: %s)", err, output)
	}
	if strings.Contains(output, "note:") {
		t.Errorf("output = %q, should not carry the untrusted-key note when --key is passed", output)
	}
}

func TestVerify_WrongTrustedKeyFails(t *testing.T) {
	dir := t.TempDir()
	signedPath, _ := signManifestFixture(t, dir, "signed.json")

	otherKeyPath := generateKeyFile(t, dir, "key-2")
	other, err := sign.LoadPrivateJWK(otherKeyPath)
	if err != nil {
		t.Fatalf("LoadPrivateJWK() error = %v", err)
	}
	pubPath := filepath.Join(dir, "wrong-pub.json")
	pubJSON, err := json.Marshal(other.PublicKey())
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := os.WriteFile(pubPath, pubJSON, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err = runCLI(t, "verify", "--in", signedPath, "--key", pubPath)
	if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("err = %v, want a signature verification failure", err)
	}
}

func TestVerify_TamperedDocumentFails(t *testing.T) {
	dir := t.TempDir()
	signedPath, _ := signManifestFixture(t, dir, "signed.json")

	raw, err := os.ReadFile(signedPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	tampered := strings.Replace(string(raw), "example.org", "evil.example", 1)
	if tampered == string(raw) {
		t.Fatal("tamper replacement did not change anything")
	}
	if err := os.WriteFile(signedPath, []byte(tampered), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err = runCLI(t, "verify", "--in", signedPath)
	if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("err = %v, want a signature verification failure after tampering", err)
	}
}

func TestVerify_UnknownVerificationMethodFails(t *testing.T) {
	dir := t.TempDir()
	signedPath, _ := signManifestFixture(t, dir, "signed.json")

	raw, err := os.ReadFile(signedPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	tampered := strings.Replace(string(raw), `"verification_method": "key-1"`, `"verification_method": "no-such-key"`, 1)
	if tampered == string(raw) {
		t.Fatal("tamper replacement did not change anything — check the expected proof formatting")
	}
	if err := os.WriteFile(signedPath, []byte(tampered), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err = runCLI(t, "verify", "--in", signedPath)
	if err == nil || !strings.Contains(err.Error(), "not found in manifest keys") {
		t.Errorf("err = %v, want an unresolvable verification_method error", err)
	}
}
