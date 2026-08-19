package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nfh-trust-labs/dedi-cli/internal/sign"
)

func TestKeygen_RequiredFlags(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "key.json")

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"missing --kid", []string{"keygen", "--out", out}, "--kid is required"},
		{"missing --out", []string{"keygen", "--kid", "k1"}, "--out is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := runCLI(t, tt.args...)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestKeygen_WritesLoadableKey(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "key.json")

	output, err := runCLI(t, "keygen", "--kid", "my-key-1", "--out", out)
	if err != nil {
		t.Fatalf("keygen error = %v (output: %s)", err, output)
	}
	if !strings.Contains(output, out) {
		t.Errorf("output = %q, want it to mention the written path %q", output, out)
	}

	k, err := sign.LoadPrivateJWK(out)
	if err != nil {
		t.Fatalf("LoadPrivateJWK() error = %v", err)
	}
	if k.Kid != "my-key-1" {
		t.Errorf("Kid = %q, want %q", k.Kid, "my-key-1")
	}
	if _, err := k.PrivateKey(); err != nil {
		t.Errorf("generated key does not decode as a valid Ed25519 private key: %v", err)
	}
}

func TestKeygen_RefusesToOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "key.json")

	if _, err := runCLI(t, "keygen", "--kid", "k1", "--out", out); err != nil {
		t.Fatalf("first keygen error = %v", err)
	}
	first, err := sign.LoadPrivateJWK(out)
	if err != nil {
		t.Fatalf("LoadPrivateJWK() error = %v", err)
	}

	if _, err := runCLI(t, "keygen", "--kid", "k1", "--out", out); err == nil {
		t.Fatal("second keygen without --force: want error, got nil")
	} else if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("err = %v, want it to mention the file already existing", err)
	}

	unchanged, err := sign.LoadPrivateJWK(out)
	if err != nil {
		t.Fatalf("LoadPrivateJWK() error = %v", err)
	}
	if unchanged.D != first.D {
		t.Error("key file was modified despite missing --force")
	}

	if _, err := runCLI(t, "keygen", "--kid", "k1", "--out", out, "--force"); err != nil {
		t.Fatalf("keygen --force error = %v", err)
	}
	second, err := sign.LoadPrivateJWK(out)
	if err != nil {
		t.Fatalf("LoadPrivateJWK() error = %v", err)
	}
	if second.D == first.D {
		t.Error("keygen --force did not generate a new key")
	}
}

func TestKeygen_CheckOutError(t *testing.T) {
	// A path component that's a regular file (not a directory) makes
	// os.Stat fail with something other than IsNotExist — exercises the
	// "check %s: %w" branch distinct from "doesn't exist yet".
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	out := filepath.Join(blocker, "key.json")

	if _, err := runCLI(t, "keygen", "--kid", "k1", "--out", out); err == nil {
		t.Fatal("want error when --out's parent isn't a directory, got nil")
	}
}
