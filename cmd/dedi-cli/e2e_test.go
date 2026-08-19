package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEndToEnd_KeygenSignVerify drives keygen -> sign -> verify entirely
// through the CLI layer (not the internal packages directly) for both
// document kinds dedi-cli understands.
func TestEndToEnd_KeygenSignVerify(t *testing.T) {
	tests := []struct {
		name     string
		unsigned []byte
	}{
		{"manifest", unsignedManifestJSON()},
		{"dedi file", unsignedDeDiFileJSON()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			keyPath := filepath.Join(dir, "key.json")
			unsignedPath := filepath.Join(dir, "unsigned.json")
			signedPath := filepath.Join(dir, "signed.json")

			if _, err := runCLI(t, "keygen", "--kid", "key-1", "--out", keyPath); err != nil {
				t.Fatalf("keygen error = %v", err)
			}

			if err := os.WriteFile(unsignedPath, tt.unsigned, 0o644); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}

			signOutput, err := runCLI(t, "sign", "--key", keyPath, "--in", unsignedPath, "--out", signedPath)
			if err != nil {
				t.Fatalf("sign error = %v (output: %s)", err, signOutput)
			}
			if !strings.Contains(signOutput, tt.name) {
				t.Errorf("sign output = %q, want it to mention %q", signOutput, tt.name)
			}

			verifyOutput, err := runCLI(t, "verify", "--in", signedPath)
			if err != nil {
				t.Fatalf("verify error = %v (output: %s)", err, verifyOutput)
			}
			if !strings.Contains(verifyOutput, "OK") {
				t.Errorf("verify output = %q, want OK", verifyOutput)
			}
		})
	}
}
