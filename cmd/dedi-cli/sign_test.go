package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nfh-trust-labs/dedi-cli/internal/protocol"
	"github.com/nfh-trust-labs/dedi-cli/internal/validate"
)

func TestDetectDocumentKind(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    documentKind
		wantErr bool
	}{
		{"manifest shape", `{"domain":"example.org"}`, documentKindManifest, false},
		{"dedi file shape", `{"publisher":{"domain":"example.org"}}`, documentKindDeDiFile, false},
		{"both domain and publisher", `{"domain":"example.org","publisher":{}}`, "", true},
		{"neither domain nor publisher", `{"dedi_version":"0.1"}`, "", true},
		{"malformed json", `not json`, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := detectDocumentKind([]byte(tt.raw))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("detectDocumentKind() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("detectDocumentKind() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("detectDocumentKind() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectDocumentKind_MalformedJSONIncludesLocation(t *testing.T) {
	_, err := detectDocumentKind([]byte("{\n  not json\n}"))
	if err == nil {
		t.Fatal("detectDocumentKind() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "line 2, column") {
		t.Errorf("detectDocumentKind() error = %q, want it to mention line 2", err.Error())
	}
}

func TestDetectDocumentKind_BothAndNeitherHaveDistinctMessages(t *testing.T) {
	_, bothErr := detectDocumentKind([]byte(`{"domain":"example.org","publisher":{}}`))
	if bothErr == nil || !strings.Contains(bothErr.Error(), "has both") {
		t.Errorf("both err = %v, want it to say \"has both\"", bothErr)
	}

	_, neitherErr := detectDocumentKind([]byte(`{"dedi_version":"0.1"}`))
	if neitherErr == nil || !strings.Contains(neitherErr.Error(), "has neither") {
		t.Errorf("neither err = %v, want it to say \"has neither\"", neitherErr)
	}

	for _, err := range []error{bothErr, neitherErr} {
		if !strings.Contains(err.Error(), "dedi-manifest.schema.json") || !strings.Contains(err.Error(), "dedi-file.schema.json") {
			t.Errorf("err = %v, want it to link both schema files", err)
		}
	}
}

func TestSign_RequiredFlags(t *testing.T) {
	_, err := runCLI(t, "sign", "--key", "k.json")
	if err == nil || !strings.Contains(err.Error(), "--key, --in, and --out are all required") {
		t.Errorf("err = %v, want required-flags error", err)
	}
}

func TestSign_InvalidKeyPath(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.json")
	if err := os.WriteFile(in, unsignedManifestJSON(), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := runCLI(t, "sign", "--key", filepath.Join(dir, "missing.json"), "--in", in, "--out", filepath.Join(dir, "out.json"))
	if err == nil || !strings.Contains(err.Error(), "load key") {
		t.Errorf("err = %v, want it to mention loading the key", err)
	}
}

func TestSign_Manifest(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateKeyFile(t, dir, "key-1")
	in := filepath.Join(dir, "in.json")
	out := filepath.Join(dir, "out.json")
	if err := os.WriteFile(in, unsignedManifestJSON(), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	output, err := runCLI(t, "sign", "--key", keyPath, "--in", in, "--out", out)
	if err != nil {
		t.Fatalf("sign error = %v (output: %s)", err, output)
	}
	if !strings.Contains(output, "manifest") {
		t.Errorf("output = %q, want it to mention the detected document kind", output)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	m, err := protocol.ParseManifest(raw)
	if err != nil {
		t.Fatalf("ParseManifest() error = %v", err)
	}
	if m.Proof.JWS == "" {
		t.Error("signed manifest has no proof.jws")
	}
	if len(m.Keys) != 1 || m.Keys[0].Kid != "key-1" {
		t.Errorf("Keys = %+v, want exactly key-1 added", m.Keys)
	}
}

func TestSign_DeDiFile_SchemaValidation(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateKeyFile(t, dir, "key-1")

	inlineSchema := `{"type":"object","required":["anchor_id"],"properties":{"anchor_id":{"type":"string"}}}`
	validRecords := `[{"record_name":"r1","details":{"anchor_id":"example.org:r1"}}]`
	invalidRecords := `[{"record_name":"r1","details":{"missing_anchor_id":true}}]`

	t.Run("valid record passes", func(t *testing.T) {
		in := filepath.Join(dir, "valid-in.json")
		out := filepath.Join(dir, "valid-out.json")
		if err := os.WriteFile(in, unsignedDeDiFileWithSchemaJSON(inlineSchema, validRecords), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		if _, err := runCLI(t, "sign", "--key", keyPath, "--in", in, "--out", out); err != nil {
			t.Fatalf("sign error = %v", err)
		}
	})

	t.Run("invalid record fails without --skip-validation", func(t *testing.T) {
		in := filepath.Join(dir, "invalid-in.json")
		out := filepath.Join(dir, "invalid-out.json")
		if err := os.WriteFile(in, unsignedDeDiFileWithSchemaJSON(inlineSchema, invalidRecords), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		_, err := runCLI(t, "sign", "--key", keyPath, "--in", in, "--out", out)
		if err == nil || !strings.Contains(err.Error(), "schema validation failed") {
			t.Errorf("err = %v, want schema validation failure", err)
		}
		if _, statErr := os.Stat(out); statErr == nil {
			t.Error("--out was written despite validation failure")
		}
	})

	t.Run("invalid record passes with --skip-validation", func(t *testing.T) {
		in := filepath.Join(dir, "skip-in.json")
		out := filepath.Join(dir, "skip-out.json")
		if err := os.WriteFile(in, unsignedDeDiFileWithSchemaJSON(inlineSchema, invalidRecords), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		if _, err := runCLI(t, "sign", "--key", keyPath, "--in", in, "--out", out, "--skip-validation"); err != nil {
			t.Fatalf("sign --skip-validation error = %v", err)
		}
	})
}

// withBecknSubscriberSchemaURL points validate.BecknSubscriberSchemaURL at
// url for the duration of the test, restoring it afterward — so a test can
// make sign treat a local httptest.Server as "the" beckn_subscriber schema
// without validateBeforeSigning's schema-fetch step ever touching the real
// network.
func withBecknSubscriberSchemaURL(t *testing.T, url string) {
	t.Helper()
	original := validate.BecknSubscriberSchemaURL
	validate.BecknSubscriberSchemaURL = url
	t.Cleanup(func() { validate.BecknSubscriberSchemaURL = original })
}

func TestSign_DeDiFile_SubscriberIDValidation(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateKeyFile(t, dir, "key-1")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"type":"object","required":["subscriber_id"]}`))
	}))
	defer srv.Close()
	withBecknSubscriberSchemaURL(t, srv.URL)

	subscriberSchemaRef := fmt.Sprintf("%q", srv.URL)
	// unsignedDeDiFileWithSchemaJSON's fixture always sets publisher.domain
	// to "example.org".
	matchingRecords := `[{"record_name":"r1","details":{"subscriber_id":"bap.example.org"}}]`
	mismatchedRecords := `[{"record_name":"r1","details":{"subscriber_id":"evil.com"}}]`

	t.Run("matching subscriber_id passes", func(t *testing.T) {
		in := filepath.Join(dir, "matching-in.json")
		out := filepath.Join(dir, "matching-out.json")
		if err := os.WriteFile(in, unsignedDeDiFileWithSchemaJSON(subscriberSchemaRef, matchingRecords), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		if _, err := runCLI(t, "sign", "--key", keyPath, "--in", in, "--out", out); err != nil {
			t.Fatalf("sign error = %v", err)
		}
	})

	t.Run("mismatched subscriber_id fails without --skip-validation", func(t *testing.T) {
		in := filepath.Join(dir, "mismatched-in.json")
		out := filepath.Join(dir, "mismatched-out.json")
		if err := os.WriteFile(in, unsignedDeDiFileWithSchemaJSON(subscriberSchemaRef, mismatchedRecords), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		_, err := runCLI(t, "sign", "--key", keyPath, "--in", in, "--out", out)
		if err == nil || !strings.Contains(err.Error(), "subscriber_id validation failed") {
			t.Errorf("err = %v, want subscriber_id validation failure", err)
		}
		if _, statErr := os.Stat(out); statErr == nil {
			t.Error("--out was written despite validation failure")
		}
	})

	t.Run("mismatched subscriber_id passes with --skip-validation", func(t *testing.T) {
		in := filepath.Join(dir, "mismatched-skip-in.json")
		out := filepath.Join(dir, "mismatched-skip-out.json")
		if err := os.WriteFile(in, unsignedDeDiFileWithSchemaJSON(subscriberSchemaRef, mismatchedRecords), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		if _, err := runCLI(t, "sign", "--key", keyPath, "--in", in, "--out", out, "--skip-validation"); err != nil {
			t.Fatalf("sign --skip-validation error = %v", err)
		}
	})
}

// dediFileWithNextUpdate is like unsignedDeDiFileJSON but with next_update
// set to nextUpdate, for tests exercising the past-next_update warning.
func dediFileWithNextUpdate(nextUpdate string) []byte {
	return []byte(fmt.Sprintf(`{
		"dedi_version": "0.1",
		"type": "dedi-file",
		"source_url": "https://example.org/.well-known/dedi.index.json",
		"next_update": %q,
		"publisher": {"domain": "example.org"},
		"namespace": "example.org",
		"registry": {
			"name": "trust-anchors",
			"schema": {"type":"object","required":["anchor_id"],"properties":{"anchor_id":{"type":"string"}}},
			"state": "live",
			"updated_at": "2026-07-01T09:00:00Z"
		},
		"records": [
			{"record_name": "lfdt-root", "details": {"anchor_id": "example.org:lfdt-root"}}
		]
	}`, nextUpdate))
}

// manifestWithNextUpdate is like unsignedManifestJSON but with next_update
// set to nextUpdate.
func manifestWithNextUpdate(nextUpdate string) []byte {
	return []byte(fmt.Sprintf(`{
		"dedi_version": "0.1",
		"domain": "example.org",
		"keys": [],
		"updated_at": "2026-07-01T09:00:00Z",
		"next_update": %q,
		"files": []
	}`, nextUpdate))
}

func TestSign_DeDiFile_PastNextUpdate_FailsWithoutForce(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateKeyFile(t, dir, "key-1")
	in := filepath.Join(dir, "in.json")
	out := filepath.Join(dir, "out.json")
	if err := os.WriteFile(in, dediFileWithNextUpdate("2020-01-01T00:00:00Z"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := runCLI(t, "sign", "--key", keyPath, "--in", in, "--out", out)
	if err == nil || !strings.Contains(err.Error(), "in the past") || !strings.Contains(err.Error(), "--force") {
		t.Errorf("err = %v, want a past-next_update error mentioning --force", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("--out was written despite next_update being in the past")
	}
}

func TestSign_DeDiFile_PastNextUpdate_SucceedsWithForce(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateKeyFile(t, dir, "key-1")
	in := filepath.Join(dir, "in.json")
	out := filepath.Join(dir, "out.json")
	if err := os.WriteFile(in, dediFileWithNextUpdate("2020-01-01T00:00:00Z"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	output, err := runCLI(t, "sign", "--key", keyPath, "--in", in, "--out", out, "--force")
	if err != nil {
		t.Fatalf("sign --force error = %v", err)
	}
	if !strings.Contains(output, "warning:") || !strings.Contains(output, "in the past") {
		t.Errorf("output = %q, want a past-next_update warning", output)
	}
	if _, statErr := os.Stat(out); statErr != nil {
		t.Errorf("--out was not written despite --force: %v", statErr)
	}
}

func TestSign_DeDiFile_NextUpdateExpiringSoon_Warns(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateKeyFile(t, dir, "key-1")
	in := filepath.Join(dir, "in.json")
	out := filepath.Join(dir, "out.json")
	soon := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)
	if err := os.WriteFile(in, dediFileWithNextUpdate(soon), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	output, err := runCLI(t, "sign", "--key", keyPath, "--in", in, "--out", out)
	if err != nil {
		t.Fatalf("sign error = %v", err)
	}
	if !strings.Contains(output, "warning:") || !strings.Contains(output, "refreshed again soon") {
		t.Errorf("output = %q, want an expiring-soon warning", output)
	}
	if _, statErr := os.Stat(out); statErr != nil {
		t.Errorf("--out was not written despite next_update only being a warning: %v", statErr)
	}
}

func TestSign_DeDiFile_FutureNextUpdate_NoWarning(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateKeyFile(t, dir, "key-1")
	in := filepath.Join(dir, "in.json")
	out := filepath.Join(dir, "out.json")
	if err := os.WriteFile(in, dediFileWithNextUpdate("2099-01-01T00:00:00Z"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	output, err := runCLI(t, "sign", "--key", keyPath, "--in", in, "--out", out)
	if err != nil {
		t.Fatalf("sign error = %v", err)
	}
	if strings.Contains(output, "warning:") {
		t.Errorf("output = %q, want no next_update warning for a comfortably future date", output)
	}
}

func TestSign_Manifest_PastNextUpdate_FailsWithoutForce(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateKeyFile(t, dir, "key-1")
	in := filepath.Join(dir, "in.json")
	out := filepath.Join(dir, "out.json")
	if err := os.WriteFile(in, manifestWithNextUpdate("2020-01-01T00:00:00Z"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := runCLI(t, "sign", "--key", keyPath, "--in", in, "--out", out)
	if err == nil || !strings.Contains(err.Error(), "in the past") || !strings.Contains(err.Error(), "--force") {
		t.Errorf("err = %v, want a past-next_update error mentioning --force", err)
	}
}

func TestSign_Manifest_PastNextUpdate_SucceedsWithForce(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateKeyFile(t, dir, "key-1")
	in := filepath.Join(dir, "in.json")
	out := filepath.Join(dir, "out.json")
	if err := os.WriteFile(in, manifestWithNextUpdate("2020-01-01T00:00:00Z"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	output, err := runCLI(t, "sign", "--key", keyPath, "--in", in, "--out", out, "--force")
	if err != nil {
		t.Fatalf("sign --force error = %v", err)
	}
	if !strings.Contains(output, "warning:") || !strings.Contains(output, "in the past") {
		t.Errorf("output = %q, want a past-next_update warning", output)
	}
}

func TestSign_DeDiFile_URLSchema(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateKeyFile(t, dir, "key-1")
	validRecords := `[{"record_name":"r1","details":{"anchor_id":"example.org:r1"}}]`

	t.Run("fetched schema validates records", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"type":"object","required":["anchor_id"]}`))
		}))
		defer srv.Close()

		in := filepath.Join(dir, "url-in.json")
		out := filepath.Join(dir, "url-out.json")
		schemaRef := `"` + srv.URL + `"`
		if err := os.WriteFile(in, unsignedDeDiFileWithSchemaJSON(schemaRef, validRecords), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		if _, err := runCLI(t, "sign", "--key", keyPath, "--in", in, "--out", out); err != nil {
			t.Fatalf("sign error = %v", err)
		}
	})

	t.Run("fetch failure blocks signing", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		in := filepath.Join(dir, "url-fail-in.json")
		out := filepath.Join(dir, "url-fail-out.json")
		schemaRef := `"` + srv.URL + `"`
		if err := os.WriteFile(in, unsignedDeDiFileWithSchemaJSON(schemaRef, validRecords), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		_, err := runCLI(t, "sign", "--key", keyPath, "--in", in, "--out", out)
		if err == nil || !strings.Contains(err.Error(), "fetch registry.schema") {
			t.Errorf("err = %v, want a schema-fetch failure", err)
		}
	})

	t.Run("oversized response blocks signing", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(bytes.Repeat([]byte("x"), schemaFetchMaxBytes+1))
		}))
		defer srv.Close()

		in := filepath.Join(dir, "url-oversized-in.json")
		out := filepath.Join(dir, "url-oversized-out.json")
		schemaRef := `"` + srv.URL + `"`
		if err := os.WriteFile(in, unsignedDeDiFileWithSchemaJSON(schemaRef, validRecords), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		_, err := runCLI(t, "sign", "--key", keyPath, "--in", in, "--out", out)
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Errorf("err = %v, want an over-the-limit fetch failure", err)
		}
	})

	t.Run("malformed schema URL fails to build a request", func(t *testing.T) {
		in := filepath.Join(dir, "url-malformed-in.json")
		out := filepath.Join(dir, "url-malformed-out.json")
		// A JSON-escaped control character decodes to a raw newline byte in
		// the URL string, which net/url rejects outright before any network
		// call is attempted.
		schemaRef := `"http://example.org/\n"`
		if err := os.WriteFile(in, unsignedDeDiFileWithSchemaJSON(schemaRef, validRecords), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		_, err := runCLI(t, "sign", "--key", keyPath, "--in", in, "--out", out)
		if err == nil || !strings.Contains(err.Error(), "fetch registry.schema") {
			t.Errorf("err = %v, want a schema-fetch failure", err)
		}
	})

	t.Run("--skip-validation skips the fetch entirely", func(t *testing.T) {
		in := filepath.Join(dir, "url-skip-in.json")
		out := filepath.Join(dir, "url-skip-out.json")
		// A closed local listener refuses connections immediately — if sign
		// tried to fetch this it would fail fast; success here proves
		// --skip-validation skipped the fetch (and the network call)
		// entirely, without depending on real external network reachability.
		closedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		unreachableURL := closedSrv.URL
		closedSrv.Close()

		schemaRef := `"` + unreachableURL + `"`
		if err := os.WriteFile(in, unsignedDeDiFileWithSchemaJSON(schemaRef, validRecords), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		if _, err := runCLI(t, "sign", "--key", keyPath, "--in", in, "--out", out, "--skip-validation"); err != nil {
			t.Fatalf("sign --skip-validation error = %v", err)
		}
	})
}

func TestSign_BatchMode(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateKeyFile(t, dir, "key-1")
	inDir := filepath.Join(dir, "in")
	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(inDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	if err := os.WriteFile(filepath.Join(inDir, "good.json"), unsignedManifestJSON(), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(inDir, "bad.json"), []byte(`not json`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	// A non-.json file must be ignored by the *.json glob.
	if err := os.WriteFile(filepath.Join(inDir, "ignore.txt"), []byte(`irrelevant`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	output, err := runCLI(t, "sign", "--key", keyPath, "--in", inDir, "--out", outDir)
	if err == nil {
		t.Fatal("batch sign with one bad file: want non-nil error, got nil")
	}
	if !strings.Contains(err.Error(), "1 of 2 files failed to sign") {
		t.Errorf("err = %v, want summary of failures", err)
	}
	if !strings.Contains(output, "FAILED") || !strings.Contains(output, "bad.json") {
		t.Errorf("output = %q, want a FAILED line naming bad.json", output)
	}
	if !strings.Contains(output, "1 of 2 files signed") {
		t.Errorf("output = %q, want a signed-count summary", output)
	}

	if _, statErr := os.Stat(filepath.Join(outDir, "good.json")); statErr != nil {
		t.Errorf("good.json was not signed and written: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(outDir, "bad.json")); statErr == nil {
		t.Error("bad.json should not have produced output")
	}
	if _, statErr := os.Stat(filepath.Join(outDir, "ignore.txt")); statErr == nil {
		t.Error("non-.json file should have been ignored, not copied to --out")
	}
}

func TestSign_BatchMode_AllSucceed(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateKeyFile(t, dir, "key-1")
	inDir := filepath.Join(dir, "in")
	if err := os.MkdirAll(inDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(inDir, "a.json"), unsignedManifestJSON(), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// --out doesn't exist yet — batch mode must create it.
	outDir := filepath.Join(dir, "does-not-exist-yet")
	output, err := runCLI(t, "sign", "--key", keyPath, "--in", inDir, "--out", outDir)
	if err != nil {
		t.Fatalf("sign error = %v (output: %s)", err, output)
	}
	if !strings.Contains(output, "1 of 1 files signed") {
		t.Errorf("output = %q, want an all-succeeded summary", output)
	}
}

func TestSign_BatchMode_OutIsExistingFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateKeyFile(t, dir, "key-1")
	inDir := filepath.Join(dir, "in")
	if err := os.MkdirAll(inDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(inDir, "a.json"), unsignedManifestJSON(), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	out := filepath.Join(dir, "out-is-a-file")
	if err := os.WriteFile(out, []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := runCLI(t, "sign", "--key", keyPath, "--in", inDir, "--out", out)
	if err == nil || !strings.Contains(err.Error(), "existing file") {
		t.Errorf("err = %v, want error about --out being an existing file", err)
	}
}
