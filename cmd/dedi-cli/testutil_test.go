package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/nfh-trust-labs/dedi-cli/internal/sign"
)

// runCLI executes a fresh root command with args, capturing combined
// stdout/stderr. Each call gets its own command tree, so flag state never
// leaks between tests.
func runCLI(t *testing.T, args ...string) (output string, err error) {
	t.Helper()
	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)
	err = root.Execute()
	return buf.String(), err
}

// generateKeyFile creates a fresh Ed25519 key and writes it to <dir>/<kid>.json,
// returning the path plus the kid for building fixtures that reference it.
func generateKeyFile(t *testing.T, dir, kid string) string {
	t.Helper()
	k, err := sign.GenerateKey(kid)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	path := filepath.Join(dir, kid+".json")
	if err := sign.SavePrivateJWK(path, k); err != nil {
		t.Fatalf("SavePrivateJWK() error = %v", err)
	}
	return path
}

// unsignedManifestJSON returns a minimal unsigned manifest fixture (no
// "proof", empty "keys" — the sign command's EnsureManifestKey adds the
// signing key). Top-level "domain" with no "publisher" is what
// detectDocumentKind sniffs as a manifest.
func unsignedManifestJSON() []byte {
	return []byte(`{
		"dedi_version": "0.1",
		"domain": "example.org",
		"keys": [],
		"updated_at": "2026-07-01T09:00:00Z",
		"next_update": "2026-07-15T10:00:00Z",
		"files": []
	}`)
}

// unsignedDeDiFileJSON returns a minimal unsigned DeDi file fixture with an
// inline registry.schema requiring "anchor_id" on every record, and one
// record satisfying it. "publisher.key" is left unset — EnsurePublisherKey
// fills it in during signing. Top-level "publisher" with no "domain" is what
// detectDocumentKind sniffs as a DeDi file.
func unsignedDeDiFileJSON() []byte {
	return []byte(`{
		"dedi_version": "0.1",
		"type": "dedi-file",
		"source_url": "https://example.org/.well-known/dedi.index.json",
		"next_update": "2026-07-15T10:00:00Z",
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
	}`)
}

// unsignedDeDiFileWithSchemaJSON is like unsignedDeDiFileJSON but with
// registry.schema replaced by schemaRef (either a quoted URL string or an
// inline object literal), and records replaced by recordsJSON — for tests
// that need to control the schema/records independently (URL-referenced
// schemas, records that violate the schema, etc).
func unsignedDeDiFileWithSchemaJSON(schemaRef, recordsJSON string) []byte {
	return []byte(fmt.Sprintf(`{
		"dedi_version": "0.1",
		"type": "dedi-file",
		"source_url": "https://example.org/.well-known/dedi.index.json",
		"next_update": "2026-07-15T10:00:00Z",
		"publisher": {"domain": "example.org"},
		"namespace": "example.org",
		"registry": {
			"name": "trust-anchors",
			"schema": %s,
			"state": "live",
			"updated_at": "2026-07-01T09:00:00Z"
		},
		"records": %s
	}`, schemaRef, recordsJSON))
}
