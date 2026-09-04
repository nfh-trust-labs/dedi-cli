// Package validate's envelope checks vendored copies of the protocol's own
// dedi-manifest.schema.json and dedi-file.schema.json, sourced from
// https://github.com/LF-Decentralized-Trust-labs/decentralized-directory-protocol/blob/main/schemas/.
// Embedded rather than fetched: unlike a registry's own schema, these apply
// to every sign invocation, and fetching them live would make basic signing
// require network access unconditionally. There's no automated sync with
// upstream — refreshing internal/validate/schemas/*.json is a manual,
// occasional maintenance task.
package validate

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

//go:embed schemas/dedi-manifest.schema.json
var manifestEnvelopeSchemaJSON []byte

//go:embed schemas/dedi-file.schema.json
var fileEnvelopeSchemaJSON []byte

// These must match each embedded schema's own "$id" exactly.
// dedi-manifest.schema.json's files[] inline-entry union resolves a $ref
// against dedi-file.schema.json's $id — and neither $id is a live,
// fetchable URL (dedi-file's $id in particular omits ".schema", unlike its
// real hosted filename), so a network-fetching compiler can't resolve it.
// Pre-registering both under their own $id via Compiler.AddResource
// sidesteps that entirely.
const (
	manifestEnvelopeSchemaID = "https://raw.githubusercontent.com/LF-Decentralized-Trust-labs/decentralized-directory-protocol/main/schemas/dedi-manifest.json"
	fileEnvelopeSchemaID     = "https://raw.githubusercontent.com/LF-Decentralized-Trust-labs/decentralized-directory-protocol/main/schemas/dedi-file.json"
)

// ValidateManifestEnvelope checks raw — the exact original input bytes, not
// a re-marshaled struct — against the protocol's own dedi-manifest schema.
// Using raw matters: re-marshaling a parsed Manifest would never surface an
// unknown top-level field, since parsing into the Go struct already
// silently dropped it.
func ValidateManifestEnvelope(raw []byte) error {
	return validateEnvelope(raw, manifestEnvelopeSchemaID)
}

// ValidateDeDiFileEnvelope is ValidateManifestEnvelope's DeDi-file counterpart.
func ValidateDeDiFileEnvelope(raw []byte) error {
	return validateEnvelope(raw, fileEnvelopeSchemaID)
}

func validateEnvelope(raw []byte, schemaID string) error {
	c := jsonschema.NewCompiler()
	if err := c.AddResource(manifestEnvelopeSchemaID, bytes.NewReader(manifestEnvelopeSchemaJSON)); err != nil {
		return fmt.Errorf("load embedded manifest schema: %w", err)
	}
	if err := c.AddResource(fileEnvelopeSchemaID, bytes.NewReader(fileEnvelopeSchemaJSON)); err != nil {
		return fmt.Errorf("load embedded dedi file schema: %w", err)
	}
	schema, err := c.Compile(schemaID)
	if err != nil {
		return fmt.Errorf("compile envelope schema: %w", err)
	}

	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("unmarshal document: %w", err)
	}
	return schema.Validate(v)
}
