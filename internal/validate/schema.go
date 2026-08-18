// Package validate checks DeDi file records against their registry's inline
// JSON Schema before signing. Pure functions, no I/O beyond what's passed
// in — this package never fetches anything itself.
package validate

import (
	"encoding/json"
	"fmt"

	"github.com/nfh-trust-labs/dedi-cli/internal/protocol"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

// CompileInlineSchema compiles a registry's inline JSON Schema object. The
// "url" jsonschema.CompileString takes is just an identifying name for the
// resource, not a real fetch target.
func CompileInlineSchema(inline json.RawMessage) (*jsonschema.Schema, error) {
	schema, err := jsonschema.CompileString("inline-registry-schema.json", string(inline))
	if err != nil {
		return nil, fmt.Errorf("compile inline schema: %w", err)
	}
	return schema, nil
}

// ValidateRecords checks every record's details against schema.
func ValidateRecords(records []protocol.Record, schema *jsonschema.Schema) error {
	for _, r := range records {
		var v interface{}
		if err := json.Unmarshal(r.Details, &v); err != nil {
			return fmt.Errorf("record %q: unmarshal details: %w", r.RecordName, err)
		}
		if err := schema.Validate(v); err != nil {
			return fmt.Errorf("record %q: %w", r.RecordName, err)
		}
	}
	return nil
}
