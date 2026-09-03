package protocol

import (
	"encoding/json"
	"fmt"
	"time"
)

// DeDiFile is a self-contained, signed document holding one registry and
// its records, per dedi-file.schema.json.
type DeDiFile struct {
	DediVersion string    `json:"dedi_version"`
	Type        string    `json:"type"` // "dedi-file" — required
	SourceURL   string    `json:"source_url"`
	NextUpdate  time.Time `json:"next_update"`
	Publisher   Publisher `json:"publisher"`
	Namespace   string    `json:"namespace"`
	Registry    Registry  `json:"registry"`
	Records     []Record  `json:"records"`
	Proof       Proof     `json:"proof"`
}

// Publisher identifies the DeDi file's signer.
type Publisher struct {
	Domain string `json:"domain"`
	Key    Key    `json:"key"` // public key only — never private material
}

// Registry describes the one directory a DeDi file carries.
type Registry struct {
	Name      string    `json:"name"`
	Schema    SchemaRef `json:"schema"`
	State     string    `json:"state"` // "live" | "inactive"
	UpdatedAt time.Time `json:"updated_at"`
	// Description and Meta mirror DeDi.global's own fields of the same
	// names (decentralized-directory-protocol PR #33, not yet merged) —
	// both optional, so a file predating them simply unmarshals these to
	// their zero values. Signed with the rest of the file; carry no
	// verification semantics of their own.
	Description string          `json:"description,omitempty"`
	Meta        json.RawMessage `json:"meta,omitempty"`
}

// Record is one entry in a registry.
type Record struct {
	RecordName string          `json:"record_name"`
	Details    json.RawMessage `json:"details"`
	// Description and Meta — see Registry's identically-named fields.
	Description string          `json:"description,omitempty"`
	Meta        json.RawMessage `json:"meta,omitempty"`
}

// ParseDeDiFile unmarshals raw bytes into a DeDiFile.
func ParseDeDiFile(raw []byte) (*DeDiFile, error) {
	var f DeDiFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse dedi file: %w", WrapJSONError(raw, err))
	}
	return &f, nil
}
