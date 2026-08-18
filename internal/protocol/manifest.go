package protocol

import (
	"encoding/json"
	"fmt"
	"time"
)

// Manifest is the signed document served at a publisher's
// /.well-known/dedi.index.json, per dedi-manifest.schema.json. It declares
// the publisher's current signing key(s) and lists its DeDi files.
type Manifest struct {
	Type        string `json:"type,omitempty"` // const "dedi-manifest" if present
	DediVersion string `json:"dedi_version"`
	Domain      string `json:"domain"`
	Name        string `json:"name,omitempty"`
	// Description is the namespace-level equivalent of Registry/Record's
	// own Description (decentralized-directory-protocol PR #33, not yet
	// merged) — optional, so a manifest predating it simply unmarshals to
	// "". No Meta counterpart here by design: the well-known is fetched by
	// every verifier just for the key check and stays minimal.
	Description string       `json:"description,omitempty"`
	Keys        []Key        `json:"keys"`
	UpdatedAt   time.Time    `json:"updated_at"`
	NextUpdate  time.Time    `json:"next_update"`
	Files       []FilesEntry `json:"files"`
	Proof       Proof        `json:"proof"`
}

// ParseManifest unmarshals raw bytes into a Manifest.
func ParseManifest(raw []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
}
