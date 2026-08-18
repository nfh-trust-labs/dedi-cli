package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ReferencedFile is a manifest files[] entry hosted at a URL, committed to
// by digest.
type ReferencedFile struct {
	Registry string     `json:"registry"`
	URL      string     `json:"url"`
	Digest   string     `json:"digest"` // "sha-256:<hex>" of the raw referenced file's bytes
	Schema   *SchemaRef `json:"schema,omitempty"`
	State    string     `json:"state,omitempty"`
}

// FilesEntry is a manifest files[] union: either a ReferencedFile, or a
// complete DeDiFile embedded verbatim ("inline", per the protocol's spec
// §6.4). The sniff is unambiguous by construction: a referenced entry
// requires "url"; an inline entry is a full DeDiFile object, which never
// has "url" (it has "source_url" instead).
type FilesEntry struct {
	Referenced *ReferencedFile
	Inline     *DeDiFile

	// RawInline is the inline entry's exact original bytes — needed
	// because re-marshaling Inline via encoding/json is not guaranteed
	// byte-identical to what the publisher signed (e.g. a time.Time field
	// with trailing zero fractional seconds or a non-Z UTC offset in the
	// source JSON re-serializes as a bare "Z"), and JCS treats string
	// field values as opaque rather than reparsing them — that drift would
	// make a genuinely valid inline file spuriously fail signature
	// verification. nil for a Referenced entry.
	RawInline json.RawMessage
}

// IsInline reports whether this entry is an inline DeDi file (as opposed
// to a referenced one).
func (f FilesEntry) IsInline() bool {
	return f.Inline != nil
}

func (f *FilesEntry) UnmarshalJSON(data []byte) error {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return fmt.Errorf("files entry: %w", err)
	}

	if _, hasURL := probe["url"]; hasURL {
		var ref ReferencedFile
		if err := json.Unmarshal(data, &ref); err != nil {
			return fmt.Errorf("files entry (referenced): %w", err)
		}
		*f = FilesEntry{Referenced: &ref}
		return nil
	}

	var inline DeDiFile
	if err := json.Unmarshal(data, &inline); err != nil {
		return fmt.Errorf("files entry (inline): %w", err)
	}
	raw := make(json.RawMessage, len(data))
	copy(raw, data)
	*f = FilesEntry{Inline: &inline, RawInline: raw}
	return nil
}

func (f FilesEntry) MarshalJSON() ([]byte, error) {
	switch {
	case f.Referenced != nil:
		return json.Marshal(f.Referenced)
	case f.Inline != nil:
		if f.RawInline != nil {
			return f.RawInline, nil
		}
		return json.Marshal(f.Inline)
	default:
		return nil, errors.New("files entry: neither Referenced nor Inline is set")
	}
}
