package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// SchemaRef is the registry.schema union: a bare URL string, or an inline
// JSON Schema object. This is a different kind of sniff than FilesEntry's
// (the first non-whitespace byte is '"' for a URL string vs '{' for an
// inline object) — not the same "shape-sniff two same-typed objects"
// recipe FilesEntry uses.
type SchemaRef struct {
	URL    string
	Inline json.RawMessage
}

// IsURL reports whether this SchemaRef holds a URL (as opposed to an inline
// schema object).
func (s SchemaRef) IsURL() bool {
	return s.URL != ""
}

func (s *SchemaRef) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return errors.New("schema ref: empty value")
	}
	if trimmed[0] == '"' {
		var url string
		if err := json.Unmarshal(data, &url); err != nil {
			return fmt.Errorf("schema ref (url): %w", err)
		}
		*s = SchemaRef{URL: url}
		return nil
	}
	inline := make(json.RawMessage, len(trimmed))
	copy(inline, trimmed)
	*s = SchemaRef{Inline: inline}
	return nil
}

func (s SchemaRef) MarshalJSON() ([]byte, error) {
	if s.IsURL() {
		return json.Marshal(s.URL)
	}
	if len(s.Inline) == 0 {
		return nil, errors.New("schema ref: neither URL nor Inline is set")
	}
	return s.Inline, nil
}
