package protocol

import (
	"encoding/json"
	"fmt"
)

// WrapJSONError enriches a json.Unmarshal error with a "line N, column M"
// prefix derived from raw's byte offset, for the two stdlib json error
// types that carry one (*json.SyntaxError, *json.UnmarshalTypeError). raw
// must be the exact, complete byte slice passed to Unmarshal — offsets are
// only meaningful against that same slice, not a sub-document. Other error
// types (including nil) pass through unchanged.
func WrapJSONError(raw []byte, err error) error {
	var offset int64
	switch e := err.(type) {
	case *json.SyntaxError:
		offset = e.Offset
	case *json.UnmarshalTypeError:
		offset = e.Offset
	default:
		return err
	}

	line, col := 1, 1
	for _, b := range raw[:min(int(offset), len(raw))] {
		if b == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return fmt.Errorf("line %d, column %d: %w", line, col, err)
}
