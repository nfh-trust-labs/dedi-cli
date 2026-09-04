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

	line, col := LineCol(raw, int(offset))
	return fmt.Errorf("line %d, column %d: %w", line, col, err)
}

// LineCol converts a byte offset into raw to a 1-indexed (line, column)
// pair. offset is clamped to raw's length, so an offset at or past the end
// of the file still returns a sensible position instead of panicking.
// Shared by WrapJSONError and any other caller that wants to point a
// message at a specific spot in the original input bytes.
func LineCol(raw []byte, offset int) (line, col int) {
	line, col = 1, 1
	for _, b := range raw[:min(offset, len(raw))] {
		if b == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}
