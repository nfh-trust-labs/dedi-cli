package protocol

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestWrapJSONError(t *testing.T) {
	t.Run("syntax error reports line and column", func(t *testing.T) {
		raw := []byte("{\n  \"a\": 1,\n  \"b\": 2,\n}\n")
		var v map[string]int
		err := json.Unmarshal(raw, &v)
		if err == nil {
			t.Fatalf("json.Unmarshal() error = nil, want a syntax error")
		}

		got := WrapJSONError(raw, err)
		if !strings.Contains(got.Error(), "line 4, column") {
			t.Errorf("WrapJSONError() = %q, want it to mention line 4", got.Error())
		}
		if !errors.Is(got, err) {
			t.Errorf("WrapJSONError() does not unwrap to the original error")
		}
	})

	t.Run("type error reports line and column", func(t *testing.T) {
		raw := []byte("{\n  \"n\": \"not a number\"\n}")
		var v struct {
			N int `json:"n"`
		}
		err := json.Unmarshal(raw, &v)
		if err == nil {
			t.Fatalf("json.Unmarshal() error = nil, want a type error")
		}

		got := WrapJSONError(raw, err)
		if !strings.Contains(got.Error(), "line 2, column") {
			t.Errorf("WrapJSONError() = %q, want it to mention line 2", got.Error())
		}
	})

	t.Run("other errors pass through unchanged", func(t *testing.T) {
		base := errors.New("some other error")
		got := WrapJSONError([]byte("{}"), base)
		if got != base {
			t.Errorf("WrapJSONError() = %v, want the original error unchanged", got)
		}
	})
}
