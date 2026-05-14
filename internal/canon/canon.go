package canon

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Encode returns the canonical JSON encoding of v.
// It ensures:
// - Struct fields in Go declaration order (NOT alphabetical)
// - No insignificant whitespace (Go's default for Marshal)
// - No HTML escaping (SetEscapeHTML(false))
//
// IMPORTANT: The organizer (TypeScript portal) must produce JSON with the same
// field ordering. Go's encoding/json outputs struct fields in declaration order,
// while JSON.stringify outputs in insertion order. Both sides must construct
// objects with fields in the same order for JWS verification to succeed.
func Encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)

	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("canonical encoding failed: %w", err)
	}

	// json.Encoder.Encode appends a newline at the end. We need to remove it.
	// https://pkg.go.dev/encoding/json#Encoder.Encode
	bytes := buf.Bytes()
	if len(bytes) > 0 && bytes[len(bytes)-1] == '\n' {
		bytes = bytes[:len(bytes)-1]
	}

	return bytes, nil
}
