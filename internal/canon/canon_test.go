package canon

import (
	"testing"
)

func TestEncode(t *testing.T) {
	input := map[string]any{
		"b": 1,
		"a": "hello",
		"c": []int{2, 1, 3},
		"d": map[string]any{
			"y": "foo",
			"x": "bar",
		},
	}

	expected := `{"a":"hello","b":1,"c":[2,1,3],"d":{"x":"bar","y":"foo"}}`

	encoded, err := Encode(input)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	if string(encoded) != expected {
		t.Errorf("Expected %q, got %q", expected, string(encoded))
	}
}

func TestEncodeStruct(t *testing.T) {
	// Fields are declared in non-alphabetical order to verify that
	// encoding preserves Go declaration order, not alphabetical order.
	type Sample struct {
		Zebra string `json:"zebra"`
		Alpha int    `json:"alpha"`
		Mango bool   `json:"mango"`
	}

	input := Sample{Zebra: "stripes", Alpha: 42, Mango: true}
	expected := `{"zebra":"stripes","alpha":42,"mango":true}`

	encoded, err := Encode(input)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	if string(encoded) != expected {
		t.Errorf("Expected %q, got %q", expected, string(encoded))
	}
}

func TestEncodeNoTrailingNewline(t *testing.T) {
	input := map[string]string{"key": "value"}

	encoded, err := Encode(input)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	if len(encoded) == 0 {
		t.Fatal("Encode returned empty bytes")
	}

	if encoded[len(encoded)-1] == '\n' {
		t.Error("Output has a trailing newline, but should not")
	}
}

func TestEncodeHTMLCharacters(t *testing.T) {
	input := map[string]string{"html": "<b>bold</b> & \"quoted\""}
	// With SetEscapeHTML(false), angle brackets and ampersands must NOT
	// be replaced with unicode escape sequences.
	expected := `{"html":"<b>bold</b> & \"quoted\""}`

	encoded, err := Encode(input)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	if string(encoded) != expected {
		t.Errorf("Expected %q, got %q", expected, string(encoded))
	}
}

func TestEncodeEmptyObject(t *testing.T) {
	type Empty struct{}
	encoded, err := Encode(Empty{})
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	if string(encoded) != "{}" {
		t.Errorf("Expected %q, got %q", "{}", string(encoded))
	}

	// Also verify with an empty map.
	encoded2, err := Encode(map[string]any{})
	if err != nil {
		t.Fatalf("Encode (empty map) failed: %v", err)
	}
	if string(encoded2) != "{}" {
		t.Errorf("Expected %q for empty map, got %q", "{}", string(encoded2))
	}
}

func TestEncodeNilPointerOmitempty(t *testing.T) {
	type WithPointers struct {
		Name  string  `json:"name"`
		Value *int    `json:"value,omitempty"`
		Note  *string `json:"note,omitempty"`
	}

	input := WithPointers{Name: "test"}
	expected := `{"name":"test"}`

	encoded, err := Encode(input)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	if string(encoded) != expected {
		t.Errorf("Expected %q, got %q", expected, string(encoded))
	}
}

func TestEncodeDeterministic(t *testing.T) {
	type Payload struct {
		ID    int    `json:"id"`
		Label string `json:"label"`
	}

	input := Payload{ID: 7, Label: "same"}

	first, err := Encode(input)
	if err != nil {
		t.Fatalf("First Encode failed: %v", err)
	}

	second, err := Encode(input)
	if err != nil {
		t.Fatalf("Second Encode failed: %v", err)
	}

	if string(first) != string(second) {
		t.Errorf("Determinism broken: first=%q, second=%q", first, second)
	}
}
