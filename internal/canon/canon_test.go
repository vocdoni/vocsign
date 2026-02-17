package canon

import (
	"testing"
)

func TestEncode(t *testing.T) {
	input := map[string]interface{}{
		"b": 1,
		"a": "hello",
		"c": []int{2, 1, 3},
		"d": map[string]interface{}{
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
