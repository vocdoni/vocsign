package widgets

import "testing"

func TestAutocomplete_Filter(t *testing.T) {
	ac := NewAutocomplete([]string{"Barcelona", "Badajoz", "Burgos", "Cádiz"})
	tests := []struct {
		query string
		want  int
	}{
		{"", 4},
		{"ba", 2},
		{"burg", 1},
		{"xyz", 0},
		{"cadiz", 1},
		{"BARCE", 1},
	}
	for _, tc := range tests {
		got := ac.filter(tc.query)
		if len(got) != tc.want {
			t.Errorf("filter(%q) returned %d results, want %d", tc.query, len(got), tc.want)
		}
	}
}

func TestAutocomplete_RemoveDiacritics(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Cádiz", "Cadiz"},
		{"Álava", "Alava"},
		{"Girona", "Girona"},
		{"Lleida", "Lleida"},
		{"María", "Maria"},
	}
	for _, tc := range tests {
		got := removeDiacritics(tc.in)
		if got != tc.want {
			t.Errorf("removeDiacritics(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestAutocomplete_SetSelected(t *testing.T) {
	ac := NewAutocomplete([]string{"Madrid", "Málaga", "Murcia"})
	ac.SetSelected("Madrid")
	if ac.Selected != "Madrid" {
		t.Fatalf("Selected = %q, want Madrid", ac.Selected)
	}
	if !ac.IsValid() {
		t.Fatal("expected IsValid() = true after SetSelected")
	}
}

func TestAutocomplete_SetOptions_ClearsInvalidSelection(t *testing.T) {
	ac := NewAutocomplete([]string{"Madrid", "Málaga"})
	ac.SetSelected("Madrid")
	ac.SetOptions([]string{"Barcelona", "Bilbao"})
	if ac.Selected != "" {
		t.Fatalf("Selected = %q, want empty after SetOptions with new list", ac.Selected)
	}
}

func TestAutocomplete_IsValid(t *testing.T) {
	ac := NewAutocomplete([]string{"Madrid", "Málaga"})
	if ac.IsValid() {
		t.Fatal("expected IsValid() = false with empty text")
	}
	ac.SetSelected("Madrid")
	if !ac.IsValid() {
		t.Fatal("expected IsValid() = true after selecting Madrid")
	}
}
