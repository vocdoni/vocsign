package version

import "testing"

func TestIsOutdated(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool
	}{
		{current: "v1.2.2", latest: "v1.2.3", want: true},
		{current: "1.2.3", latest: "v1.2.3", want: false},
		{current: "v1.2.3", latest: "v1.2.2", want: false},
		{current: "dev", latest: "v1.2.3", want: false},
		{current: "v1.2.3", latest: "latest", want: false},
		{current: "v1.2.3-rc1", latest: "v1.2.4", want: true},
		// Major version difference
		{current: "v1.0.0", latest: "v2.0.0", want: true},
		// Minor version difference
		{current: "v1.1.0", latest: "v1.2.0", want: true},
		// Same version
		{current: "v1.2.3", latest: "v1.2.3", want: false},
		// Empty strings
		{current: "", latest: "", want: false},
		// Build metadata
		{current: "v1.2.3+build", latest: "v1.2.4", want: true},
		// Only major
		{current: "v1", latest: "v2", want: true},
		// Major.minor only
		{current: "v1.2", latest: "v1.3", want: true},
		// Negative version
		{current: "v-1.0.0", latest: "v1.0.0", want: false},
		// Leading whitespace
		{current: " v1.2.3", latest: "v1.2.4", want: true},
		// Capital V
		{current: "V1.2.3", latest: "v1.2.4", want: true},
	}

	for _, tt := range tests {
		if got := IsOutdated(tt.current, tt.latest); got != tt.want {
			t.Fatalf("IsOutdated(%q,%q)=%v want %v", tt.current, tt.latest, got, tt.want)
		}
	}
}
