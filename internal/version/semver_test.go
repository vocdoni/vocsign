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
	}

	for _, tt := range tests {
		if got := IsOutdated(tt.current, tt.latest); got != tt.want {
			t.Fatalf("IsOutdated(%q,%q)=%v want %v", tt.current, tt.latest, got, tt.want)
		}
	}
}
