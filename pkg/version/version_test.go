package version

import "testing"

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.27.3", "1.27.3", 0},
		{"1.27", "1.27.0", 0},
		{"v1.2.3", "1.2.3", 0},
		{"1.2.10", "1.2.9", 1},
		{"1.10.0", "1.9.9", 1},
		{"2.0.0-rc1", "2.0.0", -1},
		{"2.0.0-rc.2", "2.0.0-rc.10", -1},
		{"2.0.0-alpha", "2.0.0-beta", -1},
		{"2.0.0-1", "2.0.0-alpha", -1},
		{"16.4", "16.10", -1},
		{"9.8p1", "9.8p2", -1},
		{"9.8p1", "9.9", -1},
		{"1.0.0+build5", "1.0.0", 0},
	}
	for _, tt := range tests {
		if got := Compare(tt.a, tt.b); got != tt.want {
			t.Errorf("Compare(%q,%q)=%d want %d", tt.a, tt.b, got, tt.want)
		}
		if got := Compare(tt.b, tt.a); got != -tt.want {
			t.Errorf("Compare(%q,%q)=%d want %d", tt.b, tt.a, got, -tt.want)
		}
	}
}
