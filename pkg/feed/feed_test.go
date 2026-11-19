package feed

import "testing"

func TestVulnMatch(t *testing.T) {
	v := Vuln{Affected: []Range{
		{GTE: "1.25.0", LT: "1.26.3"},
		{GTE: "1.27.0", LT: "1.27.2"},
		{EQ: "1.20.1"},
		{GT: "2.0.0", LTE: "2.0.5"},
	}}
	tests := []struct {
		in       string
		affected bool
		fixed    string
	}{
		{"1.24.9", false, ""},
		{"1.25.0", true, "1.26.3"},
		{"1.26.3", false, ""},
		{"1.27.1", true, "1.27.2"},
		{"1.27.2", false, ""},
		{"1.20.1", true, ""},
		{"2.0.0", false, ""},
		{"2.0.5", true, ""},
	}
	for _, tt := range tests {
		a, f := v.Match(tt.in)
		if a != tt.affected || f != tt.fixed {
			t.Errorf("Match(%q) = %v,%q want %v,%q", tt.in, a, f, tt.affected, tt.fixed)
		}
	}
	if a, _ := (Vuln{Affected: []Range{{}}}).Match("9.9"); !a {
		t.Error("empty range should match everything")
	}
}

func TestCompileVersionPattern(t *testing.T) {
	re, err := CompileVersionPattern("")
	if err != nil {
		t.Fatal(err)
	}
	for tag, want := range map[string]string{
		"1.27.3":             "1.27.3",
		"v2.13.0":            "2.13.0",
		"7.2.4-debian-12-r5": "7.2.4",
		"16.4-alpine":        "16.4",
	} {
		m := re.FindStringSubmatch(tag)
		if m == nil || m[re.SubexpIndex("version")] != want {
			t.Errorf("%q -> %v want %q", tag, m, want)
		}
	}
	if re.MatchString("latest") {
		t.Error("latest should not match")
	}
	if _, err := CompileVersionPattern("^(\\d+)"); err == nil {
		t.Error("expected error for missing group")
	}
}
