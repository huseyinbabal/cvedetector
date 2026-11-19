// Package version compares loosely semver-shaped version strings as they appear
// in image tags and vulnerability databases (e.g. "1.27.3", "v2.11.0-rc1", "16.4").
package version

import (
	"strconv"
	"strings"
)

// Version is a parsed version string.
type Version struct {
	Raw        string
	Segments   []string // release segments, e.g. ["1","27","3"]
	Prerelease []string // e.g. ["rc1"], empty for releases
}

// Parse parses s. It never fails: unknown shapes compare lexically per segment.
func Parse(s string) Version {
	raw := s
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "v"), "V")
	if i := strings.IndexByte(s, '+'); i >= 0 { // build metadata is ignored
		s = s[:i]
	}
	var pre string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		s, pre = s[:i], s[i+1:]
	}
	v := Version{Raw: raw}
	if s != "" {
		v.Segments = strings.Split(s, ".")
	}
	if pre != "" {
		v.Prerelease = strings.FieldsFunc(pre, func(r rune) bool { return r == '.' || r == '-' })
	}
	return v
}

// Compare returns -1, 0 or 1. Missing release segments count as 0, so
// "1.27" == "1.27.0". A prerelease sorts before its release.
func Compare(a, b string) int {
	return Parse(a).Compare(Parse(b))
}

// Compare compares v to o.
func (v Version) Compare(o Version) int {
	n := max(len(v.Segments), len(o.Segments))
	for i := range n {
		if c := compareIdent(seg(v.Segments, i), seg(o.Segments, i), true); c != 0 {
			return c
		}
	}
	switch {
	case len(v.Prerelease) == 0 && len(o.Prerelease) == 0:
		return 0
	case len(v.Prerelease) == 0:
		return 1
	case len(o.Prerelease) == 0:
		return -1
	}
	for i := range max(len(v.Prerelease), len(o.Prerelease)) {
		if i >= len(v.Prerelease) {
			return -1
		}
		if i >= len(o.Prerelease) {
			return 1
		}
		if c := compareIdent(v.Prerelease[i], o.Prerelease[i], false); c != 0 {
			return c
		}
	}
	return 0
}

func seg(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return "0"
}

// compareIdent compares numerically when both are numbers. In release segments a
// number with a trailing suffix ("1p1") compares by its numeric prefix first.
func compareIdent(a, b string, release bool) int {
	an, aerr := strconv.ParseUint(a, 10, 64)
	bn, berr := strconv.ParseUint(b, 10, 64)
	if aerr == nil && berr == nil {
		return cmp(an, bn)
	}
	if release {
		ap, as := splitNumPrefix(a)
		bp, bs := splitNumPrefix(b)
		if ap != "" && bp != "" {
			x, _ := strconv.ParseUint(ap, 10, 64)
			y, _ := strconv.ParseUint(bp, 10, 64)
			if c := cmp(x, y); c != 0 {
				return c
			}
			return strings.Compare(as, bs)
		}
	} else {
		// semver: numeric identifiers sort before alphanumeric ones
		if aerr == nil {
			return -1
		}
		if berr == nil {
			return 1
		}
	}
	return strings.Compare(a, b)
}

func splitNumPrefix(s string) (string, string) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i], s[i:]
}

func cmp(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
