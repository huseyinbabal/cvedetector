// Package build merges per-source results into product shards and writes the feed.
package build

import (
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/huseyinbabal/cvedetector/pkg/feed"
)

// Merge combines vulnerabilities from several sources, keyed by ID and alias.
// Affected ranges are unioned (conservative). NVD's CVSS wins over OSV's when
// both exist; the shorter OSV summary wins over NVD's description.
func Merge(lists ...[]feed.Vuln) []feed.Vuln {
	byID := map[string]*feed.Vuln{}
	alias := map[string]string{}
	var order []string
	for _, list := range lists {
		for _, v := range list {
			key, found := v.ID, false
			for _, id := range append([]string{v.ID}, v.Aliases...) {
				if k, ok := alias[id]; ok {
					key, found = k, true
					break
				}
			}
			cur := byID[key]
			if !found {
				c := v
				c.Aliases = slices.Clone(v.Aliases)
				c.Affected = slices.Clone(v.Affected)
				c.Sources = slices.Clone(v.Sources)
				c.References = slices.Clone(v.References)
				byID[key] = &c
				order = append(order, key)
				alias[key] = key
				for _, a := range v.Aliases {
					alias[a] = key
				}
				continue
			}
			mergeInto(cur, v)
			for _, a := range append([]string{v.ID}, v.Aliases...) {
				alias[a] = key
			}
		}
	}
	out := make([]feed.Vuln, 0, len(order))
	for _, k := range order {
		v := byID[k]
		v.Affected = dedupRanges(v.Affected)
		v.Aliases = dedupStrings(v.Aliases, v.ID)
		v.References = dedupStrings(v.References, "")
		sort.Strings(v.Sources)
		v.Sources = slices.Compact(v.Sources)
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func mergeInto(cur *feed.Vuln, v feed.Vuln) {
	cur.Affected = append(cur.Affected, v.Affected...)
	cur.Aliases = append(cur.Aliases, v.Aliases...)
	if v.ID != cur.ID {
		cur.Aliases = append(cur.Aliases, v.ID)
	}
	cur.Sources = append(cur.Sources, v.Sources...)
	cur.References = append(cur.References, v.References...)
	nvd := slices.Contains(v.Sources, "nvd")
	if v.CVSS > 0 && (cur.CVSS == 0 || nvd) {
		cur.CVSS, cur.CVSSVector, cur.Severity = v.CVSS, v.CVSSVector, v.Severity
	}
	if cur.Severity == feed.SeverityUnknown && v.Severity != feed.SeverityUnknown {
		cur.Severity = v.Severity
	}
	if v.Summary != "" && (cur.Summary == "" || (!nvd && len(v.Summary) < len(cur.Summary))) {
		cur.Summary = v.Summary
	}
	if cur.Published.IsZero() || (!v.Published.IsZero() && v.Published.Before(cur.Published)) {
		cur.Published = v.Published
	}
	if v.Modified.After(cur.Modified) {
		cur.Modified = v.Modified
	}
}

func dedupRanges(rs []feed.Range) []feed.Range {
	seen := map[feed.Range]bool{}
	out := rs[:0]
	for _, r := range rs {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

func dedupStrings(ss []string, skip string) []string {
	seen := map[string]bool{skip: true}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Enrich sets KEV and EPSS on vulnerabilities with a CVE id or alias.
func Enrich(vulns []feed.Vuln, kev map[string]bool, epss map[string]float64) {
	for i := range vulns {
		for _, id := range append([]string{vulns[i].ID}, vulns[i].Aliases...) {
			if kev[id] {
				vulns[i].KEV = true
			}
			if s, ok := epss[id]; ok && s > vulns[i].EPSS {
				vulns[i].EPSS = s
			}
		}
	}
}

// CVEIDs returns the distinct CVE ids referenced by vulns.
func CVEIDs(vulns []feed.Vuln) []string {
	set := map[string]bool{}
	for _, v := range vulns {
		for _, id := range append([]string{v.ID}, v.Aliases...) {
			if strings.HasPrefix(id, "CVE-") {
				set[id] = true
			}
		}
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// NewIndex returns an empty index stamped with now.
func NewIndex(now time.Time) feed.Index {
	return feed.Index{SchemaVersion: feed.SchemaVersion, GeneratedAt: now.UTC()}
}
