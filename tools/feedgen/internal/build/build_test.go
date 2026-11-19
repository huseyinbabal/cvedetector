package build

import (
	"testing"

	"github.com/huseyinbabal/cvedetector/pkg/feed"
)

func TestMerge(t *testing.T) {
	nvd := []feed.Vuln{{
		ID: "CVE-2024-1", Summary: "a long NVD description of the issue", CVSS: 9.8, Severity: feed.SeverityCritical,
		Sources: []string{"nvd"}, Affected: []feed.Range{{LT: "1.2.0"}},
	}}
	osv := []feed.Vuln{
		{ID: "CVE-2024-1", Aliases: []string{"GHSA-x"}, Summary: "short", CVSS: 7.5, Severity: feed.SeverityHigh,
			Sources: []string{"osv"}, Affected: []feed.Range{{LT: "1.2.0"}, {GTE: "2.0.0", LT: "2.0.3"}}},
		{ID: "GHSA-only", Severity: feed.SeverityLow, Sources: []string{"osv"}, Affected: []feed.Range{{EQ: "1.0.0"}}},
	}
	got := Merge(nvd, osv)
	if len(got) != 2 {
		t.Fatalf("got %d: %+v", len(got), got)
	}
	v := got[0]
	if v.ID != "CVE-2024-1" || v.CVSS != 9.8 || v.Summary != "short" || len(v.Affected) != 2 || len(v.Sources) != 2 || v.Aliases[0] != "GHSA-x" {
		t.Errorf("merged: %+v", v)
	}
	// An OSV record seen first, then the NVD record with the same CVE id.
	got = Merge(osv[:1], nvd)
	if len(got) != 1 || got[0].CVSS != 9.8 {
		t.Errorf("reverse order: %+v", got)
	}
}

func TestEnrich(t *testing.T) {
	vs := []feed.Vuln{{ID: "GHSA-x", Aliases: []string{"CVE-2024-1"}}, {ID: "CVE-2024-2"}}
	Enrich(vs, map[string]bool{"CVE-2024-1": true}, map[string]float64{"CVE-2024-2": 0.3})
	if !vs[0].KEV || vs[1].EPSS != 0.3 {
		t.Errorf("%+v", vs)
	}
}
