package build

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/huseyinbabal/cvedetector/pkg/feed"
)

func output(vulns []feed.Vuln, epss map[string]float64) Output {
	return Output{
		Index:  feed.Index{Products: []feed.Product{{ID: "nginx", Name: "NGINX", Images: []string{"docker.io/library/nginx"}}}},
		Shards: map[string]feed.Shard{"nginx": {Vulns: vulns}},
		EPSS:   epss,
	}
}

func readIndex(t *testing.T, dir string) feed.Index {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "v1", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx feed.Index
	if err := json.Unmarshal(b, &idx); err != nil {
		t.Fatal(err)
	}
	return idx
}

func TestWriteDiffAndChangelog(t *testing.T) {
	dir, changes := t.TempDir(), t.TempDir()
	day1 := time.Date(2026, 11, 19, 3, 0, 0, 0, time.UTC)
	v1 := []feed.Vuln{
		{ID: "CVE-2", Severity: "HIGH", Affected: []feed.Range{{LT: "1.2"}}, EPSS: 0.5, Modified: day1},
		{ID: "CVE-1", Severity: "LOW", Affected: []feed.Range{{LT: "1.0"}}},
	}

	// First run writes everything; no changelog for the initial import.
	d, err := Write(dir, output(v1, map[string]float64{"CVE-1": 0.1}), day1)
	if err != nil || !d.Changed || len(d.Added) != 0 {
		t.Fatalf("first: %+v %v", d, err)
	}
	idx := readIndex(t, dir)
	if idx.EPSS == nil || idx.Products[0].VulnCount != 2 || !idx.GeneratedAt.Equal(day1) {
		t.Fatalf("index: %+v", idx)
	}
	shard, _ := os.ReadFile(filepath.Join(dir, "v1", "products", "nginx.json"))
	if strings.Contains(string(shard), "epss") || strings.Contains(string(shard), "modified") || strings.Index(string(shard), "CVE-1") > strings.Index(string(shard), "CVE-2") {
		t.Fatalf("shard not normalized: %s", shard)
	}

	// Same content (different order, volatile fields): nothing changes, files untouched.
	before, _ := os.ReadFile(filepath.Join(dir, "v1", "index.json"))
	v1b := []feed.Vuln{v1[1], {ID: "CVE-2", Severity: "HIGH", Affected: []feed.Range{{LT: "1.2"}}, EPSS: 0.9, Modified: day1.Add(time.Hour)}}
	d, err = Write(dir, output(v1b, map[string]float64{"CVE-1": 0.1}), day1.Add(time.Hour))
	if err != nil || d.Changed {
		t.Fatalf("unchanged: %+v %v", d, err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "v1", "index.json"))
	if string(before) != string(after) {
		t.Fatal("index rewritten without changes")
	}

	// EPSS only.
	d, err = Write(dir, output(v1b, map[string]float64{"CVE-1": 0.2}), day1.Add(2*time.Hour))
	if err != nil || !d.Changed || !d.EPSSChanged || len(d.Updated) != 0 {
		t.Fatalf("epss only: %+v %v", d, err)
	}
	if !strings.Contains(CommitMessage(day1, d), "EPSS scores updated") {
		t.Errorf("commit message: %q", CommitMessage(day1, d))
	}

	// Real changes: CVE-3 added, CVE-2 range fixed + KEV, CVE-1 withdrawn.
	day2 := day1.Add(24 * time.Hour)
	v2 := []feed.Vuln{
		{ID: "CVE-2", Severity: "HIGH", KEV: true, Affected: []feed.Range{{LT: "1.3"}}},
		{ID: "CVE-3", Severity: "CRITICAL", Affected: []feed.Range{{}}},
	}
	d, err = Write(dir, output(v2, map[string]float64{"CVE-1": 0.2}), day2)
	if err != nil || !d.Changed {
		t.Fatal(err)
	}
	if len(d.Added) != 1 || d.Added[0].ID != "CVE-3" || len(d.Removed) != 1 || d.Removed[0].ID != "CVE-1" ||
		len(d.Updated) != 1 || strings.Join(d.Updated[0].Fields, ",") != "kev,affected" {
		t.Fatalf("diff: %+v", d)
	}
	msg := CommitMessage(day2, d)
	if !strings.HasPrefix(msg, "feed 2026-11-20: 1 new, 1 updated, 1 removed") || !strings.Contains(msg, "nginx CVE-3 (critical)") {
		t.Errorf("commit message: %q", msg)
	}
	p, err := WriteChangelog(changes, day2, d)
	if err != nil || !strings.HasSuffix(p, filepath.Join("2026", "11", "2026-11-20.json")) {
		t.Fatalf("changelog: %q %v", p, err)
	}

	// A second run the same day merges into the same file.
	d2 := Diff{Updated: []Change{{Product: "nginx", ID: "CVE-2", Severity: "HIGH", KEV: true, Fields: []string{"cvss"}}}}
	if _, err := WriteChangelog(changes, day2, d2); err != nil {
		t.Fatal(err)
	}
	var cl Changelog
	b, _ := os.ReadFile(p)
	_ = json.Unmarshal(b, &cl)
	if len(cl.Added) != 1 || len(cl.Updated) != 1 || strings.Join(cl.Updated[0].Fields, ",") != "affected,cvss,kev" {
		t.Fatalf("merged changelog: %+v", cl)
	}
	if p, _ := WriteChangelog(changes, day2, Diff{}); p != "" {
		t.Error("empty diff must not write a changelog")
	}

	// Without enrichment the previous EPSS file is kept.
	d, err = Write(dir, output(append(v2, feed.Vuln{ID: "CVE-4", Severity: "LOW", Affected: []feed.Range{{}}}), nil), day2)
	if err != nil || !d.Changed || d.EPSSChanged {
		t.Fatalf("no-enrich run: %+v %v", d, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "v1", "epss.json")); err != nil || readIndex(t, dir).EPSS == nil {
		t.Fatal("epss.json dropped on a run without enrichment")
	}
}
