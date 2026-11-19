package build

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/huseyinbabal/cvedetector/pkg/feed"
)

// Change is one changed vulnerability in the changelog.
type Change struct {
	Product  string   `json:"product"`
	ID       string   `json:"id"`
	Severity string   `json:"severity,omitempty"`
	KEV      bool     `json:"kev,omitempty"`
	Fields   []string `json:"fields,omitempty"` // for updates: what changed
}

// Diff describes what a run changed compared to the previous feed.
type Diff struct {
	Initial      bool     `json:"-"` // no previous feed in the output directory
	Products     int      `json:"-"`
	Vulns        int      `json:"-"`
	Changed      bool     `json:"-"`
	EPSSChanged  bool     `json:"-"`
	Added        []Change `json:"added"`
	Updated      []Change `json:"updated"`
	Removed      []Change `json:"removed"`
	ProductsMeta []string `json:"productsChanged,omitempty"` // mapping/pattern changes
}

// Output is everything a run produces.
type Output struct {
	Index  feed.Index
	Shards map[string]feed.Shard
	EPSS   map[string]float64
}

// Normalize makes shards deterministic: sorted vulns, no volatile fields, EPSS
// moved out (it changes daily and lives in epss.json).
func Normalize(o *Output) {
	shards := make(map[string]feed.Shard, len(o.Shards))
	for id, sh := range o.Shards {
		sh.SchemaVersion = feed.SchemaVersion
		sh.Product = id
		sh.Vulns = append([]feed.Vuln(nil), sh.Vulns...) // never mutate the caller's slice
		for i := range sh.Vulns {
			sh.Vulns[i].EPSS = 0
			sh.Vulns[i].Modified = time.Time{}
		}
		sort.Slice(sh.Vulns, func(i, j int) bool { return sh.Vulns[i].ID < sh.Vulns[j].ID })
		if sh.Vulns == nil {
			sh.Vulns = []feed.Vuln{}
		}
		shards[id] = sh
	}
	o.Shards = shards
	if o.EPSS != nil {
		epss := make(map[string]float64, len(o.EPSS))
		for k, v := range o.EPSS {
			epss[k] = math.Round(v*1e5) / 1e5
		}
		o.EPSS = epss
	}
}

func encode(v any) ([]byte, string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, "", err
	}
	s := sha256.Sum256(b)
	return b, hex.EncodeToString(s[:]), nil
}

// Write compares o with the feed already in dir/v1 and, if anything changed,
// rewrites it atomically. With no changes the files are left untouched, so a
// committed feed shows no diff. The index's generatedAt is the time of the
// last content change.
func Write(dir string, o Output, now time.Time) (Diff, error) {
	Normalize(&o)
	prevIdx, prevShards, prevEPSSSHA, err := readPrevious(filepath.Join(dir, "v1"))
	if err != nil {
		return Diff{}, err
	}

	files := map[string][]byte{}
	idx := o.Index
	idx.SchemaVersion = feed.SchemaVersion
	for i, p := range idx.Products {
		sh, ok := o.Shards[p.ID]
		if !ok {
			return Diff{}, fmt.Errorf("missing shard for %s", p.ID)
		}
		b, sum, err := encode(sh)
		if err != nil {
			return Diff{}, err
		}
		idx.Products[i].Shard = "products/" + p.ID + ".json"
		idx.Products[i].SHA256 = sum
		idx.Products[i].VulnCount = len(sh.Vulns)
		files[idx.Products[i].Shard] = b
	}
	if o.EPSS != nil {
		b, sum, err := encode(feed.EPSSFile{SchemaVersion: feed.SchemaVersion, Scores: o.EPSS})
		if err != nil {
			return Diff{}, err
		}
		idx.EPSS = &feed.File{Path: "epss.json", SHA256: sum}
		files["epss.json"] = b
	} else if prevIdx != nil && prevIdx.EPSS != nil {
		idx.EPSS = prevIdx.EPSS // enrichment skipped: keep the previous scores
	}

	d := diff(prevIdx, prevShards, idx, o.Shards)
	d.Initial = prevIdx == nil
	d.Products = len(idx.Products)
	for _, p := range idx.Products {
		d.Vulns += p.VulnCount
	}
	d.EPSSChanged = idx.EPSS != nil && idx.EPSS.SHA256 != prevEPSSSHA
	d.Changed = prevIdx == nil || d.EPSSChanged || len(d.ProductsMeta) > 0 || !sameShards(prevIdx, idx)
	if !d.Changed {
		return d, nil
	}
	idx.GeneratedAt = now.UTC()
	b, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return d, err
	}
	files["index.json"] = append(b, '\n')
	return d, swap(dir, files, prevIdx != nil && o.EPSS == nil)
}

func sameShards(a *feed.Index, b feed.Index) bool {
	if len(a.Products) != len(b.Products) {
		return false
	}
	for i := range a.Products {
		if a.Products[i].ID != b.Products[i].ID || a.Products[i].SHA256 != b.Products[i].SHA256 {
			return false
		}
	}
	return true
}

func readPrevious(v1 string) (*feed.Index, map[string]feed.Shard, string, error) {
	b, err := os.ReadFile(filepath.Join(v1, "index.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, "", nil
	} else if err != nil {
		return nil, nil, "", err
	}
	var idx feed.Index
	if err := json.Unmarshal(b, &idx); err != nil {
		return nil, nil, "", fmt.Errorf("previous index: %w", err)
	}
	shards := map[string]feed.Shard{}
	for _, p := range idx.Products {
		sb, err := os.ReadFile(filepath.Join(v1, filepath.FromSlash(p.Shard)))
		if err != nil {
			continue // treated as new
		}
		var sh feed.Shard
		if json.Unmarshal(sb, &sh) == nil {
			shards[p.ID] = sh
		}
	}
	epssSHA := ""
	if idx.EPSS != nil {
		epssSHA = idx.EPSS.SHA256
	}
	return &idx, shards, epssSHA, nil
}

func diff(prev *feed.Index, prevShards map[string]feed.Shard, idx feed.Index, shards map[string]feed.Shard) Diff {
	d := Diff{Added: []Change{}, Updated: []Change{}, Removed: []Change{}}
	prevProducts := map[string]feed.Product{}
	if prev != nil {
		for _, p := range prev.Products {
			prevProducts[p.ID] = p
		}
	}
	seen := map[string]bool{}
	for _, p := range idx.Products {
		seen[p.ID] = true
		if old, ok := prevProducts[p.ID]; ok {
			if old.Name != p.Name || !reflect.DeepEqual(old.Images, p.Images) || old.VersionPattern != p.VersionPattern || old.MinSegments != p.MinSegments {
				d.ProductsMeta = append(d.ProductsMeta, p.ID)
			}
		} else if prev != nil {
			d.ProductsMeta = append(d.ProductsMeta, p.ID)
		}
		if prev == nil {
			continue // first run: no changelog, everything is "new"
		}
		before := map[string]feed.Vuln{}
		for _, v := range prevShards[p.ID].Vulns {
			before[v.ID] = v
		}
		for _, v := range shards[p.ID].Vulns {
			old, ok := before[v.ID]
			delete(before, v.ID)
			if !ok {
				d.Added = append(d.Added, Change{Product: p.ID, ID: v.ID, Severity: v.Severity, KEV: v.KEV})
				continue
			}
			if f := changedFields(old, v); len(f) > 0 {
				d.Updated = append(d.Updated, Change{Product: p.ID, ID: v.ID, Severity: v.Severity, KEV: v.KEV, Fields: f})
			}
		}
		for _, v := range before {
			d.Removed = append(d.Removed, Change{Product: p.ID, ID: v.ID, Severity: v.Severity})
		}
	}
	for id, sh := range prevShards {
		if !seen[id] {
			for _, v := range sh.Vulns {
				d.Removed = append(d.Removed, Change{Product: id, ID: v.ID, Severity: v.Severity})
			}
		}
	}
	for _, l := range [][]Change{d.Added, d.Updated, d.Removed} {
		sort.Slice(l, func(i, j int) bool { return l[i].Product+l[i].ID < l[j].Product+l[j].ID })
	}
	sort.Strings(d.ProductsMeta)
	return d
}

func changedFields(a, b feed.Vuln) []string {
	var f []string
	if a.Severity != b.Severity {
		f = append(f, "severity")
	}
	if a.CVSS != b.CVSS {
		f = append(f, "cvss")
	}
	if a.KEV != b.KEV {
		f = append(f, "kev")
	}
	if !reflect.DeepEqual(a.Affected, b.Affected) {
		f = append(f, "affected")
	}
	if a.Summary != b.Summary {
		f = append(f, "summary")
	}
	if !reflect.DeepEqual(a.Aliases, b.Aliases) {
		f = append(f, "aliases")
	}
	if !reflect.DeepEqual(a.References, b.References) {
		f = append(f, "references")
	}
	return f
}

// swap writes files into a fresh directory and replaces dir/v1 with it.
func swap(dir string, files map[string][]byte, keepEPSS bool) error {
	final := filepath.Join(dir, "v1")
	tmp := filepath.Join(dir, ".v1.tmp")
	old := filepath.Join(dir, ".v1.old")
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if keepEPSS {
		if b, err := os.ReadFile(filepath.Join(final, "epss.json")); err == nil {
			files["epss.json"] = b
		}
	}
	for rel, b := range files {
		p := filepath.Join(tmp, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			return err
		}
	}
	_ = os.RemoveAll(old)
	if _, err := os.Stat(final); err == nil {
		if err := os.Rename(final, old); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	return os.RemoveAll(old)
}

// Changelog is one day's changes/YYYY/MM/YYYY-MM-DD.json.
type Changelog struct {
	Date    string   `json:"date"`
	Added   []Change `json:"added"`
	Updated []Change `json:"updated"`
	Removed []Change `json:"removed"`
}

// WriteChangelog merges d into the day's changelog file under dir. Nothing is
// written when the diff has no vulnerability changes.
func WriteChangelog(dir string, day time.Time, d Diff) (string, error) {
	if len(d.Added)+len(d.Updated)+len(d.Removed) == 0 {
		return "", nil
	}
	date := day.UTC().Format("2006-01-02")
	p := filepath.Join(dir, date[:4], date[5:7], date+".json")
	cl := Changelog{Date: date}
	if b, err := os.ReadFile(p); err == nil {
		if err := json.Unmarshal(b, &cl); err != nil {
			return "", fmt.Errorf("%s: %w", p, err)
		}
	}
	cl.Added = mergeChanges(cl.Added, d.Added)
	cl.Updated = mergeChanges(cl.Updated, d.Updated)
	cl.Removed = mergeChanges(cl.Removed, d.Removed)
	b, err := json.MarshalIndent(cl, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	return p, os.WriteFile(p, append(b, '\n'), 0o644)
}

func mergeChanges(a, b []Change) []Change {
	byKey := map[string]int{}
	out := append([]Change{}, a...)
	for i, c := range out {
		byKey[c.Product+"|"+c.ID] = i
	}
	for _, c := range b {
		if i, ok := byKey[c.Product+"|"+c.ID]; ok {
			out[i].Severity, out[i].KEV = c.Severity, c.KEV
			out[i].Fields = union(out[i].Fields, c.Fields)
			continue
		}
		byKey[c.Product+"|"+c.ID] = len(out)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Product+out[i].ID < out[j].Product+out[j].ID })
	return out
}

func union(a, b []string) []string {
	set := map[string]bool{}
	for _, s := range append(append([]string{}, a...), b...) {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// CommitMessage summarizes a diff for the data-branch commit.
func CommitMessage(day time.Time, d Diff) string {
	date := day.UTC().Format("2006-01-02")
	var b bytes.Buffer
	switch {
	case d.Initial:
		fmt.Fprintf(&b, "feed %s: initial import (%d products, %d vulnerabilities)\n", date, d.Products, d.Vulns)
	case len(d.Added)+len(d.Updated)+len(d.Removed) > 0:
		fmt.Fprintf(&b, "feed %s: %d new, %d updated, %d removed\n", date, len(d.Added), len(d.Updated), len(d.Removed))
	case len(d.ProductsMeta) > 0:
		fmt.Fprintf(&b, "feed %s: product mappings updated\n", date)
	case d.EPSSChanged:
		fmt.Fprintf(&b, "feed %s: EPSS scores updated\n", date)
	default:
		fmt.Fprintf(&b, "feed %s: updated\n", date)
	}
	if len(d.Added) > 0 {
		b.WriteString("\nNew:\n")
		for i, c := range d.Added {
			if i == 30 {
				fmt.Fprintf(&b, "- … and %d more\n", len(d.Added)-30)
				break
			}
			kev := ""
			if c.KEV {
				kev = " KEV"
			}
			fmt.Fprintf(&b, "- %s %s (%s%s)\n", c.Product, c.ID, strings.ToLower(c.Severity), kev)
		}
	}
	if len(d.ProductsMeta) > 0 {
		fmt.Fprintf(&b, "\nProducts changed: %s\n", strings.Join(d.ProductsMeta, ", "))
	}
	return b.String()
}
