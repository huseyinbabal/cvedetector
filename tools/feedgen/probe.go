package main

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/huseyinbabal/cvedetector/pkg/feed"
	"github.com/huseyinbabal/cvedetector/tools/feedgen/internal/build"
	"github.com/huseyinbabal/cvedetector/tools/feedgen/internal/config"
	"github.com/huseyinbabal/cvedetector/tools/feedgen/internal/sources"
)

// probe checks that each product's sources return data and shows what its
// test tags would match. It writes a Markdown report (for PR summaries) and
// returns an error when any source returns nothing: almost always a wrong CPE
// or package name.
func probe(ctx context.Context, w io.Writer, cfg *config.Config, ids []string, nvd *sources.NVD, osv *sources.OSV) error {
	byID := map[string]config.Product{}
	for _, p := range cfg.Products {
		byID[p.ID] = p
	}
	var failed []string
	fmt.Fprintln(w, "## Product check")
	fmt.Fprintln(w)
	for _, id := range ids {
		p, ok := byID[id]
		if !ok {
			fmt.Fprintf(w, "### ❌ `%s`\n\nUnknown product id.\n\n", id)
			failed = append(failed, id)
			continue
		}
		var lists [][]feed.Vuln
		var rows []string
		ok = true
		if p.NVD != nil {
			for _, cpe := range p.NVD.CPEs {
				vs, err := nvd.Fetch(ctx, cpe)
				rows = append(rows, sourceRow("NVD", cpe, vs, err))
				if err != nil || len(vs) == 0 {
					ok = false
				}
				lists = append(lists, vs)
			}
		}
		for _, o := range p.OSV {
			vs, err := osv.Fetch(ctx, o.Ecosystem, o.Package)
			rows = append(rows, sourceRow("OSV", o.Ecosystem+"/"+o.Package, vs, err))
			if err != nil || len(vs) == 0 {
				ok = false
			}
			lists = append(lists, vs)
		}
		vulns := build.Merge(lists...)
		mark := "✅"
		if !ok {
			mark = "❌"
			failed = append(failed, id)
		}
		fmt.Fprintf(w, "### %s `%s` (%s): %d vulnerabilities\n\n", mark, p.ID, p.Name, len(vulns))
		fmt.Fprintf(w, "Images: %s\n\n", "`"+strings.Join(p.Images, "`, `")+"`")
		fmt.Fprintln(w, "| Source | Query | Vulnerabilities | Newest |")
		fmt.Fprintln(w, "|---|---|---|---|")
		for _, r := range rows {
			fmt.Fprintln(w, r)
		}
		fmt.Fprintln(w)

		tags := make([]string, 0, len(p.TestTags))
		for t := range p.TestTags {
			tags = append(tags, t)
		}
		sort.Strings(tags)
		fmt.Fprintln(w, "| Test tag | Version | Affected by | Highest |")
		fmt.Fprintln(w, "|---|---|---|---|")
		for _, t := range tags {
			v := p.TestTags[t]
			if v == "" {
				fmt.Fprintf(w, "| `%s` | none | – | – |\n", t)
				continue
			}
			n, top := 0, ""
			for _, vu := range vulns {
				if a, _ := vu.Match(v); a {
					n++
					if feed.SeverityRank(vu.Severity) > feed.SeverityRank(top) {
						top = vu.Severity
					}
				}
			}
			fmt.Fprintf(w, "| `%s` | %s | %d | %s |\n", t, v, n, strings.ToLower(top))
		}
		fmt.Fprintln(w)
	}
	if len(failed) > 0 {
		fmt.Fprintf(w, "**%d product(s) need attention:** a source returned no vulnerabilities, which usually means a wrong CPE or package name. Look it up on https://nvd.nist.gov/products/cpe/search or https://osv.dev.\n", len(failed))
		return fmt.Errorf("sources without data: %s", strings.Join(failed, ", "))
	}
	return nil
}

func sourceRow(kind, query string, vs []feed.Vuln, err error) string {
	if err != nil {
		return fmt.Sprintf("| %s | `%s` | error: %s | |", kind, query, strings.ReplaceAll(err.Error(), "|", "/"))
	}
	newest := ""
	sort.Slice(vs, func(i, j int) bool { return vs[i].Published.After(vs[j].Published) })
	for i, v := range vs {
		if i == 3 {
			break
		}
		newest += v.ID + " "
	}
	return fmt.Sprintf("| %s | `%s` | %d | %s |", kind, query, len(vs), strings.TrimSpace(newest))
}
