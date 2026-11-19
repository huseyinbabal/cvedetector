// Package matcher maps image references to feed products and versions, and
// finds the vulnerabilities whose affected ranges contain that version. It is
// pure: no I/O.
package matcher

import (
	"path"
	"regexp"
	"strings"

	"github.com/huseyinbabal/cvedetector/pkg/feed"
)

// Match status of an image.
const (
	StatusMatched     = "matched"     // product known, full version in the tag
	StatusApproximate = "approximate" // floating tag such as "1.27"; compared as 1.27.0
	StatusNoVersion   = "no-version"  // product known, tag has no version ("latest", digest only)
	StatusUnknown     = "unknown"     // repository not in the feed
)

// Finding is one vulnerability affecting an image.
type Finding struct {
	VulnID  string
	FixedIn string
}

// Result of matching one image.
type Result struct {
	Product  string
	Version  string
	Status   string
	Findings []Finding
}

type product struct {
	feed.Product
	re    *regexp.Regexp
	vulns []feed.Vuln
}

// Catalog is an immutable, indexed view of the feed.
type Catalog struct {
	exact map[string]*product
	globs []globEntry
}

type globEntry struct {
	pattern string
	p       *product
}

// NewCatalog indexes products and their vulnerabilities. Products with an
// invalid version pattern are skipped.
func NewCatalog(products []feed.Product, vulns map[string][]feed.Vuln) *Catalog {
	c := &Catalog{exact: map[string]*product{}}
	for _, fp := range products {
		re, err := feed.CompileVersionPattern(fp.VersionPattern)
		if err != nil {
			continue
		}
		p := &product{Product: fp, re: re, vulns: vulns[fp.ID]}
		for _, img := range fp.Images {
			if strings.ContainsAny(img, "*?[") {
				c.globs = append(c.globs, globEntry{img, p})
			} else {
				c.exact[img] = p
			}
		}
	}
	return c
}

func (c *Catalog) lookup(repo string) *product {
	if p, ok := c.exact[repo]; ok {
		return p
	}
	for _, g := range c.globs {
		if ok, _ := path.Match(g.pattern, repo); ok {
			return g.p
		}
	}
	return nil
}

// Match resolves the product and version of repository:tag and returns the
// vulnerabilities affecting it.
func (c *Catalog) Match(repository, tag string) Result {
	p := c.lookup(repository)
	if p == nil {
		return Result{Status: StatusUnknown}
	}
	r := Result{Product: p.ID, Status: StatusNoVersion}
	m := p.re.FindStringSubmatch(tag)
	if tag == "" || m == nil {
		return r
	}
	r.Version = m[p.re.SubexpIndex("version")]
	r.Status = StatusMatched
	minSeg := p.MinSegments
	if minSeg == 0 {
		minSeg = 3
	}
	if strings.Count(r.Version, ".")+1 < minSeg {
		r.Status = StatusApproximate
	}
	for i := range p.vulns {
		if affected, fixedIn := p.vulns[i].Match(r.Version); affected {
			r.Findings = append(r.Findings, Finding{VulnID: p.vulns[i].ID, FixedIn: fixedIn})
		}
	}
	return r
}
