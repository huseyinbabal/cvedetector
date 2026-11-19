// Package feed defines the published CVE feed format shared by feedgen (producer)
// and the agent (consumer).
//
// Layout under the feed base URL:
//
//	v1/index.json              Index: products, image mappings, shard checksums
//	v1/products/<id>.json      Shard: vulnerabilities of one product
//	v1/epss.json               EPSS scores (changes daily; kept apart so shards
//	                           only change when a vulnerability really changes)
//
// Shards are deterministic (no timestamps, sorted), so an unchanged feed
// produces byte-identical files and nothing to commit.
package feed

import (
	"regexp"
	"time"

	"github.com/huseyinbabal/cvedetector/pkg/version"
)

// SchemaVersion is the major format version. Consumers reject other values.
const SchemaVersion = 1

// DefaultVersionPattern extracts a version from tags like "1.27.3",
// "v2.13.0", "7.2.4-debian-12-r5" or "16.4-alpine".
const DefaultVersionPattern = `^v?(?P<version>\d+(?:\.\d+){0,3})`

// Index is v1/index.json.
type Index struct {
	SchemaVersion int       `json:"schemaVersion"`
	GeneratedAt   time.Time `json:"generatedAt"` // last time the content changed
	Products      []Product `json:"products"`
	EPSS          *File     `json:"epss,omitempty"`
}

// File references a feed file by path (relative to v1/) and checksum.
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// EPSSFile is v1/epss.json: CVE id -> exploit prediction score (0..1).
type EPSSFile struct {
	SchemaVersion int                `json:"schemaVersion"`
	Scores        map[string]float64 `json:"scores"`
}

// Product maps container images to a piece of software with a CVE history.
type Product struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Images are normalized repositories ("docker.io/library/nginx"); path.Match
	// globs are allowed ("docker.io/bitnami/nginx*").
	Images []string `json:"images"`
	// VersionPattern is a regexp with a named group "version" applied to the tag.
	VersionPattern string `json:"versionPattern,omitempty"`
	// MinSegments is how many numeric segments a full version has (3 for
	// "1.27.3", 2 for PostgreSQL's "16.4"). Shorter tags are floating tags.
	MinSegments int    `json:"minSegments,omitempty"`
	Shard       string `json:"shard"`  // path relative to v1/
	SHA256      string `json:"sha256"` // hex sha256 of the shard file
	VulnCount   int    `json:"vulnCount"`
}

// Shard is v1/products/<id>.json.
type Shard struct {
	SchemaVersion int    `json:"schemaVersion"`
	Product       string `json:"product"`
	Vulns         []Vuln `json:"vulns"`
}

// Severity levels, ordered by SeverityRank.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityUnknown  = "UNKNOWN"
)

// SeverityRank orders severities; higher is worse.
func SeverityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

// SeverityFromScore maps a CVSS base score to a qualitative rating.
func SeverityFromScore(score float64) string {
	switch {
	case score >= 9:
		return SeverityCritical
	case score >= 7:
		return SeverityHigh
	case score >= 4:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	}
	return SeverityUnknown
}

// Vuln is one vulnerability affecting a product.
type Vuln struct {
	ID         string    `json:"id"` // CVE id when one exists, else the source id
	Aliases    []string  `json:"aliases,omitempty"`
	Summary    string    `json:"summary,omitempty"`
	Severity   string    `json:"severity"`
	CVSS       float64   `json:"cvss,omitempty"`
	CVSSVector string    `json:"cvssVector,omitempty"`
	EPSS       float64   `json:"epss,omitempty"` // filled by consumers from epss.json
	KEV        bool      `json:"kev,omitempty"`  // in CISA Known Exploited Vulnerabilities
	Published  time.Time `json:"published,omitzero"`
	Modified   time.Time `json:"modified,omitzero"`
	References []string  `json:"references,omitempty"`
	Sources    []string  `json:"sources,omitempty"` // "nvd", "osv"
	Affected   []Range   `json:"affected"`
}

// Range is a set of affected versions. All set bounds must hold; an empty
// Range means every version is affected.
type Range struct {
	EQ  string `json:"eq,omitempty"`
	GTE string `json:"gte,omitempty"`
	GT  string `json:"gt,omitempty"`
	LT  string `json:"lt,omitempty"`
	LTE string `json:"lte,omitempty"`
}

// Contains reports whether v falls into r.
func (r Range) Contains(v string) bool {
	if r.EQ != "" {
		return version.Compare(v, r.EQ) == 0
	}
	if r.GTE != "" && version.Compare(v, r.GTE) < 0 {
		return false
	}
	if r.GT != "" && version.Compare(v, r.GT) <= 0 {
		return false
	}
	if r.LT != "" && version.Compare(v, r.LT) >= 0 {
		return false
	}
	if r.LTE != "" && version.Compare(v, r.LTE) > 0 {
		return false
	}
	return true
}

// Match reports whether v is affected and, if so, the version that fixes it
// (empty when the matching range has no upper exclusive bound).
func (vu Vuln) Match(v string) (affected bool, fixedIn string) {
	for _, r := range vu.Affected {
		if r.Contains(v) {
			if !affected || (r.LT != "" && (fixedIn == "" || version.Compare(r.LT, fixedIn) < 0)) {
				fixedIn = r.LT
			}
			affected = true
		}
	}
	return affected, fixedIn
}

// CompileVersionPattern compiles p (or the default) and checks it has a
// "version" group.
func CompileVersionPattern(p string) (*regexp.Regexp, error) {
	if p == "" {
		p = DefaultVersionPattern
	}
	re, err := regexp.Compile(p)
	if err != nil {
		return nil, err
	}
	if re.SubexpIndex("version") < 0 {
		return nil, errNoVersionGroup
	}
	return re, nil
}

type feedError string

func (e feedError) Error() string { return string(e) }

const errNoVersionGroup = feedError(`version pattern must contain a named group "version"`)
