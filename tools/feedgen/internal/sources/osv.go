package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/huseyinbabal/cvedetector/pkg/feed"
)

const osvURL = "https://api.osv.dev/v1/query"

// OSV queries api.osv.dev by package.
type OSV struct {
	Client  *Client
	BaseURL string
}

// Fetch returns vulnerabilities of a package in an OSV ecosystem.
func (o *OSV) Fetch(ctx context.Context, ecosystem, pkg string) ([]feed.Vuln, error) {
	base := o.BaseURL
	if base == "" {
		base = osvURL
	}
	var out []feed.Vuln
	token := ""
	for {
		reqBody, _ := json.Marshal(map[string]any{
			"package":    map[string]string{"name": pkg, "ecosystem": ecosystem},
			"page_token": token,
		})
		body, err := o.Client.Do(ctx, func() (*http.Request, error) {
			req, err := http.NewRequest(http.MethodPost, base, bytes.NewReader(reqBody))
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
			}
			return req, err
		})
		if err != nil {
			return nil, fmt.Errorf("osv %s/%s: %w", ecosystem, pkg, err)
		}
		var page struct {
			Vulns         []osvVuln `json:"vulns"`
			NextPageToken string    `json:"next_page_token"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("osv %s/%s: decode: %w", ecosystem, pkg, err)
		}
		for _, v := range page.Vulns {
			if fv, ok := convertOSV(v, ecosystem, pkg); ok {
				out = append(out, fv)
			}
		}
		if page.NextPageToken == "" {
			return out, nil
		}
		token = page.NextPageToken
	}
}

type osvVuln struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Published string   `json:"published"`
	Modified  string   `json:"modified"`
	Withdrawn string   `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

func convertOSV(o osvVuln, ecosystem, pkg string) (feed.Vuln, bool) {
	if o.Withdrawn != "" {
		return feed.Vuln{}, false
	}
	v := feed.Vuln{ID: o.ID, Sources: []string{"osv"}}
	for _, a := range o.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			v.ID = a
			break
		}
	}
	for _, a := range append([]string{o.ID}, o.Aliases...) {
		if a != v.ID {
			v.Aliases = append(v.Aliases, a)
		}
	}
	for _, a := range o.Affected {
		if a.Package.Name != pkg || !strings.EqualFold(a.Package.Ecosystem, ecosystem) {
			continue
		}
		hasRange := false
		for _, r := range a.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			hasRange = true
			v.Affected = append(v.Affected, eventsToRanges(r.Events)...)
		}
		if !hasRange {
			for _, ver := range a.Versions {
				v.Affected = append(v.Affected, feed.Range{EQ: ver})
			}
		}
	}
	if len(v.Affected) == 0 {
		return feed.Vuln{}, false
	}
	v.Summary = o.Summary
	if v.Summary == "" {
		v.Summary = truncate(o.Details, 600)
	}
	for _, s := range o.Severity {
		if score, ok := CVSS3BaseScore(s.Score); ok {
			v.CVSS, v.CVSSVector = score, s.Score
			break
		}
	}
	v.Severity = feed.SeverityFromScore(v.CVSS)
	if v.CVSS == 0 {
		v.Severity = normalizeSeverity(o.DatabaseSpecific.Severity)
	}
	v.Published, _ = time.Parse(time.RFC3339, o.Published)
	v.Modified, _ = time.Parse(time.RFC3339, o.Modified)
	v.References = append(v.References, "https://osv.dev/vulnerability/"+o.ID)
	for i, r := range o.References {
		if i == 5 {
			break
		}
		v.References = append(v.References, r.URL)
	}
	return v, true
}

// eventsToRanges converts OSV range events (introduced/fixed/last_affected)
// into closed ranges. "introduced: 0" means no lower bound.
func eventsToRanges(events []map[string]string) []feed.Range {
	var out []feed.Range
	var cur *feed.Range
	for _, e := range events {
		if intro, ok := e["introduced"]; ok {
			if cur != nil { // open range followed by a new introduction
				out = append(out, *cur)
			}
			cur = &feed.Range{}
			if intro != "0" {
				cur.GTE = intro
			}
			continue
		}
		if cur == nil {
			continue
		}
		if f, ok := e["fixed"]; ok {
			cur.LT = f
		} else if l, ok := e["last_affected"]; ok {
			cur.LTE = l
		} else if l, ok := e["limit"]; ok {
			cur.LT = l
		} else {
			continue
		}
		out = append(out, *cur)
		cur = nil
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

func normalizeSeverity(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return feed.SeverityCritical
	case "HIGH":
		return feed.SeverityHigh
	case "MODERATE", "MEDIUM":
		return feed.SeverityMedium
	case "LOW":
		return feed.SeverityLow
	}
	return feed.SeverityUnknown
}
