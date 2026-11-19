package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/huseyinbabal/cvedetector/pkg/feed"
)

const nvdURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// NVD queries the NVD CVE API 2.0 by CPE.
type NVD struct {
	Client  *Client
	APIKey  string
	BaseURL string // override for tests

	mu   sync.Mutex
	last time.Time
}

// interval respects NVD's public rate limits (5 req/30s, or 50 with a key).
func (n *NVD) interval() time.Duration {
	if n.APIKey != "" {
		return 700 * time.Millisecond
	}
	return 6500 * time.Millisecond
}

func (n *NVD) wait(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if d := time.Until(n.last.Add(n.interval())); d > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
	}
	n.last = time.Now()
	return nil
}

// Fetch returns vulnerabilities whose configurations mark cpePrefix vulnerable.
func (n *NVD) Fetch(ctx context.Context, cpePrefix string) ([]feed.Vuln, error) {
	base := n.BaseURL
	if base == "" {
		base = nvdURL
	}
	var out []feed.Vuln
	for start := 0; ; {
		if err := n.wait(ctx); err != nil {
			return nil, err
		}
		q := url.Values{}
		q.Set("virtualMatchString", cpePrefix)
		q.Set("resultsPerPage", "2000")
		q.Set("startIndex", strconv.Itoa(start))
		u := base + "?" + q.Encode() + "&noRejected"
		body, err := n.Client.Do(ctx, func() (*http.Request, error) {
			req, err := http.NewRequest(http.MethodGet, u, nil)
			if err == nil && n.APIKey != "" {
				req.Header.Set("apiKey", n.APIKey)
			}
			return req, err
		})
		if err != nil {
			return nil, fmt.Errorf("nvd %s: %w", cpePrefix, err)
		}
		var page nvdResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("nvd %s: decode: %w", cpePrefix, err)
		}
		for _, item := range page.Vulnerabilities {
			if v, ok := convertNVD(item.CVE, cpePrefix); ok {
				out = append(out, v)
			}
		}
		start += len(page.Vulnerabilities)
		if len(page.Vulnerabilities) == 0 || start >= page.TotalResults {
			return out, nil
		}
	}
}

type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V40 []nvdMetric `json:"cvssMetricV40"`
		V31 []nvdMetric `json:"cvssMetricV31"`
		V30 []nvdMetric `json:"cvssMetricV30"`
		V2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Configurations []struct {
		Nodes []struct {
			Negate   bool `json:"negate"`
			CPEMatch []struct {
				Vulnerable            bool   `json:"vulnerable"`
				Criteria              string `json:"criteria"`
				VersionStartIncluding string `json:"versionStartIncluding"`
				VersionStartExcluding string `json:"versionStartExcluding"`
				VersionEndIncluding   string `json:"versionEndIncluding"`
				VersionEndExcluding   string `json:"versionEndExcluding"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

type nvdMetric struct {
	Type     string `json:"type"`
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}

func convertNVD(c nvdCVE, cpePrefix string) (feed.Vuln, bool) {
	if c.VulnStatus == "Rejected" {
		return feed.Vuln{}, false
	}
	want := strings.Split(cpePrefix, ":") // cpe 2.3 part vendor product
	v := feed.Vuln{ID: c.ID, Sources: []string{"nvd"}}
	for _, cfg := range c.Configurations {
		for _, node := range cfg.Nodes {
			if node.Negate {
				continue
			}
			for _, m := range node.CPEMatch {
				f := splitCPE(m.Criteria)
				if !m.Vulnerable || len(f) < 7 || f[2] != want[2] || !strings.EqualFold(f[3], want[3]) || !strings.EqualFold(f[4], want[4]) {
					continue
				}
				r := feed.Range{
					GTE: m.VersionStartIncluding, GT: m.VersionStartExcluding,
					LTE: m.VersionEndIncluding, LT: m.VersionEndExcluding,
				}
				ver, upd := f[5], f[6]
				switch {
				case ver == "-": // "not applicable": no version to match
					continue
				case ver != "*" && r == (feed.Range{}):
					if upd != "*" && upd != "-" && upd != "" {
						ver += "-" + upd
					}
					r.EQ = ver
				}
				v.Affected = append(v.Affected, r)
			}
		}
	}
	if len(v.Affected) == 0 {
		return feed.Vuln{}, false
	}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			v.Summary = truncate(d.Value, 600)
			break
		}
	}
	if m, ok := pickMetric(c.Metrics.V31, c.Metrics.V30, c.Metrics.V40, c.Metrics.V2); ok {
		v.CVSS = m.CVSSData.BaseScore
		v.CVSSVector = m.CVSSData.VectorString
	}
	v.Severity = feed.SeverityFromScore(v.CVSS)
	v.Published = parseNVDTime(c.Published)
	v.Modified = parseNVDTime(c.LastModified)
	for i, r := range c.References {
		if i == 5 {
			break
		}
		v.References = append(v.References, r.URL)
	}
	v.References = append([]string{"https://nvd.nist.gov/vuln/detail/" + c.ID}, v.References...)
	return v, true
}

// pickMetric returns the first metric of the first non-empty list, preferring
// the "Primary" (NVD-assigned) score over CNA scores.
func pickMetric(lists ...[]nvdMetric) (nvdMetric, bool) {
	for _, l := range lists {
		for _, m := range l {
			if m.Type == "Primary" {
				return m, true
			}
		}
		if len(l) > 0 {
			return l[0], true
		}
	}
	return nvdMetric{}, false
}

// splitCPE splits a CPE 2.3 formatted string on unescaped colons.
func splitCPE(s string) []string {
	var out []string
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			i++
			b.WriteByte(s[i])
		case s[i] == ':':
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteByte(s[i])
		}
	}
	return append(out, b.String())
}

func parseNVDTime(s string) time.Time {
	for _, layout := range []string{"2006-01-02T15:04:05.000", "2006-01-02T15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return strings.TrimSpace(s[:n]) + "…"
}

const nvdCPEURL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

// SearchCPEProducts returns the distinct "cpe:2.3:a:<vendor>:<product>"
// prefixes of application CPEs whose product name equals one of names.
func (n *NVD) SearchCPEProducts(ctx context.Context, keyword string, names []string) ([]string, error) {
	want := map[string]bool{}
	for _, nm := range names {
		want[strings.ToLower(nm)] = true
	}
	set := map[string]bool{}
	for start := 0; ; {
		if err := n.wait(ctx); err != nil {
			return nil, err
		}
		q := url.Values{}
		q.Set("keywordSearch", keyword)
		q.Set("resultsPerPage", "10000")
		q.Set("startIndex", strconv.Itoa(start))
		u := nvdCPEURL + "?" + q.Encode()
		body, err := n.Client.Do(ctx, func() (*http.Request, error) {
			req, err := http.NewRequest(http.MethodGet, u, nil)
			if err == nil && n.APIKey != "" {
				req.Header.Set("apiKey", n.APIKey)
			}
			return req, err
		})
		if err != nil {
			return nil, fmt.Errorf("nvd cpe search %q: %w", keyword, err)
		}
		var page struct {
			TotalResults int `json:"totalResults"`
			Products     []struct {
				CPE struct {
					Name       string `json:"cpeName"`
					Deprecated bool   `json:"deprecated"`
				} `json:"cpe"`
			} `json:"products"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("nvd cpe search %q: decode: %w", keyword, err)
		}
		for _, p := range page.Products {
			f := splitCPE(p.CPE.Name)
			if p.CPE.Deprecated || len(f) < 5 || f[2] != "a" || !want[strings.ToLower(f[4])] {
				continue
			}
			set["cpe:2.3:a:"+f[3]+":"+f[4]] = true
		}
		start += len(page.Products)
		if len(page.Products) == 0 || start >= page.TotalResults || start >= 50000 {
			break
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out, nil
}

// CountCVEs returns how many CVEs mark a CPE prefix vulnerable.
func (n *NVD) CountCVEs(ctx context.Context, cpePrefix string) (int, error) {
	if err := n.wait(ctx); err != nil {
		return 0, err
	}
	u := nvdURL + "?" + url.Values{"virtualMatchString": {cpePrefix}, "resultsPerPage": {"1"}}.Encode() + "&noRejected"
	body, err := n.Client.Do(ctx, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err == nil && n.APIKey != "" {
			req.Header.Set("apiKey", n.APIKey)
		}
		return req, err
	})
	if err != nil {
		return 0, fmt.Errorf("nvd count %s: %w", cpePrefix, err)
	}
	var page struct {
		TotalResults int `json:"totalResults"`
	}
	err = json.Unmarshal(body, &page)
	return page.TotalResults, err
}
