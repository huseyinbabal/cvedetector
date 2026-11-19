package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	kevURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	epssURL = "https://api.first.org/data/v1/epss"
)

// KEV returns the set of CVE ids in CISA's Known Exploited Vulnerabilities catalog.
func KEV(ctx context.Context, c *Client) (map[string]bool, error) {
	body, err := c.Do(ctx, func() (*http.Request, error) { return http.NewRequest(http.MethodGet, kevURL, nil) })
	if err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	var doc struct {
		Vulnerabilities []struct {
			CVEID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("kev: decode: %w", err)
	}
	set := make(map[string]bool, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		set[v.CVEID] = true
	}
	return set, nil
}

// EPSS returns exploit prediction scores (0..1) for the given CVE ids.
func EPSS(ctx context.Context, c *Client, cves []string) (map[string]float64, error) {
	scores := map[string]float64{}
	const batch = 100
	for i := 0; i < len(cves); i += batch {
		chunk := cves[i:min(i+batch, len(cves))]
		u := epssURL + "?" + url.Values{"cve": {strings.Join(chunk, ",")}, "limit": {strconv.Itoa(batch)}}.Encode()
		body, err := c.Do(ctx, func() (*http.Request, error) { return http.NewRequest(http.MethodGet, u, nil) })
		if err != nil {
			return nil, fmt.Errorf("epss: %w", err)
		}
		var doc struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, fmt.Errorf("epss: decode: %w", err)
		}
		for _, d := range doc.Data {
			if f, err := strconv.ParseFloat(d.EPSS, 64); err == nil {
				scores[d.CVE] = f
			}
		}
	}
	return scores, nil
}
