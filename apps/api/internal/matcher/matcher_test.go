package matcher

import (
	"testing"

	"github.com/huseyinbabal/cvedetector/pkg/feed"
)

func catalog() *Catalog {
	return NewCatalog(
		[]feed.Product{
			{ID: "nginx", Images: []string{"docker.io/library/nginx", "docker.io/bitnami/nginx*"}},
			{ID: "postgresql", Images: []string{"docker.io/library/postgres"}, MinSegments: 2},
			{ID: "envoy", Images: []string{"docker.io/envoyproxy/envoy"}, VersionPattern: `^(?:distroless-)?v?(?P<version>\d+(?:\.\d+){0,3})`},
		},
		map[string][]feed.Vuln{
			"nginx": {
				{ID: "CVE-A", Affected: []feed.Range{{LT: "1.27.2"}}},
				{ID: "CVE-B", Affected: []feed.Range{{GTE: "1.27.0", LTE: "1.27.3"}}},
				{ID: "CVE-C", Affected: []feed.Range{{LT: "1.20.0"}}},
			},
			"postgresql": {{ID: "CVE-P", Affected: []feed.Range{{GTE: "16.0", LT: "16.5"}}}},
		},
	)
}

func TestMatch(t *testing.T) {
	c := catalog()
	tests := []struct {
		repo, tag, status, version string
		findings                   []Finding
	}{
		{"docker.io/library/nginx", "1.27.1", StatusMatched, "1.27.1", []Finding{{"CVE-A", "1.27.2"}, {"CVE-B", ""}}},
		{"docker.io/library/nginx", "1.27.3", StatusMatched, "1.27.3", []Finding{{"CVE-B", ""}}},
		{"docker.io/bitnami/nginx-ingress", "1.27", StatusApproximate, "1.27", []Finding{{"CVE-A", "1.27.2"}, {"CVE-B", ""}}},
		{"docker.io/library/nginx", "latest", StatusNoVersion, "", nil},
		{"docker.io/library/nginx", "", StatusNoVersion, "", nil},
		{"docker.io/library/postgres", "16.4-alpine", StatusMatched, "16.4", []Finding{{"CVE-P", "16.5"}}},
		{"docker.io/envoyproxy/envoy", "distroless-v1.40.2", StatusMatched, "1.40.2", nil},
		{"ghcr.io/acme/app", "1.0.0", StatusUnknown, "", nil},
	}
	for _, tt := range tests {
		r := c.Match(tt.repo, tt.tag)
		if r.Status != tt.status || r.Version != tt.version || len(r.Findings) != len(tt.findings) {
			t.Errorf("%s:%s = %+v", tt.repo, tt.tag, r)
			continue
		}
		for i := range tt.findings {
			if r.Findings[i] != tt.findings[i] {
				t.Errorf("%s:%s finding %d = %+v want %+v", tt.repo, tt.tag, i, r.Findings[i], tt.findings[i])
			}
		}
	}
}
