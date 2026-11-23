package sources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/huseyinbabal/cvedetector/pkg/feed"
)

func TestCVSS3BaseScore(t *testing.T) {
	for vec, want := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H": 7.5,
		"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N": 6.4,
		"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	} {
		got, ok := CVSS3BaseScore(vec)
		if !ok || got != want {
			t.Errorf("%s = %v,%v want %v", vec, got, ok, want)
		}
	}
	if _, ok := CVSS3BaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"); ok {
		t.Error("v4 vectors are not supported")
	}
}

func TestEventsToRanges(t *testing.T) {
	got := eventsToRanges([]map[string]string{
		{"introduced": "0"}, {"fixed": "1.2.0"},
		{"introduced": "1.3.0"}, {"last_affected": "1.3.5"},
		{"introduced": "2.0.0"},
	})
	want := []feed.Range{{LT: "1.2.0"}, {GTE: "1.3.0", LTE: "1.3.5"}, {GTE: "2.0.0"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestConvertNVD(t *testing.T) {
	raw := `{
	 "id":"CVE-2024-7347","published":"2024-08-14T15:15:30.483","lastModified":"2024-08-20T10:00:00.000","vulnStatus":"Analyzed",
	 "descriptions":[{"lang":"en","value":"NGINX has a vulnerability in the mp4 module."}],
	 "metrics":{"cvssMetricV31":[
	   {"type":"Secondary","cvssData":{"baseScore":5.7,"vectorString":"CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H"}},
	   {"type":"Primary","cvssData":{"baseScore":4.7,"vectorString":"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H"}}]},
	 "configurations":[{"nodes":[{"negate":false,"cpeMatch":[
	   {"vulnerable":true,"criteria":"cpe:2.3:a:f5:nginx:*:*:*:*:open_source:*:*:*","versionStartIncluding":"1.5.13","versionEndExcluding":"1.26.2"},
	   {"vulnerable":true,"criteria":"cpe:2.3:a:f5:nginx:1.27.0:*:*:*:open_source:*:*:*"},
	   {"vulnerable":true,"criteria":"cpe:2.3:a:f5:nginx_plus:r30:*:*:*:*:*:*:*"},
	   {"vulnerable":false,"criteria":"cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}]}]}],
	 "references":[{"url":"https://my.f5.com/manage/s/article/K000140529"}]
	}`
	var c nvdCVE
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	v, ok := convertNVD(c, "cpe:2.3:a:f5:nginx")
	if !ok {
		t.Fatal("expected a vuln")
	}
	wantRanges := []feed.Range{{GTE: "1.5.13", LT: "1.26.2"}, {EQ: "1.27.0"}}
	if !reflect.DeepEqual(v.Affected, wantRanges) {
		t.Errorf("ranges %+v", v.Affected)
	}
	if v.CVSS != 4.7 || v.Severity != feed.SeverityMedium {
		t.Errorf("cvss %v %s, want primary 4.7 MEDIUM", v.CVSS, v.Severity)
	}
	if !v.Published.Equal(time.Date(2024, 8, 14, 15, 15, 30, 483e6, time.UTC)) {
		t.Errorf("published %v", v.Published)
	}
	if _, ok := convertNVD(c, "cpe:2.3:a:redis:redis"); ok {
		t.Error("other product must not match")
	}
}

func TestOSVFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			PageToken string `json:"page_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.PageToken == "" {
			_, _ = w.Write([]byte(`{"vulns":[{"id":"GHSA-aaaa","aliases":["CVE-2024-1111"],"summary":"bad",
			 "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
			 "affected":[{"package":{"ecosystem":"Go","name":"github.com/x/y"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.4.2"}]}]},
			             {"package":{"ecosystem":"Go","name":"github.com/other"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}],
			 "next_page_token":"p2"}`))
			return
		}
		_, _ = w.Write([]byte(`{"vulns":[{"id":"GO-2024-2","withdrawn":"2024-01-01T00:00:00Z","affected":[]},
		 {"id":"GHSA-bbbb","database_specific":{"severity":"MODERATE"},
		  "affected":[{"package":{"ecosystem":"Go","name":"github.com/x/y"},"versions":["1.0.0"]}]}]}`))
	}))
	defer srv.Close()

	o := &OSV{Client: NewClient(), BaseURL: srv.URL}
	vs, err := o.Fetch(context.Background(), "Go", "github.com/x/y")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 2 {
		t.Fatalf("got %d vulns: %+v", len(vs), vs)
	}
	if vs[0].ID != "CVE-2024-1111" || vs[0].Aliases[0] != "GHSA-aaaa" || vs[0].CVSS != 7.5 || vs[0].Severity != feed.SeverityHigh {
		t.Errorf("first: %+v", vs[0])
	}
	if !reflect.DeepEqual(vs[0].Affected, []feed.Range{{LT: "1.4.2"}}) {
		t.Errorf("first ranges: %+v", vs[0].Affected)
	}
	if vs[1].ID != "GHSA-bbbb" || vs[1].Severity != feed.SeverityMedium || vs[1].Affected[0].EQ != "1.0.0" {
		t.Errorf("second: %+v", vs[1])
	}
}

func TestTruncateCleansAndKeepsRunes(t *testing.T) {
	// No-break spaces and newlines become plain spaces.
	if got := truncate("When multiple server blocks\n are", 100); got != "When multiple server blocks are" {
		t.Errorf("clean: %q", got)
	}
	// The cut never lands inside a multi-byte rune.
	got := truncate(strings.Repeat("é", 10), 5)
	if !utf8.ValidString(got) || got != "éé…" {
		t.Errorf("cut: %q", got)
	}
}
