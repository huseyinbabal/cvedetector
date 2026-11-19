// Command discover proposes new product mappings for the feed.
//
// It collects candidate images from what people actually run (images used by
// the most-starred Helm charts on Artifact Hub, Docker Official Images and
// Bitnami images by pulls), skips those already mapped, keeps images whose
// tags carry versions, and looks the image name up in NVD's CPE dictionary.
// Confident matches (exact product name, CVEs on record, one vendor) become
// product files; everything else goes into the report for a human. The output
// is meant for a pull request, never for main directly.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/huseyinbabal/cvedetector/pkg/feed"
	"github.com/huseyinbabal/cvedetector/pkg/imageref"
	"github.com/huseyinbabal/cvedetector/pkg/version"
	"github.com/huseyinbabal/cvedetector/tools/feedgen/internal/config"
	"github.com/huseyinbabal/cvedetector/tools/feedgen/internal/registry"
	"github.com/huseyinbabal/cvedetector/tools/feedgen/internal/sources"
)

type candidate struct {
	Repo    string
	Charts  []string // Artifact Hub charts using it
	Catalog string   // "official" or "bitnami" when listed there
}

type opts struct {
	products, report, cache string
	charts, max             int
	dryRun                  bool
}

func main() {
	var o opts
	flag.StringVar(&o.products, "products", "feed/products", "product files directory (new files are written here)")
	flag.StringVar(&o.report, "report", "", "write a Markdown report to this file")
	flag.StringVar(&o.cache, "cache", ".discover-cache.json", "NVD lookup cache (resumable runs)")
	flag.IntVar(&o.charts, "charts", 300, "how many top Artifact Hub charts to inspect")
	flag.IntVar(&o.max, "max", 400, "maximum candidates to look up in NVD")
	flag.BoolVar(&o.dryRun, "dry-run", false, "report only, write no product files")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, log, o); err != nil {
		log.Error("discover failed", "err", err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------- candidates

var httpc = &http.Client{Timeout: 30 * time.Second}

func getJSON(ctx context.Context, u string, out any) error {
	for attempt := range 4 {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		req.Header.Set("User-Agent", "cvedetector-discover/1")
		resp, err := httpc.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			resp.Body.Close()
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("GET %s: %s", u, resp.Status)
		}
		return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out)
	}
	return fmt.Errorf("GET %s: giving up", u)
}

// artifactHubImages maps repositories to the charts that use them.
func artifactHubImages(ctx context.Context, log *slog.Logger, n int) (map[string][]string, error) {
	type pkg struct {
		Name       string `json:"name"`
		Repository struct {
			Name string `json:"name"`
		} `json:"repository"`
	}
	var pkgs []pkg
	for offset := 0; offset < n; offset += 60 {
		var page struct {
			Packages []pkg `json:"packages"`
		}
		u := fmt.Sprintf("https://artifacthub.io/api/v1/packages/search?kind=0&sort=stars&limit=60&offset=%d", offset)
		if err := getJSON(ctx, u, &page); err != nil {
			return nil, err
		}
		if len(page.Packages) == 0 {
			break
		}
		pkgs = append(pkgs, page.Packages...)
	}
	if len(pkgs) > n {
		pkgs = pkgs[:n]
	}
	out := map[string][]string{}
	var mu sync.Mutex
	work := make(chan pkg)
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range work {
				var d struct {
					Images []struct {
						Image string `json:"image"`
					} `json:"containers_images"`
				}
				u := "https://artifacthub.io/api/v1/packages/helm/" + url.PathEscape(p.Repository.Name) + "/" + url.PathEscape(p.Name)
				if err := getJSON(ctx, u, &d); err != nil {
					log.Debug("chart detail", "chart", p.Repository.Name+"/"+p.Name, "err", err)
					continue
				}
				mu.Lock()
				for _, im := range d.Images {
					repo := imageref.Parse(im.Image).Repository
					chart := p.Repository.Name + "/" + p.Name
					if !contains(out[repo], chart) {
						out[repo] = append(out[repo], chart)
					}
				}
				mu.Unlock()
			}
		}()
	}
	for _, p := range pkgs {
		work <- p
	}
	close(work)
	wg.Wait()
	log.Info("artifact hub", "charts", len(pkgs), "images", len(out))
	return out, nil
}

// githubDir lists entry names of a directory in a public GitHub repository
// (uses GITHUB_TOKEN when set, for the higher rate limit).
func githubDir(ctx context.Context, repo, dir string) ([]string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+repo+"/contents/"+dir, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "cvedetector-discover/1")
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github %s/%s: %s", repo, dir, resp.Status)
	}
	var entries []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !strings.HasPrefix(e.Name, ".") {
			out = append(out, e.Name)
		}
	}
	return out, nil
}

// catalogImages returns Docker Official Images and Bitnami images.
func catalogImages(ctx context.Context, log *slog.Logger) map[string]string {
	out := map[string]string{}
	for _, src := range []struct{ repo, dir, prefix, label string }{
		{"docker-library/official-images", "library", "docker.io/library/", "official"},
		{"bitnami/containers", "bitnami", "docker.io/bitnami/", "bitnami"},
	} {
		names, err := githubDir(ctx, src.repo, src.dir)
		if err != nil {
			log.Warn("catalog listing", "source", src.repo, "err", err)
			continue
		}
		for _, n := range names {
			out[src.prefix+n] = src.label
		}
		log.Info("catalog", "source", src.label, "images", len(names))
	}
	return out
}

// ---------------------------------------------------------------- NVD cache

type nvdCache struct {
	mu     sync.Mutex
	path   string
	Search map[string][]string `json:"search"` // keyword -> cpe prefixes
	Count  map[string]int      `json:"count"`  // cpe prefix -> CVE count
	Majors map[string][]string `json:"majors"` // cpe prefix -> major versions named in affected ranges
}

func loadCache(p string) *nvdCache {
	c := &nvdCache{path: p, Search: map[string][]string{}, Count: map[string]int{}, Majors: map[string][]string{}}
	if b, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(b, c)
	}
	if c.Majors == nil {
		c.Majors = map[string][]string{}
	}
	return c
}

func (c *nvdCache) save() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.path == "" {
		return
	}
	b, _ := json.MarshalIndent(c, "", " ")
	_ = os.WriteFile(c.path, b, 0o644)
}

func (c *nvdCache) search(ctx context.Context, nvd *sources.NVD, keyword string, names []string) ([]string, error) {
	key := keyword + "|" + strings.Join(names, ",")
	if v, ok := c.Search[key]; ok {
		return v, nil
	}
	v, err := nvd.SearchCPEProducts(ctx, keyword, names)
	if err != nil {
		return nil, err
	}
	c.Search[key] = v
	c.save()
	return v, nil
}

// cves fetches a CPE's vulnerabilities once and caches their count and the
// major versions their ranges mention.
func (c *nvdCache) cves(ctx context.Context, nvd *sources.NVD, cpe string) (int, []string, error) {
	if n, ok := c.Count[cpe]; ok {
		if m, ok := c.Majors[cpe]; ok {
			return n, m, nil
		}
	}
	vs, err := nvd.Fetch(ctx, cpe)
	if err != nil {
		return 0, nil, err
	}
	set := map[string]bool{}
	for _, v := range vs {
		for _, r := range v.Affected {
			for _, b := range []string{r.EQ, r.GTE, r.GT, r.LT, r.LTE} {
				if m := majorOf(b); m != "" && m != "0" {
					set[m] = true
				}
			}
		}
	}
	majors := make([]string, 0, len(set))
	for m := range set {
		majors = append(majors, m)
	}
	sort.Strings(majors)
	c.Count[cpe], c.Majors[cpe] = len(vs), majors
	c.save()
	return len(vs), majors, nil
}

func majorOf(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	i := 0
	for i < len(v) && v[i] >= '0' && v[i] <= '9' {
		i++
	}
	return v[:i]
}

// plausible reports whether the image's newest version line appears in the
// product's CVE ranges: guards against same-name, different-version-line
// matches (e.g. an operator named after its product).
func plausible(examples map[string]string, majors []string) bool {
	if len(majors) == 0 {
		return true // only open-ended ranges: nothing to compare
	}
	newest := ""
	for _, v := range examples {
		if v != "" && (newest == "" || version.Compare(v, newest) > 0) {
			newest = v
		}
	}
	return contains(majors, majorOf(newest))
}

// ---------------------------------------------------------------- matching

// Names too generic to identify a product.
var stop = map[string]bool{
	"app": true, "server": true, "web": true, "api": true, "operator": true, "controller": true, "proxy": true,
	"agent": true, "exporter": true, "worker": true, "cli": true, "init": true, "sidecar": true, "base": true,
	"runtime": true, "core": true, "manager": true, "webhook": true, "kubectl": true, "os-shell": true,
	"bitnami-shell": true, "minideb": true, "busybox": false, "alpine": true, "ubuntu": true, "debian": true,
	"centos": true, "fedora": true, "scratch": true, "pause": true, "curl": false, "git": false, "jq": true,
	"oraclelinux": true, "amazonlinux": true, "almalinux": true, "rockylinux": true, "photon": true, "clearlinux": true,
	"hello-world": true, "dashboard": true, "frontend": true, "backend": true, "ui": true, "db": true, "cache": true,
}

// Suffixes that don't change what the version refers to. Never strip things
// like -operator, -controller or -k8s: "prometheus-operator" is not Prometheus
// and has its own version line, so mapping it would produce false positives.
var suffixes = []string{"-server", "-community", "-oss", "-ce", "-ee"}

// names derives product-name spellings from a repository's last segment.
func names(repo string) (keyword string, spellings []string) {
	base := strings.ToLower(path.Base(repo))
	trimmed := base
	for _, s := range suffixes {
		trimmed = strings.TrimSuffix(trimmed, s)
	}
	set := map[string]bool{}
	for _, b := range []string{base, trimmed} {
		set[b] = true
		set[strings.ReplaceAll(b, "-", "_")] = true
		set[strings.ReplaceAll(b, "_", "-")] = true
		set[strings.NewReplacer("-", "", "_", "").Replace(b)] = true
	}
	for s := range set {
		spellings = append(spellings, s)
	}
	sort.Strings(spellings)
	return trimmed, spellings
}

// versionInfo checks tags: are they versioned, and which make good examples.
func versionInfo(tags []string) (examples map[string]string, minSegments int, ok bool) {
	re, _ := feed.CompileVersionPattern("")
	type tv struct{ tag, ver string }
	var vers []tv
	considered := 0
	maxSeg := 0
	for _, t := range tags {
		if strings.HasPrefix(t, "sha256-") || strings.HasSuffix(t, ".sig") || strings.HasSuffix(t, ".att") || strings.HasSuffix(t, ".sbom") {
			continue
		}
		considered++
		m := re.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		v := m[re.SubexpIndex("version")]
		seg := strings.Count(v, ".") + 1
		if seg < 2 || strings.Contains(t, "rc") || strings.Contains(t, "beta") || strings.Contains(t, "alpha") {
			continue
		}
		maxSeg = max(maxSeg, seg)
		vers = append(vers, tv{t, v})
	}
	if len(vers) < 3 || float64(len(vers)) < 0.3*float64(considered) {
		return nil, 0, false
	}
	sort.Slice(vers, func(i, j int) bool { return version.Compare(vers[i].ver, vers[j].ver) > 0 })
	examples = map[string]string{}
	for _, v := range vers {
		if len(examples) == 3 {
			break
		}
		examples[v.tag] = v.ver
	}
	if contains(tags, "latest") {
		examples["latest"] = ""
	}
	if maxSeg == 2 {
		minSegments = 2
	}
	return examples, minSegments, true
}

// ---------------------------------------------------------------- run

type proposal struct {
	ID, Name, CPE string
	CVEs          int
	Images        []string
	Charts        []string
	TestTags      map[string]string
	MinSegments   int
}

type extension struct {
	Product, Image, CPE string
}

type skipped struct {
	Repo, Reason string
	Charts       int
}

func run(ctx context.Context, log *slog.Logger, o opts) error {
	cfg, err := config.Load(o.products)
	if err != nil {
		return err
	}
	mapped := func(repo string) string {
		for _, p := range cfg.Products {
			for _, img := range p.Images {
				if ok, _ := path.Match(img, repo); ok || img == repo {
					return p.ID
				}
			}
		}
		return ""
	}
	byCPE := map[string]string{}
	for _, p := range cfg.Products {
		if p.NVD != nil {
			for _, c := range p.NVD.CPEs {
				byCPE[c] = p.ID
			}
		}
	}

	// 1. Candidates.
	charts, err := artifactHubImages(ctx, log, o.charts)
	if err != nil {
		return err
	}
	all := map[string]*candidate{}
	for repo, cs := range charts {
		all[repo] = &candidate{Repo: repo, Charts: cs}
	}
	for repo, label := range catalogImages(ctx, log) {
		if c := all[repo]; c != nil {
			c.Catalog = label
		} else {
			all[repo] = &candidate{Repo: repo, Catalog: label}
		}
	}
	var cands []*candidate
	alreadyMapped := 0
	for _, c := range all {
		if mapped(c.Repo) != "" {
			alreadyMapped++
			continue
		}
		if _, sp := names(c.Repo); stop[strings.ToLower(path.Base(c.Repo))] || len(sp) == 0 {
			continue
		}
		cands = append(cands, c)
	}
	sort.Slice(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if len(a.Charts) != len(b.Charts) {
			return len(a.Charts) > len(b.Charts)
		}
		if (a.Catalog == "official") != (b.Catalog == "official") {
			return a.Catalog == "official"
		}
		return a.Repo < b.Repo
	})
	log.Info("candidates", "total", len(all), "alreadyMapped", alreadyMapped, "unmapped", len(cands))

	// 2. Tags (parallel, metadata only).
	reg := registry.New()
	var skips []skipped
	var mu sync.Mutex
	type tagged struct {
		c        *candidate
		examples map[string]string
		minSeg   int
	}
	var ready []tagged
	work := make(chan *candidate)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range work {
				tags, err := reg.Tags(ctx, c.Repo)
				mu.Lock()
				if err != nil {
					skips = append(skips, skipped{c.Repo, "tags unavailable", len(c.Charts)})
				} else if ex, ms, ok := versionInfo(tags); !ok {
					skips = append(skips, skipped{c.Repo, "tags carry no version", len(c.Charts)})
				} else {
					ready = append(ready, tagged{c, ex, ms})
				}
				mu.Unlock()
			}
		}()
	}
	for i, c := range cands {
		if i >= o.max*2 {
			break
		}
		work <- c
	}
	close(work)
	wg.Wait()
	sort.Slice(ready, func(i, j int) bool {
		a, b := ready[i].c, ready[j].c
		if len(a.Charts) != len(b.Charts) {
			return len(a.Charts) > len(b.Charts)
		}
		return a.Repo < b.Repo
	})
	if len(ready) > o.max {
		ready = ready[:o.max]
	}
	log.Info("versioned candidates", "count", len(ready))

	// 3. NVD lookups (rate limited, cached).
	client := sources.NewClient()
	nvd := &sources.NVD{Client: client, APIKey: os.Getenv("NVD_API_KEY")}
	cache := loadCache(o.cache)
	proposals := map[string]*proposal{} // by CPE
	var exts []extension
	var ambiguous []string
	for i, t := range ready {
		if ctx.Err() != nil {
			break
		}
		keyword, spellings := names(t.c.Repo)
		cpes, err := cache.search(ctx, nvd, keyword, spellings)
		if err != nil {
			log.Warn("cpe search", "repo", t.c.Repo, "err", err)
			continue
		}
		var withCVEs []string
		counts := map[string]int{}
		var implausible []string
		for _, cpe := range cpes {
			n, majors, err := cache.cves(ctx, nvd, cpe)
			if err != nil {
				log.Warn("cve fetch", "cpe", cpe, "err", err)
				continue
			}
			if n == 0 {
				continue
			}
			if !plausible(t.examples, majors) {
				implausible = append(implausible, fmt.Sprintf("%s (CVE versions %s)", cpe, strings.Join(majors, ",")))
				continue
			}
			withCVEs = append(withCVEs, cpe)
			counts[cpe] = n
		}
		if len(withCVEs) == 0 && len(implausible) > 0 {
			skips = append(skips, skipped{t.c.Repo, "version line doesn't match: " + strings.Join(implausible, "; "), len(t.c.Charts)})
			continue
		}
		if (i+1)%20 == 0 {
			log.Info("progress", "done", i+1, "of", len(ready), "proposals", len(proposals), "extensions", len(exts))
		}
		var cpe string
		switch {
		case len(withCVEs) == 0:
			reason := "no CPE with CVEs named " + keyword
			if len(cpes) > 0 {
				reason = "CPE exists but has no CVEs (" + strings.Join(cpes, ", ") + ")"
			}
			skips = append(skips, skipped{t.c.Repo, reason, len(t.c.Charts)})
			continue
		case len(withCVEs) == 1:
			cpe = withCVEs[0]
		default:
			// Prefer a vendor equal to the product name or the image namespace.
			ns := strings.ToLower(path.Base(path.Dir(t.c.Repo)))
			for _, c := range withCVEs {
				f := strings.Split(c, ":")
				if f[3] == f[4] || f[3] == ns {
					cpe = c
					break
				}
			}
			if cpe == "" {
				var desc []string
				for _, c := range withCVEs {
					desc = append(desc, fmt.Sprintf("`%s` (%d)", c, counts[c]))
				}
				ambiguous = append(ambiguous, fmt.Sprintf("| `%s` | %d | %s |", t.c.Repo, len(t.c.Charts), strings.Join(desc, ", ")))
				continue
			}
		}
		if pid, ok := byCPE[cpe]; ok {
			exts = append(exts, extension{Product: pid, Image: t.c.Repo, CPE: cpe})
			continue
		}
		p := proposals[cpe]
		if p == nil {
			f := strings.Split(cpe, ":")
			id, name := f[4], prettyName(f[4])
			if len(f[4]) <= 4 || genericProduct[f[4]] {
				id, name = f[3]+"-"+f[4], prettyName(f[3])+" "+prettyName(f[4])
			}
			p = &proposal{ID: strings.NewReplacer("_", "-", ".", "-").Replace(id), Name: name, CPE: cpe, CVEs: counts[cpe], TestTags: t.examples, MinSegments: t.minSeg}
			proposals[cpe] = p
		}
		p.Images = append(p.Images, t.c.Repo)
		p.Charts = append(p.Charts, t.c.Charts...)
	}

	// 4. Write.
	ids := map[string]bool{}
	for _, p := range cfg.Products {
		ids[p.ID] = true
	}
	var list []*proposal
	for _, p := range proposals {
		for base, n := p.ID, 2; ids[p.ID]; n++ {
			p.ID = fmt.Sprintf("%s-%d", base, n)
		}
		ids[p.ID] = true
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	if !o.dryRun {
		for _, p := range list {
			if err := writeProduct(o.products, p); err != nil {
				return err
			}
		}
		if err := applyExtensions(cfg, exts); err != nil {
			return err
		}
	}
	if o.report != "" {
		if err := writeReport(o.report, list, exts, ambiguous, skips, len(all), alreadyMapped); err != nil {
			return err
		}
	}
	log.Info("done", "newProducts", len(list), "extendedProducts", len(exts), "ambiguous", len(ambiguous))
	return nil
}

// Product names that need their vendor to mean anything.
var genericProduct = map[string]bool{"server": true, "gateway": true, "console": true, "portal": true, "registry": true, "platform": true}

func prettyName(product string) string {
	words := strings.FieldsFunc(product, func(r rune) bool { return r == '_' || r == '-' })
	for i, w := range words {
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	return strings.Join(words, " ")
}

func q(s string) string { b, _ := json.Marshal(s); return string(b) }

func writeProduct(dir string, p *proposal) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by tools/feedgen/discover on %s; review before merging.\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "# Matched by product name to %s (%d CVEs on record).\n", p.CPE, p.CVEs)
	if len(p.Charts) > 0 {
		cs := p.Charts
		if len(cs) > 5 {
			cs = append(cs[:5:5], fmt.Sprintf("+%d more", len(p.Charts)-5))
		}
		fmt.Fprintf(&b, "# Used by Helm charts: %s\n", strings.Join(cs, ", "))
	}
	fmt.Fprintf(&b, "id: %s\nname: %s\nimages:\n", p.ID, q(p.Name))
	sort.Strings(p.Images)
	for _, img := range p.Images {
		fmt.Fprintf(&b, "  - %s\n", img)
	}
	if p.MinSegments > 0 {
		fmt.Fprintf(&b, "minSegments: %d\n", p.MinSegments)
	}
	fmt.Fprintf(&b, "nvd:\n  cpes:\n    - %s\n", p.CPE)
	b.WriteString("# Example tags (taken from the registry) and the version read from them.\ntestTags:\n")
	tags := make([]string, 0, len(p.TestTags))
	for t := range p.TestTags {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	for _, t := range tags {
		fmt.Fprintf(&b, "  %s: %s\n", q(t), q(p.TestTags[t]))
	}
	return os.WriteFile(filepath.Join(dir, p.ID+".yaml"), []byte(b.String()), 0o644)
}

// applyExtensions appends newly found images to existing product files.
func applyExtensions(cfg *config.Config, exts []extension) error {
	byProduct := map[string][]string{}
	for _, e := range exts {
		byProduct[e.Product] = append(byProduct[e.Product], e.Image)
	}
	for id, imgs := range byProduct {
		file := cfg.File(id)
		b, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		s := string(b)
		i := strings.Index(s, "images:\n")
		if i < 0 {
			return fmt.Errorf("%s: no images list", file)
		}
		j := i + len("images:\n")
		for j < len(s) && strings.HasPrefix(s[j:], "  - ") {
			j += strings.IndexByte(s[j:], '\n') + 1
		}
		var add strings.Builder
		sort.Strings(imgs)
		for _, img := range imgs {
			fmt.Fprintf(&add, "  - %s\n", img)
		}
		if err := os.WriteFile(file, []byte(s[:j]+add.String()+s[j:]), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func writeReport(file string, list []*proposal, exts []extension, ambiguous []string, skips []skipped, total, mapped int) error {
	var b strings.Builder
	fmt.Fprintf(&b, "## Product discovery\n\n")
	fmt.Fprintf(&b, "Looked at %d images (Artifact Hub charts, Docker Official Images, Bitnami); %d were already mapped.\n\n", total, mapped)
	fmt.Fprintf(&b, "- **%d new products**\n- **%d images added to existing products**\n- %d ambiguous (several vendors, needs a human)\n\n", len(list), len(exts), len(ambiguous))
	if len(list) > 0 {
		b.WriteString("### New products\n\n| Product | CPE | CVEs | Images | Charts |\n|---|---|---|---|---|\n")
		for _, p := range list {
			fmt.Fprintf(&b, "| `%s` | `%s` | %d | %s | %d |\n", p.ID, p.CPE, p.CVEs, "`"+strings.Join(p.Images, "`<br>`")+"`", len(p.Charts))
		}
		b.WriteString("\n")
	}
	if len(exts) > 0 {
		b.WriteString("### Images added to existing products\n\n| Product | Image |\n|---|---|\n")
		for _, e := range exts {
			fmt.Fprintf(&b, "| `%s` | `%s` |\n", e.Product, e.Image)
		}
		b.WriteString("\n")
	}
	if len(ambiguous) > 0 {
		b.WriteString("### Ambiguous: pick the right CPE by hand\n\n| Image | Charts | CPEs (CVEs) |\n|---|---|---|\n")
		b.WriteString(strings.Join(ambiguous, "\n") + "\n\n")
	}
	if len(skips) > 0 {
		sort.Slice(skips, func(i, j int) bool { return skips[i].Charts > skips[j].Charts })
		b.WriteString("<details><summary>Skipped images (most used first)</summary>\n\n| Image | Charts | Reason |\n|---|---|---|\n")
		for i, s := range skips {
			if i == 200 {
				fmt.Fprintf(&b, "| … | | %d more |\n", len(skips)-200)
				break
			}
			fmt.Fprintf(&b, "| `%s` | %d | %s |\n", s.Repo, s.Charts, s.Reason)
		}
		b.WriteString("\n</details>\n")
	}
	return os.WriteFile(file, []byte(b.String()), 0o644)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
