// Package config loads the product catalog: one YAML file per product in
// feed/products/<id>.yaml (so contributions don't conflict).
package config

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/huseyinbabal/cvedetector/pkg/feed"
)

// Config is the product catalog.
type Config struct {
	Products []Product `json:"products"`
	files    map[string]string
}

// Product describes how to recognize a product's images and where its CVEs live.
type Product struct {
	ID             string       `json:"id"`
	Name           string       `json:"name"`
	Images         []string     `json:"images"`
	VersionPattern string       `json:"versionPattern,omitempty"`
	MinSegments    int          `json:"minSegments,omitempty"`
	NVD            *NVDSource   `json:"nvd,omitempty"`
	OSV            []OSVPackage `json:"osv,omitempty"`
	// TestTags maps example image tags to the version that must be read from
	// them ("" = no version, e.g. "latest"). Checked by Validate.
	TestTags map[string]string `json:"testTags"`
}

// NVDSource lists CPE prefixes ("cpe:2.3:a:<vendor>:<product>").
type NVDSource struct {
	CPEs []string `json:"cpes"`
}

// OSVPackage is a package in an OSV ecosystem.
type OSVPackage struct {
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
}

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// Load reads a directory of <id>.yaml product files.
func Load(dir string) (*Config, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	c := &Config{files: map[string]string{}}
	for _, e := range entries {
		if e.IsDir() || !(strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		file := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var p Product
		if err := yaml.UnmarshalStrict(b, &p); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		if want := strings.TrimSuffix(strings.TrimSuffix(e.Name(), ".yaml"), ".yml"); p.ID != want {
			return nil, fmt.Errorf("%s: id %q must match the file name (%s)", file, p.ID, want)
		}
		c.Products = append(c.Products, p)
		c.files[p.ID] = file
	}
	sort.Slice(c.Products, func(i, j int) bool { return c.Products[i].ID < c.Products[j].ID })
	if len(c.Products) == 0 {
		return nil, fmt.Errorf("%s: no product files", dir)
	}
	return c, c.Validate()
}

// File returns the file a product was loaded from.
func (c *Config) File(id string) string { return c.files[id] }

// Validate checks ids, image patterns, version patterns, test tags and sources.
func (c *Config) Validate() error {
	ids := map[string]bool{}
	images := map[string]string{}
	var errs []string
	for _, p := range c.Products {
		where := p.ID
		if f := c.files[p.ID]; f != "" {
			where = f
		}
		fail := func(format string, a ...any) { errs = append(errs, where+": "+fmt.Sprintf(format, a...)) }
		if !idRe.MatchString(p.ID) {
			fail("id must match %s", idRe)
		}
		if ids[p.ID] {
			fail("duplicate id")
		}
		ids[p.ID] = true
		if strings.TrimSpace(p.Name) == "" {
			fail("name is required")
		}
		if len(p.Images) == 0 {
			fail("at least one image is required")
		}
		for _, img := range p.Images {
			if _, err := path.Match(img, ""); err != nil {
				fail("bad image pattern %q: %v", img, err)
			}
			first := strings.SplitN(img, "/", 2)[0]
			if !strings.Contains(first, ".") && first != "localhost" {
				fail("image %q must start with its registry (e.g. docker.io/library/nginx)", img)
			}
			if strings.Contains(strings.TrimPrefix(img, first), ":") || strings.Contains(img, "@") {
				fail("image %q must be a repository without tag or digest", img)
			}
			if other, ok := images[img]; ok {
				fail("image %q is already mapped to %s", img, other)
			}
			images[img] = p.ID
		}
		re, err := feed.CompileVersionPattern(p.VersionPattern)
		if err != nil {
			fail("%v", err)
		}
		if len(p.TestTags) == 0 {
			fail(`testTags is required: example tags and the version they contain, e.g. {"1.27.3-alpine": "1.27.3", "latest": ""}`)
		}
		if re != nil {
			for tag, want := range p.TestTags {
				got := ""
				if m := re.FindStringSubmatch(tag); m != nil {
					got = m[re.SubexpIndex("version")]
				}
				if got != want {
					fail("testTags: tag %q gives version %q, expected %q", tag, got, want)
				}
			}
		}
		if (p.NVD == nil || len(p.NVD.CPEs) == 0) && len(p.OSV) == 0 {
			fail("needs an nvd or osv source")
		}
		if p.NVD != nil {
			for _, cpe := range p.NVD.CPEs {
				if parts := strings.Split(cpe, ":"); len(parts) != 5 || !strings.HasPrefix(cpe, "cpe:2.3:") {
					fail("cpe %q must look like cpe:2.3:a:<vendor>:<product>", cpe)
				}
			}
		}
		for _, o := range p.OSV {
			if o.Ecosystem == "" || o.Package == "" {
				fail("osv entries need ecosystem and package")
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid products:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}
