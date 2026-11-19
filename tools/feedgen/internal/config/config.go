// Package config loads feed/products.yaml.
package config

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/huseyinbabal/cvedetector/pkg/feed"
)

// Config is the root of products.yaml.
type Config struct {
	Products []Product `json:"products"`
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

// Load reads and validates a config file.
func Load(file string) (*Config, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return &c, c.Validate()
}

// Validate checks ids, image patterns, version patterns and sources.
func (c *Config) Validate() error {
	ids := map[string]bool{}
	images := map[string]string{}
	for i, p := range c.Products {
		where := fmt.Sprintf("products[%d] (%s)", i, p.ID)
		if !idRe.MatchString(p.ID) {
			return fmt.Errorf("%s: id must match %s", where, idRe)
		}
		if ids[p.ID] {
			return fmt.Errorf("%s: duplicate id", where)
		}
		ids[p.ID] = true
		if len(p.Images) == 0 {
			return fmt.Errorf("%s: at least one image is required", where)
		}
		for _, img := range p.Images {
			if _, err := path.Match(img, ""); err != nil {
				return fmt.Errorf("%s: bad image pattern %q: %w", where, img, err)
			}
			if strings.Contains(img, ":") && !strings.Contains(strings.SplitN(img, "/", 2)[0], ":") {
				return fmt.Errorf("%s: image %q must be a repository without a tag", where, img)
			}
			if other, ok := images[img]; ok {
				return fmt.Errorf("%s: image %q already mapped to %s", where, img, other)
			}
			images[img] = p.ID
		}
		if _, err := feed.CompileVersionPattern(p.VersionPattern); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		if (p.NVD == nil || len(p.NVD.CPEs) == 0) && len(p.OSV) == 0 {
			return fmt.Errorf("%s: needs an nvd or osv source", where)
		}
		if p.NVD != nil {
			for _, cpe := range p.NVD.CPEs {
				if len(strings.Split(cpe, ":")) != 5 || !strings.HasPrefix(cpe, "cpe:2.3:") {
					return fmt.Errorf("%s: cpe %q must look like cpe:2.3:a:<vendor>:<product>", where, cpe)
				}
			}
		}
		for _, o := range p.OSV {
			if o.Ecosystem == "" || o.Package == "" {
				return fmt.Errorf("%s: osv entries need ecosystem and package", where)
			}
		}
	}
	return nil
}
