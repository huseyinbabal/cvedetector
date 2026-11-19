// Command feedgen builds the CVE feed from feed/products.yaml using NVD and OSV
// version-range data. It never pulls or scans images.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/huseyinbabal/cvedetector/pkg/feed"
	"github.com/huseyinbabal/cvedetector/tools/feedgen/internal/build"
	"github.com/huseyinbabal/cvedetector/tools/feedgen/internal/config"
	"github.com/huseyinbabal/cvedetector/tools/feedgen/internal/sources"
)

func main() {
	cfgPath := flag.String("config", "feed/products.yaml", "products config")
	out := flag.String("out", "dist/feed", "output directory (feed is written to <out>/v1); an existing feed there is diffed against")
	changes := flag.String("changes", "", "directory for daily changelogs (<dir>/YYYY/MM/YYYY-MM-DD.json); empty disables")
	commitMsg := flag.String("commit-message", "", "write a commit message summarizing the changes to this file (only when something changed)")
	only := flag.String("only", "", "comma-separated product ids to build (default: all)")
	noEnrich := flag.Bool("no-enrich", false, "skip CISA KEV and EPSS enrichment")
	validate := flag.Bool("validate", false, "only validate the config and exit")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("invalid config", "err", err)
		os.Exit(1)
	}
	if *validate {
		fmt.Printf("%s: %d products OK\n", *cfgPath, len(cfg.Products))
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, log, cfg, *out, *only, !*noEnrich, *changes, *commitMsg); err != nil {
		log.Error("feed generation failed", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, log *slog.Logger, cfg *config.Config, out, only string, enrich bool, changesDir, commitMsg string) error {
	client := sources.NewClient()
	nvd := &sources.NVD{Client: client, APIKey: os.Getenv("NVD_API_KEY")}
	osv := &sources.OSV{Client: client}
	if nvd.APIKey == "" {
		log.Warn("NVD_API_KEY not set; NVD requests are throttled to 5 per 30s")
	}

	want := map[string]bool{}
	for _, id := range strings.Split(only, ",") {
		if id = strings.TrimSpace(id); id != "" {
			want[id] = true
		}
	}

	idx := build.NewIndex(time.Now())
	shards := map[string]feed.Shard{}
	for _, p := range cfg.Products {
		if len(want) > 0 && !want[p.ID] {
			continue
		}
		var lists [][]feed.Vuln
		if p.NVD != nil {
			for _, cpe := range p.NVD.CPEs {
				vs, err := nvd.Fetch(ctx, cpe)
				if err != nil {
					return fmt.Errorf("%s: %w", p.ID, err)
				}
				log.Info("nvd", "product", p.ID, "cpe", cpe, "vulns", len(vs))
				lists = append(lists, vs)
			}
		}
		for _, o := range p.OSV {
			vs, err := osv.Fetch(ctx, o.Ecosystem, o.Package)
			if err != nil {
				return fmt.Errorf("%s: %w", p.ID, err)
			}
			log.Info("osv", "product", p.ID, "package", o.Ecosystem+"/"+o.Package, "vulns", len(vs))
			lists = append(lists, vs)
		}
		vulns := build.Merge(lists...)
		if len(vulns) == 0 {
			log.Warn("no vulnerabilities found; check the CPE / package names", "product", p.ID)
		}
		name := p.Name
		if name == "" {
			name = p.ID
		}
		idx.Products = append(idx.Products, feed.Product{
			ID: p.ID, Name: name, Images: p.Images,
			VersionPattern: p.VersionPattern, MinSegments: p.MinSegments,
		})
		shards[p.ID] = feed.Shard{SchemaVersion: feed.SchemaVersion, Product: p.ID, Vulns: vulns}
	}

	var epss map[string]float64
	if enrich {
		var flat []feed.Vuln
		for _, s := range shards {
			flat = append(flat, s.Vulns...)
		}
		kev, err := sources.KEV(ctx, client)
		if err != nil {
			return err
		}
		epss, err = sources.EPSS(ctx, client, build.CVEIDs(flat))
		if err != nil {
			return err
		}
		for id, s := range shards {
			build.Enrich(s.Vulns, kev, nil)
			shards[id] = s
		}
		log.Info("enriched", "kev", len(kev), "epss", len(epss))
	}

	now := time.Now()
	d, err := build.Write(out, build.Output{Index: idx, Shards: shards, EPSS: epss}, now)
	if err != nil {
		return err
	}
	if !d.Changed {
		log.Info("feed unchanged", "dir", out+"/v1")
		return nil
	}
	log.Info("feed written", "dir", out+"/v1", "products", len(idx.Products),
		"added", len(d.Added), "updated", len(d.Updated), "removed", len(d.Removed), "epssChanged", d.EPSSChanged)
	if changesDir != "" {
		p, err := build.WriteChangelog(changesDir, now, d)
		if err != nil {
			return err
		}
		if p != "" {
			log.Info("changelog written", "file", p)
		}
	}
	if commitMsg != "" {
		if err := os.WriteFile(commitMsg, []byte(build.CommitMessage(now, d)), 0o644); err != nil {
			return err
		}
	}
	return nil
}
