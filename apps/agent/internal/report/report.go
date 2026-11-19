// Package report turns discovered pods into an inventory report and sends it
// to the API.
package report

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/huseyinbabal/cvedetector/apps/agent/internal/discovery"
	"github.com/huseyinbabal/cvedetector/pkg/imageref"
	"github.com/huseyinbabal/cvedetector/pkg/inventory"
)

// Build aggregates pods into distinct images and workloads.
func Build(cluster, agentVersion string, pods []discovery.Pod, now time.Time) inventory.Report {
	type wkey struct{ ns, kind, name string }
	images := map[string]*inventory.Image{}
	imagePods := map[string]map[string]bool{}
	workloads := map[wkey]*inventory.Workload{}
	workloadImages := map[wkey]map[string]bool{}

	for _, p := range pods {
		k := wkey{p.Namespace, p.Owner.Kind, p.Owner.Name}
		w := workloads[k]
		if w == nil {
			w = &inventory.Workload{Namespace: k.ns, Kind: k.kind, Name: k.name}
			workloads[k] = w
			workloadImages[k] = map[string]bool{}
		}
		w.Pods++
		for _, c := range p.Containers {
			ref := imageref.Parse(c.Image)
			key := Key(ref)
			img := images[key]
			if img == nil {
				img = &inventory.Image{Ref: key, Repository: ref.Repository, Tag: ref.Tag}
				if ref.Digest != "" {
					img.Digests = []string{ref.Digest}
				}
				images[key] = img
				imagePods[key] = map[string]bool{}
			}
			if d := imageref.DigestFromImageID(c.ImageID); d != "" && !contains(img.Digests, d) {
				img.Digests = append(img.Digests, d)
			}
			imagePods[key][p.Namespace+"/"+p.Name] = true
			workloadImages[k][key] = true
		}
	}

	r := inventory.Report{SchemaVersion: inventory.SchemaVersion, Cluster: cluster, AgentVersion: agentVersion, GeneratedAt: now.UTC()}
	r.Images = make([]inventory.Image, 0, len(images))
	for key, img := range images {
		img.Pods = len(imagePods[key])
		r.Images = append(r.Images, *img)
	}
	r.Workloads = make([]inventory.Workload, 0, len(workloads))
	for k, w := range workloads {
		for ref := range workloadImages[k] {
			w.Images = append(w.Images, ref)
		}
		r.Workloads = append(r.Workloads, *w)
	}
	r.Normalize()
	return r
}

// Key is the distinct-image key: repository:tag, else repository@digest.
func Key(r imageref.Ref) string {
	if r.Tag != "" {
		return r.Repository + ":" + r.Tag
	}
	if r.Digest != "" {
		return r.Repository + "@" + r.Digest
	}
	return r.Repository
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// Sender posts reports to the API.
type Sender struct {
	URL   string // API base URL, e.g. http://cvedetector-api:8080
	Token string
	HTTP  *http.Client
}

// Send posts a gzip-compressed report to /api/v1/ingest.
func (s *Sender) Send(ctx context.Context, r *inventory.Report) error {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(r); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(s.URL, "/")+"/api/v1/ingest", &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Authorization", "Bearer "+s.Token)
	req.Header.Set("User-Agent", "cvedetector-agent/"+r.AgentVersion)
	client := s.HTTP
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("ingest: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}
