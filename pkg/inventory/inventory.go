// Package inventory is the contract between the in-cluster agent and the API:
// the agent reports which images run in which workloads; the API matches them
// against the CVE feed and stores the result.
package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"time"
)

// SchemaVersion of the report payload. The API rejects other values.
const SchemaVersion = 1

// Report is one full inventory snapshot of a cluster. It replaces the
// previous snapshot of the same cluster.
type Report struct {
	SchemaVersion int        `json:"schemaVersion"`
	Cluster       string     `json:"cluster"`
	AgentVersion  string     `json:"agentVersion"`
	GeneratedAt   time.Time  `json:"generatedAt"`
	Images        []Image    `json:"images"`
	Workloads     []Workload `json:"workloads"`
}

// Image is a distinct image reference running in the cluster.
type Image struct {
	Ref        string   `json:"ref"` // normalized repository:tag or repository@digest
	Repository string   `json:"repository"`
	Tag        string   `json:"tag,omitempty"`
	Digests    []string `json:"digests,omitempty"` // digests actually running (from imageID)
	Pods       int      `json:"pods"`
}

// Workload is the top-level owner of a set of pods.
type Workload struct {
	Namespace string   `json:"namespace"`
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Pods      int      `json:"pods"`
	Images    []string `json:"images"` // image refs
}

var clusterRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidClusterName reports whether s is a DNS-label-like cluster name.
func ValidClusterName(s string) bool { return clusterRe.MatchString(s) }

// Validate checks structural consistency.
func (r *Report) Validate() error {
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schemaVersion %d", r.SchemaVersion)
	}
	if !ValidClusterName(r.Cluster) {
		return fmt.Errorf("invalid cluster name %q (lowercase letters, digits and '-', max 63)", r.Cluster)
	}
	refs := make(map[string]bool, len(r.Images))
	for _, img := range r.Images {
		if img.Ref == "" || img.Repository == "" {
			return fmt.Errorf("image with empty ref or repository")
		}
		if refs[img.Ref] {
			return fmt.Errorf("duplicate image %q", img.Ref)
		}
		refs[img.Ref] = true
	}
	type key struct{ ns, kind, name string }
	seen := map[key]bool{}
	for _, w := range r.Workloads {
		k := key{w.Namespace, w.Kind, w.Name}
		if w.Kind == "" || w.Name == "" {
			return fmt.Errorf("workload with empty kind or name")
		}
		if seen[k] {
			return fmt.Errorf("duplicate workload %s/%s/%s", w.Namespace, w.Kind, w.Name)
		}
		seen[k] = true
		for _, ref := range w.Images {
			if !refs[ref] {
				return fmt.Errorf("workload %s/%s/%s references unknown image %q", w.Namespace, w.Kind, w.Name, ref)
			}
		}
	}
	return nil
}

// Normalize sorts everything so equal inventories serialize identically.
func (r *Report) Normalize() {
	sort.Slice(r.Images, func(i, j int) bool { return r.Images[i].Ref < r.Images[j].Ref })
	for i := range r.Images {
		sort.Strings(r.Images[i].Digests)
	}
	sort.Slice(r.Workloads, func(i, j int) bool {
		a, b := r.Workloads[i], r.Workloads[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Name < b.Name
	})
	for i := range r.Workloads {
		sort.Strings(r.Workloads[i].Images)
	}
}

// Fingerprint hashes the inventory content (not GeneratedAt) so the agent can
// skip sending unchanged snapshots.
func (r Report) Fingerprint() string {
	r.GeneratedAt = time.Time{}
	r.Normalize()
	b, _ := json.Marshal(r)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
