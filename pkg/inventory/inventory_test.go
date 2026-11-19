package inventory

import (
	"testing"
	"time"
)

func sample() Report {
	return Report{
		SchemaVersion: 1, Cluster: "prod-eu-1", GeneratedAt: time.Now(),
		Images:    []Image{{Ref: "docker.io/library/redis:7.2.4", Repository: "docker.io/library/redis", Tag: "7.2.4", Pods: 1}, {Ref: "docker.io/library/nginx:1.27.1", Repository: "docker.io/library/nginx", Tag: "1.27.1", Pods: 2}},
		Workloads: []Workload{{Namespace: "web", Kind: "Deployment", Name: "web", Pods: 2, Images: []string{"docker.io/library/nginx:1.27.1"}}},
	}
}

func TestValidate(t *testing.T) {
	r := sample()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []func(*Report){
		func(r *Report) { r.SchemaVersion = 2 },
		func(r *Report) { r.Cluster = "Prod_EU" },
		func(r *Report) { r.Cluster = "" },
		func(r *Report) { r.Images = append(r.Images, r.Images[0]) },
		func(r *Report) { r.Workloads[0].Images = []string{"docker.io/library/missing:1"} },
		func(r *Report) { r.Workloads = append(r.Workloads, r.Workloads[0]) },
	}
	for i, mutate := range bad {
		r := sample()
		r.Images = append([]Image(nil), r.Images...)
		r.Workloads = []Workload{{Namespace: "web", Kind: "Deployment", Name: "web", Pods: 2, Images: []string{"docker.io/library/nginx:1.27.1"}}}
		mutate(&r)
		if err := r.Validate(); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

func TestFingerprintIgnoresOrderAndTime(t *testing.T) {
	a, b := sample(), sample()
	b.GeneratedAt = a.GeneratedAt.Add(time.Hour)
	b.Images[0], b.Images[1] = b.Images[1], b.Images[0]
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("fingerprint should ignore order and time")
	}
	b.Images[0].Pods = 9
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("fingerprint should change with content")
	}
}
