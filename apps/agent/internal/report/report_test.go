package report

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/huseyinbabal/cvedetector/apps/agent/internal/discovery"
	"github.com/huseyinbabal/cvedetector/pkg/inventory"
)

func pods() []discovery.Pod {
	return []discovery.Pod{
		{Namespace: "web", Name: "web-1", Owner: discovery.Owner{Kind: "Deployment", Name: "web"}, Containers: []discovery.Container{
			{Image: "nginx:1.27.1", ImageID: "docker-pullable://nginx@sha256:aa"},
			{Image: "busybox:1.36", Init: true},
		}},
		{Namespace: "web", Name: "web-2", Owner: discovery.Owner{Kind: "Deployment", Name: "web"}, Containers: []discovery.Container{
			{Image: "docker.io/library/nginx:1.27.1", ImageID: "docker.io/library/nginx@sha256:bb"},
		}},
		{Namespace: "db", Name: "pg-0", Owner: discovery.Owner{Kind: "StatefulSet", Name: "pg"}, Containers: []discovery.Container{
			{Image: "postgres@sha256:cc"},
		}},
	}
}

func TestBuild(t *testing.T) {
	r := Build("prod", "v1", pods(), time.Unix(0, 0))
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(r.Images) != 3 || len(r.Workloads) != 2 {
		t.Fatalf("%+v", r)
	}
	nginx := r.Images[2] // sorted: busybox, postgres@, nginx? check by ref
	for _, img := range r.Images {
		if img.Ref == "docker.io/library/nginx:1.27.1" {
			nginx = img
		}
	}
	if nginx.Pods != 2 || len(nginx.Digests) != 2 {
		t.Errorf("nginx: %+v", nginx)
	}
	var web inventory.Workload
	for _, w := range r.Workloads {
		if w.Name == "web" {
			web = w
		}
	}
	if web.Pods != 2 || len(web.Images) != 2 {
		t.Errorf("web: %+v", web)
	}
	found := false
	for _, img := range r.Images {
		if img.Ref == "docker.io/library/postgres@sha256:cc" && img.Tag == "" {
			found = true
		}
	}
	if !found {
		t.Errorf("digest-only image missing: %+v", r.Images)
	}
}

func TestSend(t *testing.T) {
	var got inventory.Report
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ingest" || r.Header.Get("Authorization") != "Bearer secret" {
			http.Error(w, "nope", http.StatusUnauthorized)
			return
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		_ = json.NewDecoder(zr).Decode(&got)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	r := Build("prod", "v1", pods(), time.Now())
	if err := (&Sender{URL: srv.URL + "/", Token: "secret"}).Send(context.Background(), &r); err != nil {
		t.Fatal(err)
	}
	if got.Cluster != "prod" || len(got.Images) != 3 {
		t.Errorf("server got %+v", got)
	}
	if err := (&Sender{URL: srv.URL, Token: "wrong"}).Send(context.Background(), &r); err == nil {
		t.Error("expected 401 error")
	}
}
