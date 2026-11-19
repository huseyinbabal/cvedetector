package imageref

import "testing"

func TestParse(t *testing.T) {
	tests := []struct{ in, repo, tag, digest string }{
		{"nginx", "docker.io/library/nginx", "", ""},
		{"nginx:1.27.3", "docker.io/library/nginx", "1.27.3", ""},
		{"bitnami/redis:7.2.4-debian-12-r5", "docker.io/bitnami/redis", "7.2.4-debian-12-r5", ""},
		{"docker.io/nginx:1.27", "docker.io/library/nginx", "1.27", ""},
		{"index.docker.io/library/nginx:1", "docker.io/library/nginx", "1", ""},
		{"registry.k8s.io/kube-proxy:v1.31.2", "registry.k8s.io/kube-proxy", "v1.31.2", ""},
		{"localhost:5000/app:dev", "localhost:5000/app", "dev", ""},
		{"localhost/app", "localhost/app", "", ""},
		{"GHCR.IO/Org/app:1", "ghcr.io/Org/app", "1", ""},
		{"quay.io/argoproj/argocd:v2.13.0@sha256:abc", "quay.io/argoproj/argocd", "v2.13.0", "sha256:abc"},
		{"nginx@sha256:abc", "docker.io/library/nginx", "", "sha256:abc"},
	}
	for _, tt := range tests {
		r := Parse(tt.in)
		if r.Repository != tt.repo || r.Tag != tt.tag || r.Digest != tt.digest {
			t.Errorf("Parse(%q) = %+v", tt.in, r)
		}
	}
}

func TestDigestFromImageID(t *testing.T) {
	for in, want := range map[string]string{
		"docker-pullable://nginx@sha256:aa": "sha256:aa",
		"docker.io/library/nginx@sha256:bb": "sha256:bb",
		"sha256:cc":                         "sha256:cc",
		"":                                  "",
	} {
		if got := DigestFromImageID(in); got != want {
			t.Errorf("DigestFromImageID(%q)=%q want %q", in, got, want)
		}
	}
}
