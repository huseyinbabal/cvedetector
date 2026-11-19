// Package imageref normalizes container image references the way container
// runtimes resolve them (Docker Hub defaults, "library/" prefix, digests).
package imageref

import "strings"

const dockerHub = "docker.io"

// Ref is a normalized image reference.
type Ref struct {
	Repository string // registry + path, e.g. "docker.io/library/nginx"
	Tag        string // may be empty
	Digest     string // "sha256:...", may be empty
}

// String renders the reference in canonical form.
func (r Ref) String() string {
	s := r.Repository
	if r.Tag != "" {
		s += ":" + r.Tag
	}
	if r.Digest != "" {
		s += "@" + r.Digest
	}
	return s
}

// Parse normalizes a reference such as "nginx:1.27", "ghcr.io/org/app@sha256:..."
// or "localhost:5000/app:dev". A missing tag stays empty (no implicit "latest"):
// callers decide how to treat untagged images.
func Parse(s string) Ref {
	s = strings.TrimSpace(s)
	var r Ref
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s, r.Digest = s[:i], s[i+1:]
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 && !strings.Contains(s[i+1:], "/") {
		s, r.Tag = s[:i], s[i+1:]
	}
	domain, rest := dockerHub, s
	if i := strings.IndexByte(s, '/'); i >= 0 {
		first := s[:i]
		if strings.ContainsAny(first, ".:") || first == "localhost" || strings.ToLower(first) != first {
			domain, rest = strings.ToLower(first), s[i+1:]
		}
	}
	if domain == "index.docker.io" || domain == "registry-1.docker.io" {
		domain = dockerHub
	}
	if domain == dockerHub && !strings.Contains(rest, "/") {
		rest = "library/" + rest
	}
	r.Repository = domain + "/" + rest
	return r
}

// DigestFromImageID extracts the digest from a containerStatus.imageID, which
// runtimes report as "docker-pullable://repo@sha256:...", "repo@sha256:..." or
// a bare "sha256:...".
func DigestFromImageID(id string) string {
	if i := strings.LastIndexByte(id, '@'); i >= 0 {
		return id[i+1:]
	}
	if i := strings.Index(id, "sha256:"); i >= 0 {
		return id[i:]
	}
	return ""
}
