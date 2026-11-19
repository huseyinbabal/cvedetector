package registry

import (
	"context"
	"os"
	"testing"
)

// Live test against public registries; run with REGISTRY_LIVE=1.
func TestLiveTags(t *testing.T) {
	if os.Getenv("REGISTRY_LIVE") == "" {
		t.Skip("set REGISTRY_LIVE=1")
	}
	c := New()
	for _, repo := range []string{"docker.io/library/nginx", "quay.io/keycloak/keycloak", "ghcr.io/kyverno/kyverno", "registry.k8s.io/kube-proxy", "mcr.microsoft.com/dotnet/aspnet"} {
		tags, err := c.Tags(context.Background(), repo)
		if err != nil || len(tags) == 0 {
			t.Errorf("%s: %d tags, %v", repo, len(tags), err)
			continue
		}
		t.Logf("%s: %d tags, e.g. %v", repo, len(tags), tags[:min(3, len(tags))])
	}
}
