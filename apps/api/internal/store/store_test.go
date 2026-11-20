package store_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/huseyinbabal/cvedetector/apps/api/internal/db"
	"github.com/huseyinbabal/cvedetector/apps/api/internal/store"
	"github.com/huseyinbabal/cvedetector/pkg/feed"
	"github.com/huseyinbabal/cvedetector/pkg/inventory"
)

// Integration tests run against TEST_DATABASE_URL (a disposable database: the
// public schema is dropped). They are skipped when it is not set.
func setup(t *testing.T) (*store.Store, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := db.Migrate(ctx, pool, log); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, pool, log); err != nil { // idempotent
		t.Fatal(err)
	}
	return store.New(pool), pool
}

func index(nginxSHA string) *feed.Index {
	return &feed.Index{SchemaVersion: 1, GeneratedAt: time.Now().UTC(), Products: []feed.Product{
		{ID: "nginx", Name: "NGINX", Images: []string{"docker.io/library/nginx"}, SHA256: nginxSHA},
		{ID: "redis", Name: "Redis", Images: []string{"docker.io/library/redis"}, SHA256: "r1"},
	}}
}

func report(cluster, nginxTag string) *inventory.Report {
	nginx := "docker.io/library/nginx:" + nginxTag
	return &inventory.Report{
		SchemaVersion: 1, Cluster: cluster, AgentVersion: "test",
		Images: []inventory.Image{
			{Ref: nginx, Repository: "docker.io/library/nginx", Tag: nginxTag, Pods: 2, Digests: []string{"sha256:aa"}},
			{Ref: "docker.io/library/redis:7.2.4", Repository: "docker.io/library/redis", Tag: "7.2.4", Pods: 1},
			{Ref: "ghcr.io/acme/app:1.0", Repository: "ghcr.io/acme/app", Tag: "1.0", Pods: 3},
		},
		Workloads: []inventory.Workload{
			{Namespace: "web", Kind: "Deployment", Name: "web", Pods: 2, Images: []string{nginx}},
			{Namespace: "web", Kind: "Deployment", Name: "app", Pods: 3, Images: []string{"ghcr.io/acme/app:1.0", nginx}},
			{Namespace: "data", Kind: "StatefulSet", Name: "redis", Pods: 1, Images: []string{"docker.io/library/redis:7.2.4"}},
		},
	}
}

func TestIngestReconcileAndRead(t *testing.T) {
	st, pool := setup(t)
	ctx := context.Background()
	now := time.Now()

	err := st.ApplyFeed(ctx, index("n1"), `"e1"`, map[string]*feed.Shard{
		"nginx": {Vulns: []feed.Vuln{
			{ID: "CVE-1", Severity: feed.SeverityHigh, CVSS: 7.5, KEV: true, Affected: []feed.Range{{LT: "1.27.2"}}},
			{ID: "CVE-2", Severity: feed.SeverityMedium, Affected: []feed.Range{{GTE: "1.27.0", LTE: "1.27.3"}}},
		}},
		"redis": {Vulns: []feed.Vuln{{ID: "CVE-R", Severity: feed.SeverityCritical, Affected: []feed.Range{{LT: "7.2.5"}}}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := st.ApplyReport(ctx, report("prod", "1.27.1"), now)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.Opened != 3 || res.Open != 3 {
		t.Fatalf("first report: %+v", res)
	}

	// Unchanged report: heartbeat only.
	res, err = st.ApplyReport(ctx, report("prod", "1.27.1"), now.Add(time.Minute))
	if err != nil || res.Changed {
		t.Fatalf("unchanged report: %+v %v", res, err)
	}

	// Upgrade nginx to 1.27.2: CVE-1 resolves, CVE-2 stays open.
	res, err = st.ApplyReport(ctx, report("prod", "1.27.2"), now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if res.Opened != 1 || res.Resolved != 2 || res.Open != 2 {
		// new ref (nginx:1.27.2) opens CVE-2 for it; old ref's CVE-1 and CVE-2 resolve
		t.Fatalf("upgrade: %+v", res)
	}

	// Feed update adds a vuln for the running nginx: rematch opens it.
	err = st.ApplyFeed(ctx, index("n2"), `"e2"`, map[string]*feed.Shard{"nginx": {Vulns: []feed.Vuln{
		{ID: "CVE-1", Severity: feed.SeverityHigh, CVSS: 7.5, KEV: true, Affected: []feed.Range{{LT: "1.27.2"}}},
		{ID: "CVE-2", Severity: feed.SeverityMedium, Affected: []feed.Range{{GTE: "1.27.0", LTE: "1.27.3"}}},
		{ID: "CVE-3", Severity: feed.SeverityCritical, CVSS: 9.8, Affected: []feed.Range{{LT: "1.28.0"}}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	rm, err := st.RematchAll(ctx, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if rm["prod"].Opened != 1 || rm["prod"].Open != 3 {
		t.Fatalf("rematch: %+v", rm["prod"])
	}

	// Second cluster.
	if _, err := st.ApplyReport(ctx, report("staging", "1.27.1"), now); err != nil {
		t.Fatal(err)
	}

	// ---- reads
	clusters, err := st.Clusters(ctx)
	if err != nil || len(clusters) != 2 || clusters[0].Name != "prod" || clusters[0].Counts.Total != 3 || clusters[0].Images != 3 {
		t.Fatalf("clusters: %+v %v", clusters, err)
	}

	products, err := st.Products(ctx)
	if err != nil || len(products) == 0 || products[0].ID == "" || len(products[0].Images) == 0 {
		t.Fatalf("products: %+v %v", products, err)
	}

	sum, err := st.Summary(ctx, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if sum.Vulns.Critical != 2 || sum.Vulns.Medium != 1 || sum.Vulns.Total != 3 || sum.ImagesByStatus["unknown"] != 1 || sum.Vulnerable != 3 || sum.Namespaces != 2 {
		t.Errorf("summary: %+v", sum)
	}
	if len(sum.TopWorkloads) == 0 || sum.TopWorkloads[0].MaxSeverity != "CRITICAL" {
		t.Errorf("top workloads: %+v", sum.TopWorkloads)
	}

	imgs, err := st.Images(ctx, store.ListOpts{Cluster: "prod", MinSeverity: 4, Limit: 10})
	if err != nil || imgs.Total != 2 {
		t.Fatalf("critical images: %+v %v", imgs, err)
	}
	imgs, err = st.Images(ctx, store.ListOpts{Status: "unknown"})
	if err != nil || imgs.Total != 2 { // one per cluster
		t.Fatalf("unknown images: %+v %v", imgs, err)
	}
	imgs, err = st.Images(ctx, store.ListOpts{Cluster: "prod", Sort: "ref", Desc: false, Limit: 1, Offset: 1})
	if err != nil || imgs.Total != 3 || len(imgs.Items) != 1 || imgs.Items[0].Ref != "docker.io/library/redis:7.2.4" {
		t.Fatalf("paged images: %+v %v", imgs, err)
	}

	wl, err := st.Workloads(ctx, store.ListOpts{Cluster: "prod", Q: "acme"})
	if err != nil || wl.Total != 1 || wl.Items[0].Name != "app" || wl.Items[0].Counts.Total != 2 || len(wl.Items[0].Images) != 2 {
		t.Fatalf("workloads search: %+v %v", wl, err)
	}

	vulns, err := st.Vulns(ctx, store.ListOpts{})
	if err != nil || vulns.Total != 4 || vulns.Items[0].ID != "CVE-1" { // KEV first (still open in staging)
		t.Fatalf("vulns: %+v %v", vulns, err)
	}
	vulns, err = st.Vulns(ctx, store.ListOpts{Cluster: "prod", Fixable: true})
	if err != nil || vulns.Total != 2 {
		t.Fatalf("fixable vulns: %+v %v", vulns, err)
	}
	vulns, err = st.Vulns(ctx, store.ListOpts{Sort: "severity", Desc: false, Limit: 1})
	if err != nil || vulns.Items[0].ID != "CVE-2" {
		t.Fatalf("vulns asc: %+v %v", vulns, err)
	}

	d, err := st.VulnDetail(ctx, "CVE-1", "prod")
	if err != nil || d == nil || len(d.Images) != 0 || len(d.Resolved) != 1 || d.Resolved[0].ResolvedAt == nil {
		t.Fatalf("CVE-1 in prod (resolved): %+v %v", d, err)
	}
	d, err = st.VulnDetail(ctx, "CVE-3", "prod")
	if err != nil || d == nil || len(d.Images) != 1 || len(d.Workloads) != 2 || d.Vuln.CVSS != 9.8 {
		t.Fatalf("CVE-3: %+v %v", d, err)
	}

	img, err := st.ImageDetail(ctx, "prod", "docker.io/library/nginx:1.27.2")
	if err != nil || img == nil || len(img.Vulns) != 2 || len(img.Workloads) != 2 || img.Vulns[0].ID != "CVE-3" {
		t.Fatalf("image detail: %+v %v", img, err)
	}
	if missing, err := st.ImageDetail(ctx, "prod", "nope"); err != nil || missing != nil {
		t.Fatalf("missing image: %+v %v", missing, err)
	}

	w, err := st.WorkloadDetail(ctx, store.WorkloadRef{Cluster: "prod", Namespace: "web", Kind: "Deployment", Name: "app"})
	if err != nil || w == nil || len(w.Images) != 2 {
		t.Fatalf("workload detail: %+v %v", w, err)
	}

	h, err := st.History(ctx, "prod", 7)
	if err != nil || len(h.Points) != 7 || h.Resolved != 2 || h.Opened != 5 {
		t.Fatalf("history: %+v %v", h, err)
	}
	last := h.Points[len(h.Points)-1]
	if last.Critical != 2 || last.Medium != 1 {
		t.Errorf("history today: %+v", last)
	}

	// Feed removes redis: its findings resolve on rematch.
	idx := index("n2")
	idx.Products = idx.Products[:1]
	if err := st.ApplyFeed(ctx, idx, `"e3"`, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RematchAll(ctx, now.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	var openRedis int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE product = 'redis' AND resolved_at IS NULL`).Scan(&openRedis); err != nil || openRedis != 0 {
		t.Fatalf("redis findings still open: %d %v", openRedis, err)
	}

	if ok, err := st.DeleteCluster(ctx, "staging"); err != nil || !ok {
		t.Fatalf("delete: %v %v", ok, err)
	}
	if n, err := st.PruneResolved(ctx, now.Add(time.Hour)); err != nil || n == 0 {
		t.Fatalf("prune: %d %v", n, err)
	}
}
