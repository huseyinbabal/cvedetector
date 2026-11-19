package feedsync_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/huseyinbabal/cvedetector/apps/api/internal/db"
	"github.com/huseyinbabal/cvedetector/apps/api/internal/feedsync"
	"github.com/huseyinbabal/cvedetector/apps/api/internal/store"
	"github.com/huseyinbabal/cvedetector/pkg/feed"
)

const token = "secret"

type fakeFeed struct {
	mu                 sync.Mutex
	index, shard, epss []byte
	corrupt            atomic.Bool
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (f *fakeFeed) set(scores map[string]float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shard, _ = json.Marshal(feed.Shard{SchemaVersion: 1, Product: "nginx", Vulns: []feed.Vuln{
		{ID: "CVE-1", Severity: feed.SeverityHigh, Affected: []feed.Range{{LT: "1.27.2"}}},
		{ID: "GHSA-2", Aliases: []string{"CVE-2"}, Severity: feed.SeverityLow, Affected: []feed.Range{{}}},
	}})
	f.epss, _ = json.Marshal(feed.EPSSFile{SchemaVersion: 1, Scores: scores})
	f.index, _ = json.Marshal(feed.Index{SchemaVersion: 1,
		Products: []feed.Product{{ID: "nginx", Name: "NGINX", Images: []string{"docker.io/library/nginx"}, Shard: "products/nginx.json", SHA256: sum(f.shard), VulnCount: 2}},
		EPSS:     &feed.File{Path: "epss.json", SHA256: sum(f.epss)},
	})
}

// ServeHTTP requires the bearer token and sends no ETag, like
// raw.githubusercontent.com behind a private repo without caching headers.
func (f *fakeFeed) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+token {
		http.Error(w, "not found", http.StatusNotFound) // GitHub answers 404 for private content
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/v1/index.json":
		_, _ = w.Write(f.index)
	case "/v1/epss.json":
		_, _ = w.Write(f.epss)
	case "/v1/products/nginx.json":
		if f.corrupt.Load() {
			_, _ = w.Write([]byte(`{"tampered":true}`))
			return
		}
		_, _ = w.Write(f.shard)
	default:
		http.NotFound(w, r)
	}
}

func epssOf(t *testing.T, st *store.Store, id string) float64 {
	t.Helper()
	var v float64
	if err := st.Pool().QueryRow(context.Background(), `SELECT epss FROM vulns WHERE id = $1`, id).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSync(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := db.Migrate(ctx, pool, log); err != nil {
		t.Fatal(err)
	}
	st := store.New(pool)
	ff := &fakeFeed{}
	ff.set(map[string]float64{"CVE-1": 0.5, "CVE-2": 0.25})
	srv := httptest.NewServer(ff)
	defer srv.Close()

	// Private feed without a token: fails, nothing stored.
	anon, _ := feedsync.New(srv.URL, "", st, log)
	if _, err := anon.Sync(ctx); err == nil {
		t.Fatal("expected an error without a token")
	}

	s, err := feedsync.New(srv.URL, token, st, log)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Sync(ctx)
	if err != nil || !res.Changed || res.Shards != 1 {
		t.Fatalf("first sync: %+v %v", res, err)
	}
	if epssOf(t, st, "CVE-1") != 0.5 || epssOf(t, st, "GHSA-2") != 0.25 {
		t.Fatal("EPSS not applied (by id and by alias)")
	}
	state, _ := st.GetFeedState(ctx)
	if state.Vulns != 2 || state.Revision != 1 || state.LastError != "" {
		t.Fatalf("state after first sync: %+v", state)
	}

	// Same content, no ETag: unchanged.
	if res, err = s.Sync(ctx); err != nil || res.Changed {
		t.Fatalf("second sync should be a no-op: %+v %v", res, err)
	}

	// Only EPSS changes: scores update, shards are not re-downloaded.
	ff.set(map[string]float64{"CVE-1": 0.75, "CVE-2": 0.25})
	if res, err = s.Sync(ctx); err != nil || !res.Changed || res.Shards != 0 {
		t.Fatalf("epss-only sync: %+v %v", res, err)
	}
	if epssOf(t, st, "CVE-1") != 0.75 {
		t.Fatal("EPSS update not applied")
	}

	// A shard failing its checksum: rejected, old data kept, error recorded.
	ff.mu.Lock()
	var idx feed.Index
	_ = json.Unmarshal(ff.index, &idx)
	idx.Products[0].SHA256 = "deadbeef"
	ff.index, _ = json.Marshal(idx)
	ff.mu.Unlock()
	ff.corrupt.Store(true)
	if _, err := s.Sync(ctx); err == nil {
		t.Fatal("expected checksum error")
	}
	state, _ = st.GetFeedState(ctx)
	if state.Vulns != 2 || state.LastError == "" || epssOf(t, st, "CVE-1") != 0.75 {
		t.Fatalf("failed sync must keep the previous feed and record the error: %+v", state)
	}
}
