// Package feedsync mirrors the published CVE feed into PostgreSQL. One API
// replica at a time syncs (PostgreSQL advisory lock); after a change every
// cluster is re-matched so new CVEs show up without a new inventory report.
package feedsync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/huseyinbabal/cvedetector/apps/api/internal/store"
	"github.com/huseyinbabal/cvedetector/pkg/feed"
)

const syncLock = 0x63766566 // "cvef"

// Syncer syncs the feed.
type Syncer struct {
	base  *url.URL
	token string
	store *store.Store
	http  *http.Client
	log   *slog.Logger
}

// New creates a Syncer for a base URL ("https://…/" or "file:///…/"). token,
// when set, is sent as a bearer token: needed for a feed in a private GitHub
// repository (raw.githubusercontent.com).
func New(baseURL, token string, st *store.Store, log *slog.Logger) (*Syncer, error) {
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("feed url: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" && u.Scheme != "file" {
		return nil, fmt.Errorf("feed url: unsupported scheme %q", u.Scheme)
	}
	return &Syncer{base: u, token: token, store: st, http: &http.Client{Timeout: 2 * time.Minute}, log: log}, nil
}

// URL returns the redacted feed URL.
func (s *Syncer) URL() string { return s.base.Redacted() }

// Result describes one sync run.
type Result struct {
	Skipped  bool // another replica holds the lock
	Changed  bool
	Products int
	Shards   int
}

// Sync runs one sync if this replica gets the lock.
func (s *Syncer) Sync(ctx context.Context) (Result, error) {
	conn, err := s.store.Pool().Acquire(ctx)
	if err != nil {
		return Result{}, err
	}
	defer conn.Release()
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, syncLock).Scan(&got); err != nil {
		return Result{}, err
	}
	if !got {
		return Result{Skipped: true}, nil
	}
	defer func() { _, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, syncLock) }()

	res, err := s.sync(ctx)
	if rerr := s.store.RecordFeedAttempt(ctx, s.URL(), time.Now(), err); rerr != nil && err == nil {
		err = rerr
	}
	return res, err
}

func (s *Syncer) sync(ctx context.Context) (Result, error) {
	state, err := s.store.GetFeedState(ctx)
	if err != nil {
		return Result{}, err
	}
	etag := state.ETag
	if state.URL != s.URL() {
		etag = "" // feed source changed: fetch everything
	}
	body, newTag, notModified, err := s.get(ctx, "v1/index.json", etag)
	if err != nil {
		return Result{}, err
	}
	if notModified {
		return Result{}, nil
	}
	var idx feed.Index
	if err := json.Unmarshal(body, &idx); err != nil {
		return Result{}, fmt.Errorf("decode index: %w", err)
	}
	if idx.SchemaVersion != feed.SchemaVersion {
		return Result{}, fmt.Errorf("unsupported feed schemaVersion %d (supported: %d)", idx.SchemaVersion, feed.SchemaVersion)
	}
	have, err := s.store.ProductHashes(ctx)
	if err != nil {
		return Result{}, err
	}
	shards := map[string]*feed.Shard{}
	for _, p := range idx.Products {
		if have[p.ID] == p.SHA256 && p.SHA256 != "" {
			continue
		}
		sh, err := s.fetchShard(ctx, p)
		if err != nil {
			return Result{}, err // keep the previous feed intact
		}
		shards[p.ID] = sh
	}
	// EPSS ships separately; fetch it before writing anything so a bad file
	// leaves the previous feed intact. Shards reset scores, so re-apply then too.
	var epss *feed.EPSSFile
	if idx.EPSS != nil && (len(shards) > 0 || idx.EPSS.SHA256 != state.EPSSSHA) {
		if epss, err = s.fetchEPSS(ctx, *idx.EPSS); err != nil {
			return Result{}, err
		}
	}
	if err := s.store.ApplyFeed(ctx, &idx, newTag, shards); err != nil {
		return Result{}, err
	}
	if epss != nil {
		n, err := s.store.ApplyEPSS(ctx, epss.Scores, idx.EPSS.SHA256)
		if err != nil {
			return Result{}, err
		}
		s.log.Info("epss applied", "scores", len(epss.Scores), "updated", n)
	}
	s.log.Info("feed updated", "generatedAt", idx.GeneratedAt, "products", len(idx.Products), "shards", len(shards))
	rematched, err := s.store.RematchAll(ctx, time.Now())
	for c, r := range rematched {
		if r.Opened > 0 || r.Resolved > 0 {
			s.log.Info("cluster re-matched", "cluster", c, "opened", r.Opened, "resolved", r.Resolved, "open", r.Open)
		}
	}
	return Result{Changed: true, Products: len(idx.Products), Shards: len(shards)}, err
}

func (s *Syncer) fetchEPSS(ctx context.Context, f feed.File) (*feed.EPSSFile, error) {
	if strings.Contains(f.Path, "..") || strings.HasPrefix(f.Path, "/") {
		return nil, fmt.Errorf("refusing epss path %q", f.Path)
	}
	body, _, _, err := s.get(ctx, "v1/"+f.Path, "")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != f.SHA256 {
		return nil, fmt.Errorf("checksum mismatch for %s: got %s want %s", f.Path, got, f.SHA256)
	}
	var e feed.EPSSFile
	if err := json.Unmarshal(body, &e); err != nil {
		return nil, fmt.Errorf("decode %s: %w", f.Path, err)
	}
	return &e, nil
}

func (s *Syncer) fetchShard(ctx context.Context, p feed.Product) (*feed.Shard, error) {
	if strings.Contains(p.Shard, "..") || strings.HasPrefix(p.Shard, "/") {
		return nil, fmt.Errorf("refusing shard path %q", p.Shard)
	}
	body, _, _, err := s.get(ctx, "v1/"+p.Shard, "")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != p.SHA256 {
		return nil, fmt.Errorf("checksum mismatch for %s: got %s want %s", p.Shard, got, p.SHA256)
	}
	var sh feed.Shard
	if err := json.Unmarshal(body, &sh); err != nil {
		return nil, fmt.Errorf("decode %s: %w", p.Shard, err)
	}
	if sh.SchemaVersion != feed.SchemaVersion {
		return nil, fmt.Errorf("%s: unsupported schemaVersion %d", p.Shard, sh.SchemaVersion)
	}
	return &sh, nil
}

func (s *Syncer) get(ctx context.Context, rel, etag string) (body []byte, newTag string, notModified bool, err error) {
	u := s.base.ResolveReference(&url.URL{Path: rel})
	if u.Scheme == "file" {
		body, err = os.ReadFile(u.Path)
		if err == nil {
			sum := sha256.Sum256(body)
			newTag = hex.EncodeToString(sum[:])
			if newTag == etag {
				return nil, etag, true, nil
			}
		}
		return body, newTag, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", false, err
	}
	req.Header.Set("User-Agent", "cvedetector-api/1")
	if s.token != "" {
		// Go's client drops this header if a redirect leaves the host.
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, "", false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, etag, true, nil
	case http.StatusOK:
		body, err = io.ReadAll(io.LimitReader(resp.Body, 256<<20))
		if err != nil {
			return nil, "", false, err
		}
		newTag = resp.Header.Get("ETag")
		if newTag == "" {
			// No ETag from the server: use the content hash so an unchanged
			// index is still recognized.
			sum := sha256.Sum256(body)
			newTag = "sha256:" + hex.EncodeToString(sum[:])
		}
		if newTag == etag {
			return nil, etag, true, nil
		}
		return body, newTag, false, nil
	}
	return nil, "", false, fmt.Errorf("GET %s: %s", u.Redacted(), resp.Status)
}

// Run syncs immediately and then every interval until ctx is done.
func (s *Syncer) Run(ctx context.Context, interval time.Duration, onError func()) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		res, err := s.Sync(ctx)
		switch {
		case err != nil:
			s.log.Warn("feed sync failed; keeping the previous feed", "err", err)
			if onError != nil {
				onError()
			}
		case res.Skipped:
			s.log.Debug("feed sync skipped: another replica holds the lock")
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
