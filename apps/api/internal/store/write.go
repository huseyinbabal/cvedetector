// Package store holds all SQL: feed mirroring, inventory ingestion with
// finding reconciliation, and the read queries behind the API.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/huseyinbabal/cvedetector/apps/api/internal/matcher"
	"github.com/huseyinbabal/cvedetector/pkg/feed"
	"github.com/huseyinbabal/cvedetector/pkg/inventory"
)

// Store wraps the pool and caches the matcher catalog per feed revision.
type Store struct {
	pool *pgxpool.Pool

	mu       sync.Mutex
	catRev   int64
	catalog  *matcher.Catalog
	catLoads int
}

// New returns a Store.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool, catRev: -1} }

// Pool exposes the pool for health checks and locks.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// ---------------------------------------------------------------- feed

// FeedState mirrors the feed_state row.
type FeedState struct {
	URL         string     `json:"url"`
	GeneratedAt *time.Time `json:"indexGeneratedAt,omitempty"`
	ETag        string     `json:"-"`
	EPSSSHA     string     `json:"-"`
	LastAttempt *time.Time `json:"lastAttempt,omitempty"`
	LastSuccess *time.Time `json:"lastSuccess,omitempty"`
	LastError   string     `json:"lastError,omitempty"`
	Revision    int64      `json:"revision"`
	Products    int        `json:"products"`
	Vulns       int        `json:"vulns"`
}

// GetFeedState returns the feed state with product and vulnerability counts.
func (s *Store) GetFeedState(ctx context.Context) (FeedState, error) {
	var f FeedState
	err := s.pool.QueryRow(ctx, `
		SELECT url, generated_at, etag, epss_sha, last_attempt, last_success, last_error, revision,
		       (SELECT count(*) FROM products), (SELECT count(*) FROM vulns)
		FROM feed_state WHERE id = 1`).
		Scan(&f.URL, &f.GeneratedAt, &f.ETag, &f.EPSSSHA, &f.LastAttempt, &f.LastSuccess, &f.LastError, &f.Revision, &f.Products, &f.Vulns)
	return f, err
}

// RecordFeedAttempt stores the outcome of a sync attempt.
func (s *Store) RecordFeedAttempt(ctx context.Context, url string, at time.Time, syncErr error) error {
	if syncErr != nil {
		_, err := s.pool.Exec(ctx, `UPDATE feed_state SET url = $1, last_attempt = $2, last_error = $3 WHERE id = 1`, url, at, syncErr.Error())
		return err
	}
	_, err := s.pool.Exec(ctx, `UPDATE feed_state SET url = $1, last_attempt = $2, last_success = $2, last_error = '' WHERE id = 1`, url, at)
	return err
}

// ProductHashes returns product id -> stored shard sha256.
func (s *Store) ProductHashes(ctx context.Context) (map[string]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, sha256 FROM products`)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for rows.Next() {
		var id, sha string
		if err := rows.Scan(&id, &sha); err != nil {
			return nil, err
		}
		out[id] = sha
	}
	return out, rows.Err()
}

// ApplyFeed writes a new index in one transaction: product metadata is always
// updated (image mappings can change without the shard changing), vulns are
// replaced for products present in shards, products missing from the index are
// deleted. The revision is bumped so catalogs reload.
func (s *Store) ApplyFeed(ctx context.Context, idx *feed.Index, etag string, shards map[string]*feed.Shard) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		ids := make([]string, 0, len(idx.Products))
		for _, p := range idx.Products {
			ids = append(ids, p.ID)
			if _, err := tx.Exec(ctx, `
				INSERT INTO products (id, name, images, version_pattern, min_segments, sha256, vuln_count)
				VALUES ($1, $2, $3, $4, $5, $6, $7)
				ON CONFLICT (id) DO UPDATE SET name = $2, images = $3, version_pattern = $4, min_segments = $5,
					sha256 = CASE WHEN $8 THEN $6 ELSE products.sha256 END, vuln_count = $7`,
				p.ID, p.Name, p.Images, p.VersionPattern, p.MinSegments, p.SHA256, p.VulnCount, shards[p.ID] != nil); err != nil {
				return fmt.Errorf("product %s: %w", p.ID, err)
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM products WHERE NOT (id = ANY($1))`, ids); err != nil {
			return err
		}
		for id, sh := range shards {
			if _, err := tx.Exec(ctx, `DELETE FROM vulns WHERE product = $1`, id); err != nil {
				return err
			}
			rows := make([][]any, 0, len(sh.Vulns))
			for _, v := range sh.Vulns {
				affected, _ := json.Marshal(v.Affected)
				var published *time.Time
				if !v.Published.IsZero() {
					published = &v.Published
				}
				rows = append(rows, []any{id, v.ID, nonNil(v.Aliases), v.Summary, v.Severity, v.CVSS, v.CVSSVector, v.EPSS, v.KEV, published, nonNil(v.References), affected})
			}
			if _, err := tx.CopyFrom(ctx, pgx.Identifier{"vulns"},
				[]string{"product", "id", "aliases", "summary", "severity", "cvss", "cvss_vector", "epss", "kev", "published", "refs", "affected"},
				pgx.CopyFromRows(dedupVulnRows(rows))); err != nil {
				return fmt.Errorf("vulns %s: %w", id, err)
			}
		}
		_, err := tx.Exec(ctx, `UPDATE feed_state SET generated_at = $1, etag = $2, revision = revision + 1 WHERE id = 1`, idx.GeneratedAt, etag)
		return err
	})
}

// ApplyEPSS sets EPSS scores (keyed by CVE id) on every vulnerability whose id
// or alias matches, and records the applied file checksum. Vulnerabilities
// without a score get 0.
func (s *Store) ApplyEPSS(ctx context.Context, scores map[string]float64, sha string) (int, error) {
	rows, err := s.pool.Query(ctx, `SELECT product, id, aliases FROM vulns`)
	if err != nil {
		return 0, err
	}
	var products, ids []string
	var values []float64
	for rows.Next() {
		var product, id string
		var aliases []string
		if err := rows.Scan(&product, &id, &aliases); err != nil {
			return 0, err
		}
		best := scores[id]
		for _, a := range aliases {
			best = max(best, scores[a])
		}
		products, ids, values = append(products, product), append(ids, id), append(values, best)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE vulns v SET epss = u.epss
			FROM unnest($1::text[], $2::text[], $3::float8[]) AS u(product, id, epss)
			WHERE v.product = u.product AND v.id = u.id AND v.epss IS DISTINCT FROM u.epss`, products, ids, values)
		if err != nil {
			return err
		}
		n = int(tag.RowsAffected())
		_, err = tx.Exec(ctx, `UPDATE feed_state SET epss_sha = $1 WHERE id = 1`, sha)
		return err
	})
	return n, err
}

// dedupVulnRows drops repeated (product, id) pairs defensively; the feed merges
// by id, but a duplicate would abort the COPY.
func dedupVulnRows(rows [][]any) [][]any {
	seen := map[string]bool{}
	out := rows[:0]
	for _, r := range rows {
		k := r[1].(string)
		if !seen[k] {
			seen[k] = true
			out = append(out, r)
		}
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Catalog returns the matcher catalog for the current feed revision, loading
// it from the database when the revision changed.
func (s *Store) Catalog(ctx context.Context) (*matcher.Catalog, int64, error) {
	var rev int64
	if err := s.pool.QueryRow(ctx, `SELECT revision FROM feed_state WHERE id = 1`).Scan(&rev); err != nil {
		return nil, 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.catalog != nil && s.catRev == rev {
		return s.catalog, rev, nil
	}
	var products []feed.Product
	rows, err := s.pool.Query(ctx, `SELECT id, name, images, version_pattern, min_segments FROM products`)
	if err != nil {
		return nil, 0, err
	}
	for rows.Next() {
		var p feed.Product
		if err := rows.Scan(&p.ID, &p.Name, &p.Images, &p.VersionPattern, &p.MinSegments); err != nil {
			return nil, 0, err
		}
		products = append(products, p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	vulns := map[string][]feed.Vuln{}
	rows, err = s.pool.Query(ctx, `SELECT product, id, affected FROM vulns`)
	if err != nil {
		return nil, 0, err
	}
	for rows.Next() {
		var product string
		var v feed.Vuln
		var affected []byte
		if err := rows.Scan(&product, &v.ID, &affected); err != nil {
			return nil, 0, err
		}
		if err := json.Unmarshal(affected, &v.Affected); err != nil {
			return nil, 0, fmt.Errorf("vuln %s/%s affected: %w", product, v.ID, err)
		}
		vulns[product] = append(vulns[product], v)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	s.catalog, s.catRev = matcher.NewCatalog(products, vulns), rev
	s.catLoads++
	return s.catalog, rev, nil
}

// ---------------------------------------------------------------- ingest

// IngestResult summarizes an applied report.
type IngestResult struct {
	Images   int  `json:"images"`
	Opened   int  `json:"opened"`
	Resolved int  `json:"resolved"`
	Open     int  `json:"open"`
	Changed  bool `json:"changed"`
}

// errNoChange aborts the ingest transaction when the inventory is unchanged.
var errNoChange = errors.New("no change")

// ApplyReport replaces a cluster's inventory and reconciles its findings. If
// the inventory fingerprint is unchanged only last_report is updated.
func (s *Store) ApplyReport(ctx context.Context, r *inventory.Report, now time.Time) (IngestResult, error) {
	cat, _, err := s.Catalog(ctx)
	if err != nil {
		return IngestResult{}, err
	}
	fp := r.Fingerprint()
	var res IngestResult
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockCluster(ctx, tx, r.Cluster); err != nil {
			return err
		}
		var prev string
		err := tx.QueryRow(ctx, `
			INSERT INTO clusters (name, agent_version, first_seen, last_report, fingerprint) VALUES ($1, $2, $3, $3, '')
			ON CONFLICT (name) DO UPDATE SET agent_version = $2, last_report = $3
			RETURNING fingerprint`, r.Cluster, r.AgentVersion, now).Scan(&prev)
		if err != nil {
			return err
		}
		if prev == fp {
			return errNoChange
		}
		res.Changed = true
		if _, err := tx.Exec(ctx, `DELETE FROM workloads WHERE cluster = $1`, r.Cluster); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM images WHERE cluster = $1`, r.Cluster); err != nil {
			return err
		}
		images := make([]imageMatch, 0, len(r.Images))
		imgRows := make([][]any, 0, len(r.Images))
		for _, img := range r.Images {
			m := cat.Match(img.Repository, img.Tag)
			images = append(images, imageMatch{ref: img.Ref, result: m})
			imgRows = append(imgRows, []any{r.Cluster, img.Ref, img.Repository, img.Tag, nonNil(img.Digests), img.Pods, m.Product, m.Version, m.Status})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"images"},
			[]string{"cluster", "ref", "repository", "tag", "digests", "pods", "product", "version", "status"}, pgx.CopyFromRows(imgRows)); err != nil {
			return fmt.Errorf("images: %w", err)
		}
		var wRows, wiRows [][]any
		for _, w := range r.Workloads {
			wRows = append(wRows, []any{r.Cluster, w.Namespace, w.Kind, w.Name, w.Pods})
			for _, ref := range w.Images {
				wiRows = append(wiRows, []any{r.Cluster, w.Namespace, w.Kind, w.Name, ref})
			}
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"workloads"}, []string{"cluster", "namespace", "kind", "name", "pods"}, pgx.CopyFromRows(wRows)); err != nil {
			return fmt.Errorf("workloads: %w", err)
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"workload_images"}, []string{"cluster", "namespace", "kind", "name", "ref"}, pgx.CopyFromRows(wiRows)); err != nil {
			return fmt.Errorf("workload images: %w", err)
		}
		res.Images = len(images)
		if err := reconcile(ctx, tx, r.Cluster, images, now, &res); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE clusters SET fingerprint = $2 WHERE name = $1`, r.Cluster, fp)
		return err
	})
	if errors.Is(err, errNoChange) {
		// The transaction rolled back; record the heartbeat separately.
		_, err = s.pool.Exec(ctx, `UPDATE clusters SET agent_version = $2, last_report = $3 WHERE name = $1`, r.Cluster, r.AgentVersion, now)
		return IngestResult{Images: len(r.Images)}, err
	}
	return res, err
}

// RematchAll re-evaluates every cluster's images against the current catalog,
// after a feed change.
func (s *Store) RematchAll(ctx context.Context, now time.Time) (map[string]IngestResult, error) {
	cat, _, err := s.Catalog(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT name FROM clusters ORDER BY name`)
	if err != nil {
		return nil, err
	}
	clusters, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	out := map[string]IngestResult{}
	for _, c := range clusters {
		var res IngestResult
		err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			if err := lockCluster(ctx, tx, c); err != nil {
				return err
			}
			rows, err := tx.Query(ctx, `SELECT ref, repository, tag FROM images WHERE cluster = $1`, c)
			if err != nil {
				return err
			}
			type img struct{ ref, repo, tag string }
			list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (img, error) {
				var i img
				return i, r.Scan(&i.ref, &i.repo, &i.tag)
			})
			if err != nil {
				return err
			}
			images := make([]imageMatch, 0, len(list))
			batch := &pgx.Batch{}
			for _, i := range list {
				m := cat.Match(i.repo, i.tag)
				images = append(images, imageMatch{ref: i.ref, result: m})
				batch.Queue(`UPDATE images SET product = $3, version = $4, status = $5 WHERE cluster = $1 AND ref = $2`, c, i.ref, m.Product, m.Version, m.Status)
			}
			if err := tx.SendBatch(ctx, batch).Close(); err != nil {
				return err
			}
			res.Images = len(images)
			return reconcile(ctx, tx, c, images, now, &res)
		})
		if err != nil {
			return out, fmt.Errorf("rematch %s: %w", c, err)
		}
		out[c] = res
	}
	return out, nil
}

type imageMatch struct {
	ref    string
	result matcher.Result
}

// lockCluster serializes ingest and rematch of one cluster across replicas.
func lockCluster(ctx context.Context, tx pgx.Tx, cluster string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('cluster:' || $1, 0))`, cluster)
	return err
}

// reconcile turns the desired set of (image, vuln) pairs into finding rows:
// new pairs are opened, vanished pairs resolved, the rest touched.
func reconcile(ctx context.Context, tx pgx.Tx, cluster string, images []imageMatch, now time.Time, res *IngestResult) error {
	type key struct{ ref, vuln string }
	type want struct{ product, fixedIn string }
	desired := map[key]want{}
	for _, im := range images {
		for _, f := range im.result.Findings {
			desired[key{im.ref, f.VulnID}] = want{im.result.Product, f.FixedIn}
		}
	}

	rows, err := tx.Query(ctx, `SELECT id, ref, vuln_id, fixed_in FROM findings WHERE cluster = $1 AND resolved_at IS NULL`, cluster)
	if err != nil {
		return err
	}
	var resolve []int64
	open := map[key]bool{}
	fixChanged := &pgx.Batch{}
	for rows.Next() {
		var id int64
		var k key
		var fixedIn string
		if err := rows.Scan(&id, &k.ref, &k.vuln, &fixedIn); err != nil {
			return err
		}
		w, ok := desired[k]
		if !ok {
			resolve = append(resolve, id)
			continue
		}
		open[k] = true
		if w.fixedIn != fixedIn {
			fixChanged.Queue(`UPDATE findings SET fixed_in = $2 WHERE id = $1`, id, w.fixedIn)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(resolve) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE findings SET resolved_at = $2 WHERE id = ANY($1)`, resolve, now); err != nil {
			return err
		}
	}
	if fixChanged.Len() > 0 {
		if err := tx.SendBatch(ctx, fixChanged).Close(); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE findings SET last_seen = $2 WHERE cluster = $1 AND resolved_at IS NULL`, cluster, now); err != nil {
		return err
	}
	var insert [][]any
	for k, w := range desired {
		if !open[k] {
			insert = append(insert, []any{cluster, k.ref, w.product, k.vuln, w.fixedIn, now, now})
		}
	}
	if len(insert) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"findings"},
			[]string{"cluster", "ref", "product", "vuln_id", "fixed_in", "first_seen", "last_seen"}, pgx.CopyFromRows(insert)); err != nil {
			return fmt.Errorf("findings: %w", err)
		}
	}
	res.Opened, res.Resolved, res.Open = len(insert), len(resolve), len(desired)
	return nil
}

// DeleteCluster removes a cluster and all its data (including history).
func (s *Store) DeleteCluster(ctx context.Context, name string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM clusters WHERE name = $1`, name)
	return tag.RowsAffected() > 0, err
}

// PruneResolved deletes findings resolved before cutoff.
func (s *Store) PruneResolved(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM findings WHERE resolved_at < $1`, cutoff)
	return tag.RowsAffected(), err
}
