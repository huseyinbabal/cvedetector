// Package metrics exposes vulnerability gauges read from PostgreSQL. Every API
// replica reports the same values; aggregate with max(), not sum().
package metrics

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// Collector queries the database at most once per TTL.
type Collector struct {
	pool             *pgxpool.Pool
	log              *slog.Logger
	ttl              time.Duration
	workloadMetrics  bool
	vulns, kev       *prometheus.Desc
	clusterVulns     *prometheus.Desc
	clusterKEV       *prometheus.Desc
	images, reportAt *prometheus.Desc
	feedAge          *prometheus.Desc
	workload         *prometheus.Desc

	mu      sync.Mutex
	cached  []prometheus.Metric
	fetched time.Time
}

// New creates a collector. workloadMetrics enables a per-workload series
// (one per workload: mind the cardinality on large clusters).
func New(pool *pgxpool.Pool, log *slog.Logger, workloadMetrics bool) *Collector {
	return &Collector{
		pool: pool, log: log, ttl: 30 * time.Second, workloadMetrics: workloadMetrics,
		vulns: prometheus.NewDesc("cvedetector_vulnerabilities", "Distinct open vulnerabilities affecting running workloads.", []string{"cluster", "namespace", "severity"}, nil),
		kev:   prometheus.NewDesc("cvedetector_kev_vulnerabilities", "Distinct open vulnerabilities listed in CISA KEV.", []string{"cluster", "namespace"}, nil),
		clusterVulns: prometheus.NewDesc("cvedetector_cluster_vulnerabilities",
			"Distinct open vulnerabilities per cluster (a CVE in several namespaces counts once).", []string{"cluster", "severity"}, nil),
		clusterKEV: prometheus.NewDesc("cvedetector_cluster_kev_vulnerabilities",
			"Distinct open CISA KEV vulnerabilities per cluster.", []string{"cluster"}, nil),
		images:   prometheus.NewDesc("cvedetector_images", "Distinct running images by match status.", []string{"cluster", "status"}, nil),
		reportAt: prometheus.NewDesc("cvedetector_cluster_last_report_timestamp_seconds", "Unix time of the last inventory report.", []string{"cluster"}, nil),
		feedAge:  prometheus.NewDesc("cvedetector_feed_age_seconds", "Seconds since the stored feed was generated (-1 when none).", nil, nil),
		workload: prometheus.NewDesc("cvedetector_workload_max_severity", "1 per workload, labelled with its highest severity.", []string{"cluster", "namespace", "kind", "name", "severity"}, nil),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{c.vulns, c.kev, c.clusterVulns, c.clusterKEV, c.images, c.reportAt, c.feedAge, c.workload} {
		ch <- d
	}
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.fetched) > c.ttl {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		ms, err := c.query(ctx)
		cancel()
		if err != nil {
			c.log.Warn("metrics query failed", "err", err)
		} else {
			c.cached, c.fetched = ms, time.Now()
		}
	}
	for _, m := range c.cached {
		ch <- m
	}
}

func (c *Collector) query(ctx context.Context) ([]prometheus.Metric, error) {
	var out []prometheus.Metric
	add := func(d *prometheus.Desc, v float64, labels ...string) {
		out = append(out, prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...))
	}
	rows, err := c.pool.Query(ctx, `
		SELECT wi.cluster, wi.namespace, v.severity, count(DISTINCT (f.product, f.vuln_id)),
		       count(DISTINCT (f.product, f.vuln_id)) FILTER (WHERE v.kev)
		FROM findings f
		JOIN workload_images wi ON wi.cluster = f.cluster AND wi.ref = f.ref
		JOIN vulns v ON v.product = f.product AND v.id = f.vuln_id
		WHERE f.resolved_at IS NULL
		GROUP BY 1, 2, 3`)
	if err != nil {
		return nil, err
	}
	kev := map[[2]string]float64{}
	for rows.Next() {
		var cl, ns, sev string
		var n, k float64
		if err := rows.Scan(&cl, &ns, &sev, &n, &k); err != nil {
			return nil, err
		}
		add(c.vulns, n, cl, ns, sev)
		kev[[2]string{cl, ns}] += k
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for key, n := range kev {
		add(c.kev, n, key[0], key[1])
	}
	rows, err = c.pool.Query(ctx, `
		SELECT f.cluster, v.severity, count(DISTINCT (f.product, f.vuln_id)),
		       count(DISTINCT (f.product, f.vuln_id)) FILTER (WHERE v.kev)
		FROM findings f JOIN vulns v ON v.product = f.product AND v.id = f.vuln_id
		WHERE f.resolved_at IS NULL
		GROUP BY 1, 2`)
	if err != nil {
		return nil, err
	}
	clusterKEV := map[string]float64{}
	for rows.Next() {
		var cl, sev string
		var n, k float64
		if err := rows.Scan(&cl, &sev, &n, &k); err != nil {
			return nil, err
		}
		add(c.clusterVulns, n, cl, sev)
		clusterKEV[cl] += k
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Every cluster gets a KEV series (0 included) so alerts and panels can rely on it.
	rows, err = c.pool.Query(ctx, `SELECT name FROM clusters`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var cl string
		if err := rows.Scan(&cl); err != nil {
			return nil, err
		}
		add(c.clusterKEV, clusterKEV[cl], cl)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = c.pool.Query(ctx, `SELECT cluster, status, count(*) FROM images GROUP BY 1, 2`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var cl, st string
		var n float64
		if err := rows.Scan(&cl, &st, &n); err != nil {
			return nil, err
		}
		add(c.images, n, cl, st)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = c.pool.Query(ctx, `SELECT name, extract(epoch FROM last_report) FROM clusters`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var cl string
		var ts float64
		if err := rows.Scan(&cl, &ts); err != nil {
			return nil, err
		}
		add(c.reportAt, ts, cl)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var age *float64
	if err := c.pool.QueryRow(ctx, `SELECT extract(epoch FROM now() - generated_at) FROM feed_state WHERE id = 1`).Scan(&age); err != nil {
		return nil, err
	}
	if age == nil {
		add(c.feedAge, -1)
	} else {
		add(c.feedAge, *age)
	}
	if c.workloadMetrics {
		rows, err = c.pool.Query(ctx, `
			SELECT w.cluster, w.namespace, w.kind, w.name,
			       coalesce(max(CASE v.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END), -1)
			FROM workloads w
			LEFT JOIN workload_images wi USING (cluster, namespace, kind, name)
			LEFT JOIN findings f ON f.cluster = wi.cluster AND f.ref = wi.ref AND f.resolved_at IS NULL
			LEFT JOIN vulns v ON v.product = f.product AND v.id = f.vuln_id
			GROUP BY 1, 2, 3, 4`)
		if err != nil {
			return nil, err
		}
		names := map[int]string{4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "UNKNOWN", -1: "NONE"}
		for rows.Next() {
			var cl, ns, kind, name string
			var r int
			if err := rows.Scan(&cl, &ns, &kind, &name, &r); err != nil {
				return nil, err
			}
			add(c.workload, 1, cl, ns, kind, name, names[r])
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}
