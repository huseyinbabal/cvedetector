package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---------------------------------------------------------------- types

// Counts aggregates distinct vulnerabilities by severity.
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	Total    int `json:"total"`
	KEV      int `json:"kev"`
	Fixable  int `json:"fixable"`
}

// MaxSeverity of the counts, "NONE" when empty.
func (c Counts) MaxSeverity() string {
	switch {
	case c.Critical > 0:
		return "CRITICAL"
	case c.High > 0:
		return "HIGH"
	case c.Medium > 0:
		return "MEDIUM"
	case c.Low > 0:
		return "LOW"
	case c.Unknown > 0:
		return "UNKNOWN"
	}
	return "NONE"
}

// WorkloadRef identifies a workload.
type WorkloadRef struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
}

// Image is an image row with its open-vulnerability counts.
type Image struct {
	Cluster     string   `json:"cluster"`
	Ref         string   `json:"ref"`
	Repository  string   `json:"repository"`
	Tag         string   `json:"tag,omitempty"`
	Digests     []string `json:"digests,omitempty"`
	Product     string   `json:"product,omitempty"`
	ProductName string   `json:"productName,omitempty"`
	Version     string   `json:"version,omitempty"`
	Status      string   `json:"status"`
	Pods        int      `json:"pods"`
	Workloads   int      `json:"workloads"`
	Counts      Counts   `json:"counts"`
	MaxSeverity string   `json:"maxSeverity"`
}

// Workload is a workload row with counts.
type Workload struct {
	WorkloadRef
	Pods        int      `json:"pods"`
	Images      []string `json:"images"`
	Counts      Counts   `json:"counts"`
	MaxSeverity string   `json:"maxSeverity"`
}

// Vuln is a vulnerability seen in the selected clusters.
type Vuln struct {
	ID         string     `json:"id"`
	Product    string     `json:"product"`
	Aliases    []string   `json:"aliases,omitempty"`
	Summary    string     `json:"summary,omitempty"`
	Severity   string     `json:"severity"`
	CVSS       float64    `json:"cvss,omitempty"`
	CVSSVector string     `json:"cvssVector,omitempty"`
	EPSS       float64    `json:"epss,omitempty"`
	KEV        bool       `json:"kev,omitempty"`
	Published  *time.Time `json:"published,omitempty"`
	References []string   `json:"references,omitempty"`
	Fixable    bool       `json:"fixable"`
	FirstSeen  *time.Time `json:"firstSeen,omitempty"`
	Images     int        `json:"images"`
	Workloads  int        `json:"workloads"`
	Clusters   int        `json:"clusters"`
}

// Page is a paginated list.
type Page[T any] struct {
	Items []T `json:"items"`
	Total int `json:"total"`
}

// ListOpts are the shared list parameters. Zero values mean "no filter".
type ListOpts struct {
	Cluster     string
	Namespace   string
	Q           string
	MinSeverity int // 1 low .. 4 critical
	Status      string
	Product     string
	KEV         bool
	Fixable     bool
	Ref         string // exact image ref
	Kind        string // exact workload kind
	Name        string // exact workload name
	Sort        string
	Desc        bool
	Limit       int
	Offset      int
}

const sevRank = `CASE %s WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END`

func rank(col string) string { return fmt.Sprintf(sevRank, col) }

// countCols aggregates distinct vulnerability keys from a row source with
// columns k (product|vuln), severity, kev, fixable.
const countCols = `
	count(DISTINCT k) FILTER (WHERE severity = 'CRITICAL') AS critical,
	count(DISTINCT k) FILTER (WHERE severity = 'HIGH')     AS high,
	count(DISTINCT k) FILTER (WHERE severity = 'MEDIUM')   AS medium,
	count(DISTINCT k) FILTER (WHERE severity = 'LOW')      AS low,
	count(DISTINCT k) FILTER (WHERE severity NOT IN ('CRITICAL','HIGH','MEDIUM','LOW')) AS unknown,
	count(DISTINCT k) AS total,
	count(DISTINCT k) FILTER (WHERE kev) AS kev,
	count(DISTINCT k) FILTER (WHERE fixable) AS fixable`

// countsWeight orders by critical, then high, medium, low.
const countsWeight = `(coalesce(c.critical,0)::bigint * 1000000000 + coalesce(c.high,0) * 1000000 + coalesce(c.medium,0) * 1000 + coalesce(c.low,0))`

func minSevClause(min int) string {
	switch min {
	case 4:
		return "coalesce(c.critical,0) > 0"
	case 3:
		return "coalesce(c.critical,0) + coalesce(c.high,0) > 0"
	case 2:
		return "coalesce(c.critical,0) + coalesce(c.high,0) + coalesce(c.medium,0) > 0"
	case 1:
		return "coalesce(c.critical,0) + coalesce(c.high,0) + coalesce(c.medium,0) + coalesce(c.low,0) > 0"
	}
	return "true"
}

// args collects positional parameters.
type args []any

func (a *args) add(v any) string {
	*a = append(*a, v)
	return fmt.Sprintf("$%d", len(*a))
}

func orderBy(sorts map[string]string, key string, desc bool, def string) string {
	expr, ok := sorts[key]
	if !ok {
		return def
	}
	dir := " ASC NULLS LAST"
	if desc {
		dir = " DESC NULLS LAST"
	}
	parts := strings.Split(expr, ";")
	for i := range parts {
		parts[i] += dir
	}
	return strings.Join(parts, ", ")
}

func limits(o ListOpts) (int, int) {
	l := o.Limit
	if l <= 0 || l > 500 {
		l = 50
	}
	off := o.Offset
	if off < 0 {
		off = 0
	}
	return l, off
}

func likeEscape(s string) string {
	return "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(s)) + "%"
}

func scanCounts(c *Counts) []any {
	return []any{&c.Critical, &c.High, &c.Medium, &c.Low, &c.Unknown, &c.Total, &c.KEV, &c.Fixable}
}

// ---------------------------------------------------------------- clusters

// Cluster is a reporting cluster.
type Cluster struct {
	Name         string    `json:"name"`
	AgentVersion string    `json:"agentVersion"`
	FirstSeen    time.Time `json:"firstSeen"`
	LastReport   time.Time `json:"lastReport"`
	Images       int       `json:"images"`
	Workloads    int       `json:"workloads"`
	Counts       Counts    `json:"counts"`
}

// Clusters lists clusters with their sizes and open-vulnerability counts.
func (s *Store) Clusters(ctx context.Context) ([]Cluster, error) {
	rows, err := s.pool.Query(ctx, `
		WITH f AS (
			SELECT f.cluster, f.product || '|' || f.vuln_id AS k, v.severity, v.kev, f.fixed_in <> '' AS fixable
			FROM findings f JOIN vulns v ON v.product = f.product AND v.id = f.vuln_id
			WHERE f.resolved_at IS NULL),
		c AS (SELECT cluster, `+countCols+` FROM f GROUP BY cluster)
		SELECT cl.name, cl.agent_version, cl.first_seen, cl.last_report,
		       (SELECT count(*) FROM images i WHERE i.cluster = cl.name),
		       (SELECT count(*) FROM workloads w WHERE w.cluster = cl.name),
		       coalesce(c.critical,0), coalesce(c.high,0), coalesce(c.medium,0), coalesce(c.low,0),
		       coalesce(c.unknown,0), coalesce(c.total,0), coalesce(c.kev,0), coalesce(c.fixable,0)
		FROM clusters cl LEFT JOIN c ON c.cluster = cl.name
		ORDER BY cl.name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Cluster, error) {
		var c Cluster
		dst := append([]any{&c.Name, &c.AgentVersion, &c.FirstSeen, &c.LastReport, &c.Images, &c.Workloads}, scanCounts(&c.Counts)...)
		return c, r.Scan(dst...)
	})
}

// Product is one catalog entry of the current feed.
type Product struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Images []string `json:"images"`
	Vulns  int      `json:"vulns"`
}

// Products lists the feed's products by id.
func (s *Store) Products(ctx context.Context) ([]Product, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, images, vuln_count FROM products ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Product, error) {
		var p Product
		return p, r.Scan(&p.ID, &p.Name, &p.Images, &p.Vulns)
	})
}

// Namespaces lists namespaces with workloads (optionally in one cluster).
func (s *Store) Namespaces(ctx context.Context, cluster string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT namespace FROM workloads WHERE ($1 = '' OR cluster = $1) ORDER BY 1`, cluster)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// ---------------------------------------------------------------- summary

// Summary is the overview payload.
type Summary struct {
	Clusters       int            `json:"clusters"`
	Vulns          Counts         `json:"vulns"`
	Images         int            `json:"images"`
	ImagesByStatus map[string]int `json:"imagesByStatus"`
	Workloads      int            `json:"workloads"`
	Vulnerable     int            `json:"vulnerableWorkloads"`
	Namespaces     int            `json:"namespaces"`
	TopWorkloads   []Workload     `json:"topWorkloads"`
	VulnsByProduct map[string]int `json:"vulnsByProduct"`
	LastReport     *time.Time     `json:"lastReport,omitempty"`
}

// Summary computes the overview for one cluster or all.
func (s *Store) Summary(ctx context.Context, cluster string) (Summary, error) {
	out := Summary{ImagesByStatus: map[string]int{}, VulnsByProduct: map[string]int{}}
	err := s.pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM clusters WHERE ($1 = '' OR name = $1)),
		       (SELECT max(last_report) FROM clusters WHERE ($1 = '' OR name = $1)),
		       (SELECT count(*) FROM images WHERE ($1 = '' OR cluster = $1)),
		       (SELECT count(*) FROM workloads WHERE ($1 = '' OR cluster = $1)),
		       (SELECT count(DISTINCT (cluster, namespace)) FROM workloads WHERE ($1 = '' OR cluster = $1))`, cluster).
		Scan(&out.Clusters, &out.LastReport, &out.Images, &out.Workloads, &out.Namespaces)
	if err != nil {
		return out, err
	}
	rows, err := s.pool.Query(ctx, `SELECT status, count(*) FROM images WHERE ($1 = '' OR cluster = $1) GROUP BY status`, cluster)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return out, err
		}
		out.ImagesByStatus[st] = n
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	err = s.pool.QueryRow(ctx, `
		WITH f AS (
			SELECT f.product || '|' || f.vuln_id AS k, v.severity, v.kev, f.fixed_in <> '' AS fixable
			FROM findings f JOIN vulns v ON v.product = f.product AND v.id = f.vuln_id
			WHERE f.resolved_at IS NULL AND ($1 = '' OR f.cluster = $1))
		SELECT `+countCols+` FROM f`, cluster).Scan(scanCounts(&out.Vulns)...)
	if err != nil {
		return out, err
	}
	rows, err = s.pool.Query(ctx, `
		SELECT product, count(DISTINCT vuln_id) FROM findings
		WHERE resolved_at IS NULL AND ($1 = '' OR cluster = $1) GROUP BY product`, cluster)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var p string
		var n int
		if err := rows.Scan(&p, &n); err != nil {
			return out, err
		}
		out.VulnsByProduct[p] = n
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	top, err := s.Workloads(ctx, ListOpts{Cluster: cluster, MinSeverity: 1, Sort: "vulns", Desc: true, Limit: 10})
	if err != nil {
		return out, err
	}
	out.TopWorkloads = top.Items
	err = s.pool.QueryRow(ctx, `
		SELECT count(DISTINCT (wi.cluster, wi.namespace, wi.kind, wi.name))
		FROM workload_images wi JOIN findings f ON f.cluster = wi.cluster AND f.ref = wi.ref AND f.resolved_at IS NULL
		WHERE ($1 = '' OR wi.cluster = $1)`, cluster).Scan(&out.Vulnerable)
	return out, err
}

// ---------------------------------------------------------------- images

var imageSorts = map[string]string{
	"ref":      "i.ref",
	"cluster":  "i.cluster",
	"product":  "p.name",
	"status":   "i.status",
	"severity": rank("CASE WHEN c.critical > 0 THEN 'CRITICAL' WHEN c.high > 0 THEN 'HIGH' WHEN c.medium > 0 THEN 'MEDIUM' WHEN c.low > 0 THEN 'LOW' END"),
	"vulns":    countsWeight,
	"pods":     "i.pods",
}

// Images lists images with counts.
func (s *Store) Images(ctx context.Context, o ListOpts) (Page[Image], error) {
	var a args
	where := []string{"true"}
	if o.Cluster != "" {
		where = append(where, "i.cluster = "+a.add(o.Cluster))
	}
	if o.Status != "" {
		where = append(where, "i.status = "+a.add(o.Status))
	}
	if o.Product != "" {
		where = append(where, "i.product = "+a.add(o.Product))
	}
	if o.Namespace != "" {
		where = append(where, "EXISTS (SELECT 1 FROM workload_images wi WHERE wi.cluster = i.cluster AND wi.ref = i.ref AND wi.namespace = "+a.add(o.Namespace)+")")
	}
	if o.Ref != "" {
		where = append(where, "i.ref = "+a.add(o.Ref))
	}
	if o.Q != "" {
		p := a.add(likeEscape(o.Q))
		where = append(where, "(lower(i.ref) LIKE "+p+" OR lower(coalesce(p.name,'')) LIKE "+p+")")
	}
	where = append(where, minSevClause(o.MinSeverity))
	limit, offset := limits(o)
	q := `
		WITH f AS (
			SELECT f.cluster, f.ref, f.product || '|' || f.vuln_id AS k, v.severity, v.kev, f.fixed_in <> '' AS fixable
			FROM findings f JOIN vulns v ON v.product = f.product AND v.id = f.vuln_id
			WHERE f.resolved_at IS NULL),
		c AS (SELECT cluster, ref, ` + countCols + ` FROM f GROUP BY cluster, ref)
		SELECT i.cluster, i.ref, i.repository, i.tag, i.digests, i.product, coalesce(p.name, ''), i.version, i.status, i.pods,
		       (SELECT count(*) FROM workload_images wi WHERE wi.cluster = i.cluster AND wi.ref = i.ref),
		       coalesce(c.critical,0), coalesce(c.high,0), coalesce(c.medium,0), coalesce(c.low,0),
		       coalesce(c.unknown,0), coalesce(c.total,0), coalesce(c.kev,0), coalesce(c.fixable,0),
		       count(*) OVER ()
		FROM images i
		LEFT JOIN products p ON p.id = i.product
		LEFT JOIN c ON c.cluster = i.cluster AND c.ref = i.ref
		WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY ` + orderBy(imageSorts, o.Sort, o.Desc, countsWeight+" DESC") + `, i.ref, i.cluster
		LIMIT ` + fmt.Sprint(limit) + ` OFFSET ` + fmt.Sprint(offset)
	return collectPage(ctx, s, q, a, scanImage)
}

func scanImage(r pgx.CollectableRow, total *int) (Image, error) {
	var i Image
	dst := []any{&i.Cluster, &i.Ref, &i.Repository, &i.Tag, &i.Digests, &i.Product, &i.ProductName, &i.Version, &i.Status, &i.Pods, &i.Workloads}
	dst = append(dst, scanCounts(&i.Counts)...)
	dst = append(dst, total)
	err := r.Scan(dst...)
	i.MaxSeverity = i.Counts.MaxSeverity()
	return i, err
}

func collectPage[T any](ctx context.Context, s *Store, q string, a args, scan func(pgx.CollectableRow, *int) (T, error)) (Page[T], error) {
	rows, err := s.pool.Query(ctx, q, a...)
	if err != nil {
		return Page[T]{}, err
	}
	var total int
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (T, error) { return scan(r, &total) })
	if items == nil {
		items = []T{}
	}
	return Page[T]{Items: items, Total: total}, err
}

// ImageFinding is an open or resolved finding on an image, joined with its vuln.
type ImageFinding struct {
	Vuln
	FixedIn    string     `json:"fixedIn,omitempty"`
	ResolvedAt *time.Time `json:"resolvedAt,omitempty"`
}

// ImageDetail is the image page payload.
type ImageDetail struct {
	Image     Image          `json:"image"`
	Vulns     []ImageFinding `json:"vulns"`
	Resolved  []ImageFinding `json:"resolved"`
	Workloads []WorkloadRef  `json:"workloads"`
}

// ImageDetail returns an image with its findings and workloads.
func (s *Store) ImageDetail(ctx context.Context, cluster, ref string) (*ImageDetail, error) {
	img, err := s.imageByRef(ctx, cluster, ref)
	if err != nil || img == nil {
		return nil, err
	}
	d := ImageDetail{Image: *img}
	rows, err := s.pool.Query(ctx, `
		SELECT `+vulnCols+`, f.fixed_in, f.first_seen, f.resolved_at
		FROM findings f JOIN vulns v ON v.product = f.product AND v.id = f.vuln_id
		WHERE f.cluster = $1 AND f.ref = $2
		ORDER BY f.resolved_at DESC NULLS FIRST, `+rank("v.severity")+` DESC, v.cvss DESC, v.id DESC`, cluster, ref)
	if err != nil {
		return nil, err
	}
	all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ImageFinding, error) {
		var f ImageFinding
		dst := append(vulnDst(&f.Vuln), &f.FixedIn, &f.FirstSeen, &f.ResolvedAt)
		return f, r.Scan(dst...)
	})
	if err != nil {
		return nil, err
	}
	d.Vulns, d.Resolved = []ImageFinding{}, []ImageFinding{}
	for _, f := range all {
		if f.ResolvedAt == nil {
			f.Fixable = f.FixedIn != ""
			d.Vulns = append(d.Vulns, f)
		} else if len(d.Resolved) < 100 {
			d.Resolved = append(d.Resolved, f)
		}
	}
	rows, err = s.pool.Query(ctx, `SELECT cluster, namespace, kind, name FROM workload_images WHERE cluster = $1 AND ref = $2 ORDER BY 2, 3, 4`, cluster, ref)
	if err != nil {
		return nil, err
	}
	d.Workloads, err = pgx.CollectRows(rows, pgx.RowToStructByPos[WorkloadRef])
	return &d, err
}

func (s *Store) imageByRef(ctx context.Context, cluster, ref string) (*Image, error) {
	page, err := s.Images(ctx, ListOpts{Cluster: cluster, Ref: ref, Limit: 1})
	if err != nil || len(page.Items) == 0 {
		return nil, err
	}
	return &page.Items[0], nil
}

const vulnCols = `v.id, v.product, v.aliases, v.summary, v.severity, v.cvss, v.cvss_vector, v.epss, v.kev, v.published, v.refs`

func vulnDst(v *Vuln) []any {
	return []any{&v.ID, &v.Product, &v.Aliases, &v.Summary, &v.Severity, &v.CVSS, &v.CVSSVector, &v.EPSS, &v.KEV, &v.Published, &v.References}
}

// ---------------------------------------------------------------- workloads

var workloadSorts = map[string]string{
	"name":      "w.name",
	"namespace": "w.namespace",
	"cluster":   "w.cluster",
	"kind":      "w.kind",
	"severity":  rank("CASE WHEN c.critical > 0 THEN 'CRITICAL' WHEN c.high > 0 THEN 'HIGH' WHEN c.medium > 0 THEN 'MEDIUM' WHEN c.low > 0 THEN 'LOW' END"),
	"vulns":     countsWeight,
	"images":    "cardinality(imgs.refs)",
	"pods":      "w.pods",
}

// Workloads lists workloads with counts of distinct vulnerabilities across their images.
func (s *Store) Workloads(ctx context.Context, o ListOpts) (Page[Workload], error) {
	var a args
	where := []string{"true"}
	if o.Cluster != "" {
		where = append(where, "w.cluster = "+a.add(o.Cluster))
	}
	if o.Namespace != "" {
		where = append(where, "w.namespace = "+a.add(o.Namespace))
	}
	if o.Kind != "" {
		where = append(where, "w.kind = "+a.add(o.Kind))
	}
	if o.Name != "" {
		where = append(where, "w.name = "+a.add(o.Name))
	}
	if o.Q != "" {
		p := a.add(likeEscape(o.Q))
		where = append(where, "(lower(w.namespace || '/' || w.kind || '/' || w.name) LIKE "+p+" OR EXISTS (SELECT 1 FROM unnest(imgs.refs) r WHERE lower(r) LIKE "+p+"))")
	}
	where = append(where, minSevClause(o.MinSeverity))
	limit, offset := limits(o)
	q := `
		WITH f AS (
			SELECT wi.cluster, wi.namespace, wi.kind, wi.name, f.product || '|' || f.vuln_id AS k, v.severity, v.kev, f.fixed_in <> '' AS fixable
			FROM workload_images wi
			JOIN findings f ON f.cluster = wi.cluster AND f.ref = wi.ref AND f.resolved_at IS NULL
			JOIN vulns v ON v.product = f.product AND v.id = f.vuln_id),
		c AS (SELECT cluster, namespace, kind, name, ` + countCols + ` FROM f GROUP BY cluster, namespace, kind, name)
		SELECT w.cluster, w.namespace, w.kind, w.name, w.pods, coalesce(imgs.refs, '{}'),
		       coalesce(c.critical,0), coalesce(c.high,0), coalesce(c.medium,0), coalesce(c.low,0),
		       coalesce(c.unknown,0), coalesce(c.total,0), coalesce(c.kev,0), coalesce(c.fixable,0),
		       count(*) OVER ()
		FROM workloads w
		LEFT JOIN LATERAL (
			SELECT array_agg(wi.ref ORDER BY wi.ref) AS refs FROM workload_images wi
			WHERE wi.cluster = w.cluster AND wi.namespace = w.namespace AND wi.kind = w.kind AND wi.name = w.name) imgs ON true
		LEFT JOIN c ON c.cluster = w.cluster AND c.namespace = w.namespace AND c.kind = w.kind AND c.name = w.name
		WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY ` + orderBy(workloadSorts, o.Sort, o.Desc, countsWeight+" DESC") + `, w.namespace, w.kind, w.name, w.cluster
		LIMIT ` + fmt.Sprint(limit) + ` OFFSET ` + fmt.Sprint(offset)
	return collectPage(ctx, s, q, a, func(r pgx.CollectableRow, total *int) (Workload, error) {
		var w Workload
		dst := []any{&w.Cluster, &w.Namespace, &w.Kind, &w.Name, &w.Pods, &w.Images}
		dst = append(dst, scanCounts(&w.Counts)...)
		dst = append(dst, total)
		err := r.Scan(dst...)
		w.MaxSeverity = w.Counts.MaxSeverity()
		return w, err
	})
}

// WorkloadDetail is the workload page payload.
type WorkloadDetail struct {
	Workload Workload `json:"workload"`
	Images   []Image  `json:"images"`
}

// WorkloadDetail returns a workload and its images.
func (s *Store) WorkloadDetail(ctx context.Context, ref WorkloadRef) (*WorkloadDetail, error) {
	page, err := s.Workloads(ctx, ListOpts{Cluster: ref.Cluster, Namespace: ref.Namespace, Kind: ref.Kind, Name: ref.Name, Limit: 1})
	if err != nil || len(page.Items) == 0 {
		return nil, err
	}
	d := WorkloadDetail{Workload: page.Items[0], Images: []Image{}}
	for _, r := range d.Workload.Images {
		img, err := s.imageByRef(ctx, ref.Cluster, r)
		if err != nil {
			return nil, err
		}
		if img != nil {
			d.Images = append(d.Images, *img)
		}
	}
	return &d, nil
}

// ---------------------------------------------------------------- vulns

var vulnSorts = map[string]string{
	"id":        "v.id",
	"severity":  rank("v.severity") + ";v.cvss",
	"cvss":      "v.cvss",
	"epss":      "v.epss",
	"product":   "v.product",
	"workloads": "coalesce(wl.n, 0)",
	"images":    "agg.images",
	"firstSeen": "agg.first_seen",
}

const vulnDefaultOrder = `v.kev DESC, ` + `CASE v.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC, v.cvss DESC, coalesce(wl.n,0) DESC`

// Vulns lists vulnerabilities with open findings.
func (s *Store) Vulns(ctx context.Context, o ListOpts) (Page[Vuln], error) {
	var a args
	fw := []string{"f.resolved_at IS NULL"}
	if o.Cluster != "" {
		fw = append(fw, "f.cluster = "+a.add(o.Cluster))
	}
	if o.Namespace != "" {
		fw = append(fw, "EXISTS (SELECT 1 FROM workload_images wi WHERE wi.cluster = f.cluster AND wi.ref = f.ref AND wi.namespace = "+a.add(o.Namespace)+")")
	}
	where := []string{"true"}
	if o.MinSeverity > 0 {
		where = append(where, rank("v.severity")+" >= "+a.add(o.MinSeverity))
	}
	if o.KEV {
		where = append(where, "v.kev")
	}
	if o.Fixable {
		where = append(where, "agg.fixable")
	}
	if o.Product != "" {
		where = append(where, "v.product = "+a.add(o.Product))
	}
	if o.Q != "" {
		where = append(where, "lower(v.id || ' ' || array_to_string(v.aliases, ' ') || ' ' || v.summary || ' ' || v.product) LIKE "+a.add(likeEscape(o.Q)))
	}
	limit, offset := limits(o)
	fwhere := strings.Join(fw, " AND ")
	q := `
		WITH agg AS (
			SELECT f.product, f.vuln_id, bool_or(f.fixed_in <> '') AS fixable, min(f.first_seen) AS first_seen,
			       count(DISTINCT (f.cluster, f.ref)) AS images, count(DISTINCT f.cluster) AS clusters
			FROM findings f WHERE ` + fwhere + ` GROUP BY 1, 2),
		wl AS (
			SELECT f.product, f.vuln_id, count(DISTINCT (wi.cluster, wi.namespace, wi.kind, wi.name)) AS n
			FROM findings f JOIN workload_images wi ON wi.cluster = f.cluster AND wi.ref = f.ref
			WHERE ` + fwhere + ` GROUP BY 1, 2)
		SELECT ` + vulnCols + `, agg.fixable, agg.first_seen, agg.images, coalesce(wl.n, 0), agg.clusters, count(*) OVER ()
		FROM agg
		JOIN vulns v ON v.product = agg.product AND v.id = agg.vuln_id
		LEFT JOIN wl ON wl.product = agg.product AND wl.vuln_id = agg.vuln_id
		WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY ` + orderBy(vulnSorts, o.Sort, o.Desc, vulnDefaultOrder) + `, v.id DESC
		LIMIT ` + fmt.Sprint(limit) + ` OFFSET ` + fmt.Sprint(offset)
	return collectPage(ctx, s, q, a, func(r pgx.CollectableRow, total *int) (Vuln, error) {
		var v Vuln
		dst := append(vulnDst(&v), &v.Fixable, &v.FirstSeen, &v.Images, &v.Workloads, &v.Clusters, total)
		return v, r.Scan(dst...)
	})
}

// AffectedImage is an image affected (now or before) by a vulnerability.
type AffectedImage struct {
	Cluster    string     `json:"cluster"`
	Ref        string     `json:"ref"`
	Version    string     `json:"version"`
	Status     string     `json:"status"`
	FixedIn    string     `json:"fixedIn,omitempty"`
	FirstSeen  time.Time  `json:"firstSeen"`
	ResolvedAt *time.Time `json:"resolvedAt,omitempty"`
}

// VulnDetail is the CVE page payload.
type VulnDetail struct {
	Vuln      Vuln            `json:"vuln"`
	Images    []AffectedImage `json:"images"`
	Resolved  []AffectedImage `json:"resolved"`
	Workloads []WorkloadRef   `json:"workloads"`
}

// VulnDetail returns a vulnerability with its affected images and history.
// It returns nil when the vulnerability has never affected the selection.
func (s *Store) VulnDetail(ctx context.Context, id, cluster string) (*VulnDetail, error) {
	var d VulnDetail
	err := s.pool.QueryRow(ctx, `
		SELECT `+vulnCols+`,
		       coalesce(bool_or(f.fixed_in <> '') FILTER (WHERE f.resolved_at IS NULL), false),
		       min(f.first_seen) FILTER (WHERE f.resolved_at IS NULL),
		       count(DISTINCT (f.cluster, f.ref)) FILTER (WHERE f.resolved_at IS NULL),
		       count(DISTINCT f.cluster) FILTER (WHERE f.resolved_at IS NULL)
		FROM vulns v JOIN findings f ON f.product = v.product AND f.vuln_id = v.id
		WHERE v.id = $1 AND ($2 = '' OR f.cluster = $2)
		GROUP BY v.product, v.id
		ORDER BY count(*) FILTER (WHERE f.resolved_at IS NULL) DESC
		LIMIT 1`, id, cluster).
		Scan(append(vulnDst(&d.Vuln), &d.Vuln.Fixable, &d.Vuln.FirstSeen, &d.Vuln.Images, &d.Vuln.Clusters)...)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT f.cluster, f.ref, coalesce(i.version, ''), coalesce(i.status, ''), f.fixed_in, f.first_seen, f.resolved_at
		FROM findings f LEFT JOIN images i ON i.cluster = f.cluster AND i.ref = f.ref
		WHERE f.vuln_id = $1 AND f.product = $2 AND ($3 = '' OR f.cluster = $3)
		ORDER BY f.resolved_at DESC NULLS FIRST, f.cluster, f.ref
		LIMIT 500`, id, d.Vuln.Product, cluster)
	if err != nil {
		return nil, err
	}
	all, err := pgx.CollectRows(rows, pgx.RowToStructByPos[AffectedImage])
	if err != nil {
		return nil, err
	}
	d.Images, d.Resolved = []AffectedImage{}, []AffectedImage{}
	for _, a := range all {
		if a.ResolvedAt == nil {
			d.Images = append(d.Images, a)
		} else {
			d.Resolved = append(d.Resolved, a)
		}
	}
	rows, err = s.pool.Query(ctx, `
		SELECT DISTINCT wi.cluster, wi.namespace, wi.kind, wi.name
		FROM findings f JOIN workload_images wi ON wi.cluster = f.cluster AND wi.ref = f.ref
		WHERE f.vuln_id = $1 AND f.product = $2 AND f.resolved_at IS NULL AND ($3 = '' OR f.cluster = $3)
		ORDER BY 1, 2, 3, 4`, id, d.Vuln.Product, cluster)
	if err != nil {
		return nil, err
	}
	d.Workloads, err = pgx.CollectRows(rows, pgx.RowToStructByPos[WorkloadRef])
	d.Vuln.Workloads = len(d.Workloads)
	return &d, err
}

// ---------------------------------------------------------------- history

// HistoryPoint is the number of distinct open vulnerabilities at the end of a day.
type HistoryPoint struct {
	Day      string `json:"day"` // YYYY-MM-DD
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Unknown  int    `json:"unknown"`
}

// History is the trend payload.
type History struct {
	Days          int            `json:"days"`
	Points        []HistoryPoint `json:"points"`
	Opened        int            `json:"opened"`   // findings opened in the window
	Resolved      int            `json:"resolved"` // findings resolved in the window
	MeanDaysToFix *float64       `json:"meanDaysToFix,omitempty"`
	TrackingSince *time.Time     `json:"trackingSince,omitempty"`
}

// History returns daily open-vulnerability counts for the last `days` days.
func (s *Store) History(ctx context.Context, cluster string, days int) (History, error) {
	if days <= 0 || days > 365 {
		days = 30
	}
	h := History{Days: days, Points: []HistoryPoint{}}
	rows, err := s.pool.Query(ctx, `
		WITH d AS (
			SELECT generate_series(date_trunc('day', now()) - ($2::int - 1) * interval '1 day', date_trunc('day', now()), interval '1 day') AS day),
		f AS (
			SELECT d.day, f.product || '|' || f.vuln_id AS k, v.severity
			FROM d JOIN findings f ON f.first_seen < d.day + interval '1 day'
			                      AND (f.resolved_at IS NULL OR f.resolved_at >= d.day + interval '1 day')
			JOIN vulns v ON v.product = f.product AND v.id = f.vuln_id
			WHERE ($1 = '' OR f.cluster = $1))
		SELECT to_char(d.day, 'YYYY-MM-DD'),
		       count(DISTINCT f.k) FILTER (WHERE f.severity = 'CRITICAL'),
		       count(DISTINCT f.k) FILTER (WHERE f.severity = 'HIGH'),
		       count(DISTINCT f.k) FILTER (WHERE f.severity = 'MEDIUM'),
		       count(DISTINCT f.k) FILTER (WHERE f.severity = 'LOW'),
		       count(DISTINCT f.k) FILTER (WHERE f.severity NOT IN ('CRITICAL','HIGH','MEDIUM','LOW'))
		FROM d LEFT JOIN f ON f.day = d.day
		GROUP BY d.day ORDER BY d.day`, cluster, days)
	if err != nil {
		return h, err
	}
	h.Points, err = pgx.CollectRows(rows, pgx.RowToStructByPos[HistoryPoint])
	if err != nil {
		return h, err
	}
	err = s.pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE first_seen >= now() - $2::int * interval '1 day'),
		       count(*) FILTER (WHERE resolved_at >= now() - $2::int * interval '1 day'),
		       avg(extract(epoch FROM resolved_at - first_seen) / 86400) FILTER (WHERE resolved_at >= now() - $2::int * interval '1 day'),
		       (SELECT min(first_seen) FROM clusters WHERE ($1 = '' OR name = $1))
		FROM findings WHERE ($1 = '' OR cluster = $1)`, cluster, days).
		Scan(&h.Opened, &h.Resolved, &h.MeanDaysToFix, &h.TrackingSince)
	return h, err
}
