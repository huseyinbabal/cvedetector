// Package httpapi serves the agent ingest endpoint and the read API used by the UI.
package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/huseyinbabal/cvedetector/apps/api/internal/store"
	"github.com/huseyinbabal/cvedetector/pkg/feed"
	"github.com/huseyinbabal/cvedetector/pkg/inventory"
)

// MaxReportBytes bounds an uncompressed inventory report.
const MaxReportBytes = 64 << 20

// Server holds dependencies.
type Server struct {
	Store        *store.Store
	IngestTokens []string
	Log          *slog.Logger
	OnIngest     func(cluster string, res store.IngestResult, err error)
}

// Handler returns the routes under /api/v1/.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/ingest", s.ingest)
	mux.HandleFunc("DELETE /api/v1/clusters/{name}", s.deleteCluster)

	mux.HandleFunc("GET /api/v1/clusters", s.get(func(r *http.Request) (any, error) { return s.Store.Clusters(r.Context()) }))
	mux.HandleFunc("GET /api/v1/feed", s.get(func(r *http.Request) (any, error) { return s.Store.GetFeedState(r.Context()) }))
	mux.HandleFunc("GET /api/v1/summary", s.get(func(r *http.Request) (any, error) {
		return s.Store.Summary(r.Context(), r.URL.Query().Get("cluster"))
	}))
	mux.HandleFunc("GET /api/v1/namespaces", s.get(func(r *http.Request) (any, error) {
		return s.Store.Namespaces(r.Context(), r.URL.Query().Get("cluster"))
	}))
	mux.HandleFunc("GET /api/v1/history", s.get(func(r *http.Request) (any, error) {
		days, _ := strconv.Atoi(r.URL.Query().Get("days"))
		return s.Store.History(r.Context(), r.URL.Query().Get("cluster"), days)
	}))
	mux.HandleFunc("GET /api/v1/images", s.get(func(r *http.Request) (any, error) { return s.Store.Images(r.Context(), listOpts(r)) }))
	mux.HandleFunc("GET /api/v1/image", s.get(func(r *http.Request) (any, error) {
		q := r.URL.Query()
		return notFoundIfNil(s.Store.ImageDetail(r.Context(), q.Get("cluster"), q.Get("ref")))
	}))
	mux.HandleFunc("GET /api/v1/workloads", s.get(func(r *http.Request) (any, error) { return s.Store.Workloads(r.Context(), listOpts(r)) }))
	mux.HandleFunc("GET /api/v1/workloads/{cluster}/{namespace}/{kind}/{name}", s.get(func(r *http.Request) (any, error) {
		return notFoundIfNil(s.Store.WorkloadDetail(r.Context(), store.WorkloadRef{
			Cluster: r.PathValue("cluster"), Namespace: r.PathValue("namespace"), Kind: r.PathValue("kind"), Name: r.PathValue("name"),
		}))
	}))
	mux.HandleFunc("GET /api/v1/cves", s.get(func(r *http.Request) (any, error) { return s.Store.Vulns(r.Context(), listOpts(r)) }))
	mux.HandleFunc("GET /api/v1/cves/{id}", s.get(func(r *http.Request) (any, error) {
		return notFoundIfNil(s.Store.VulnDetail(r.Context(), r.PathValue("id"), r.URL.Query().Get("cluster")))
	}))
	return mux
}

var errNotFound = errors.New("not found")

func notFoundIfNil[T any](v *T, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, errNotFound
	}
	return v, nil
}

func listOpts(r *http.Request) store.ListOpts {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	return store.ListOpts{
		Cluster:     q.Get("cluster"),
		Namespace:   q.Get("namespace"),
		Q:           strings.TrimSpace(q.Get("q")),
		MinSeverity: feed.SeverityRank(strings.ToUpper(q.Get("minSeverity"))),
		Status:      q.Get("status"),
		Product:     q.Get("product"),
		KEV:         q.Get("kev") == "true",
		Fixable:     q.Get("fixable") == "true",
		Sort:        q.Get("sort"),
		Desc:        q.Get("order") != "asc",
		Limit:       limit,
		Offset:      offset,
	}
}

// get wraps a read handler with JSON encoding, ETag/304 and error mapping.
func (s *Server) get(fn func(*http.Request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, err := fn(r)
		switch {
		case errors.Is(err, errNotFound):
			writeErr(w, http.StatusNotFound, "not found")
			return
		case errors.Is(err, context.Canceled):
			return
		case err != nil:
			s.Log.Error("query failed", "path", r.URL.Path, "err", err)
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		body, err := json.Marshal(v)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "encode error")
			return
		}
		sum := sha256.Sum256(body)
		etag := `"` + hex.EncodeToString(sum[:16]) + `"`
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "no-cache")
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(append(body, '\n'))
	}
}

func (s *Server) authorized(r *http.Request) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		return false
	}
	for _, t := range s.IngestTokens {
		if t != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(t)) == 1 {
			return true
		}
	}
	return false
}

func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		writeErr(w, http.StatusUnauthorized, "missing or invalid bearer token")
		return
	}
	var body io.Reader = http.MaxBytesReader(w, r.Body, MaxReportBytes)
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid gzip body")
			return
		}
		defer zr.Close()
		body = io.LimitReader(zr, MaxReportBytes+1)
	}
	raw, err := io.ReadAll(body)
	if err != nil || len(raw) > MaxReportBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "report too large")
		return
	}
	var rep inventory.Report
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&rep); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := rep.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.Store.ApplyReport(r.Context(), &rep, time.Now())
	if s.OnIngest != nil {
		s.OnIngest(rep.Cluster, res, err)
	}
	if err != nil {
		s.Log.Error("ingest failed", "cluster", rep.Cluster, "err", err)
		writeErr(w, http.StatusInternalServerError, "could not store report")
		return
	}
	if res.Changed {
		s.Log.Info("inventory stored", "cluster", rep.Cluster, "images", res.Images, "opened", res.Opened, "resolved", res.Resolved, "open", res.Open)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(res)
}

func (s *Server) deleteCluster(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		writeErr(w, http.StatusUnauthorized, "missing or invalid bearer token")
		return
	}
	ok, err := s.Store.DeleteCluster(r.Context(), r.PathValue("name"))
	switch {
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "internal error")
	case !ok:
		writeErr(w, http.StatusNotFound, "cluster not found")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
