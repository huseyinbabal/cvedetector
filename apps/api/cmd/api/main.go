// Command api stores cluster inventories reported by agents in PostgreSQL,
// mirrors the CVE feed, matches the two and serves the read API.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/huseyinbabal/cvedetector/apps/api/internal/db"
	"github.com/huseyinbabal/cvedetector/apps/api/internal/feedsync"
	"github.com/huseyinbabal/cvedetector/apps/api/internal/httpapi"
	"github.com/huseyinbabal/cvedetector/apps/api/internal/metrics"
	"github.com/huseyinbabal/cvedetector/apps/api/internal/store"
)

var version = "dev"

type config struct {
	databaseURL     string
	feedURL         string
	feedToken       string
	feedRefresh     time.Duration
	ingestToken     string
	ingestTokens    string
	listen          string
	retention       time.Duration
	workloadMetrics bool
	logLevel        string
	logFormat       string
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(os.Getenv(key)); err == nil {
		return d
	}
	return def
}

func parseConfig() config {
	var c config
	flag.StringVar(&c.databaseURL, "database-url", env("DATABASE_URL", ""), "PostgreSQL URL; when empty the PG* environment variables are used [DATABASE_URL]")
	flag.StringVar(&c.feedURL, "feed-url", env("FEED_URL", "https://raw.githubusercontent.com/huseyinbabal/cvedetector/data/"), "feed base URL (https:// or file://) [FEED_URL]")
	flag.StringVar(&c.feedToken, "feed-token", env("FEED_TOKEN", ""), "bearer token for a private feed, e.g. a GitHub token with read access to the repository [FEED_TOKEN]")
	flag.DurationVar(&c.feedRefresh, "feed-refresh", envDuration("FEED_REFRESH_INTERVAL", time.Hour), "feed refresh interval [FEED_REFRESH_INTERVAL]")
	flag.StringVar(&c.ingestToken, "ingest-token", env("INGEST_TOKEN", ""), "bearer token accepted from agents [INGEST_TOKEN]")
	flag.StringVar(&c.ingestTokens, "ingest-tokens", env("INGEST_TOKENS", ""), "additional comma-separated tokens, e.g. one per remote cluster [INGEST_TOKENS]")
	flag.StringVar(&c.listen, "listen", env("LISTEN_ADDR", ":8080"), "HTTP listen address [LISTEN_ADDR]")
	flag.DurationVar(&c.retention, "retention", envDuration("RETENTION", 365*24*time.Hour), "how long resolved findings are kept [RETENTION]")
	flag.BoolVar(&c.workloadMetrics, "workload-metrics", env("WORKLOAD_METRICS", "false") == "true", "export one metric series per workload [WORKLOAD_METRICS]")
	flag.StringVar(&c.logLevel, "log-level", env("LOG_LEVEL", "info"), "debug, info, warn, error [LOG_LEVEL]")
	flag.StringVar(&c.logFormat, "log-format", env("LOG_FORMAT", "json"), "json or text [LOG_FORMAT]")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}
	return c
}

func newLogger(level, format string) *slog.Logger {
	var l slog.Level
	_ = l.UnmarshalText([]byte(level))
	opts := &slog.HandlerOptions{Level: l}
	if format == "text" {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}

func main() {
	cfg := parseConfig()
	log := newLogger(cfg.logLevel, cfg.logFormat)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, log); err != nil {
		log.Error("api stopped", "err", err)
		os.Exit(1)
	}
}

// connect retries for a while: the bundled database may start after the API.
func connect(ctx context.Context, dsn string, log *slog.Logger) (*pgxpool.Pool, error) {
	deadline := time.Now().Add(3 * time.Minute)
	for wait := time.Second; ; wait = min(wait*2, 15*time.Second) {
		pool, err := db.Open(ctx, dsn)
		if err == nil {
			return pool, nil
		}
		if strings.Contains(err.Error(), "no database configured") || time.Now().After(deadline) {
			return nil, err
		}
		log.Warn("database not reachable yet, retrying", "err", err, "in", wait)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}

func run(ctx context.Context, cfg config, log *slog.Logger) error {
	tokens := append(splitList(cfg.ingestTokens), splitList(cfg.ingestToken)...)
	if len(tokens) == 0 {
		return errors.New("INGEST_TOKEN or INGEST_TOKENS is required: agents authenticate with one of these tokens")
	}
	pool, err := connect(ctx, cfg.databaseURL, log)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool, log); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	st := store.New(pool)
	syncer, err := feedsync.New(cfg.feedURL, cfg.feedToken, st, log)
	if err != nil {
		return err
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	reg.MustRegister(metrics.New(pool, log, cfg.workloadMetrics))
	ingests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "cvedetector_ingest_total", Help: "Inventory reports received, by result.",
	}, []string{"result"})
	feedErrors := prometheus.NewCounter(prometheus.CounterOpts{Name: "cvedetector_feed_sync_errors_total", Help: "Failed feed syncs."})
	reg.MustRegister(ingests, feedErrors)
	for _, r := range []string{"changed", "unchanged", "error"} {
		ingests.WithLabelValues(r) // export 0 before the first report so rate() works
	}

	api := &httpapi.Server{
		Store: st, IngestTokens: tokens, Log: log,
		OnIngest: func(_ string, res store.IngestResult, err error) {
			switch {
			case err != nil:
				ingests.WithLabelValues("error").Inc()
			case res.Changed:
				ingests.WithLabelValues("changed").Inc()
			default:
				ingests.WithLabelValues("unchanged").Inc()
			}
		},
	}
	mux := http.NewServeMux()
	mux.Handle("/api/v1/", api.Handler())
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		pctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := pool.Ping(pctx); err != nil {
			http.Error(w, "database unreachable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{Addr: cfg.listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	srvErr := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.listen, "version", version, "feed", syncer.URL())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErr <- err
		}
	}()

	go syncer.Run(ctx, cfg.feedRefresh, feedErrors.Inc)
	go prune(ctx, st, cfg.retention, log)

	select {
	case <-ctx.Done():
	case err := <-srvErr:
		return err
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}

// prune deletes resolved findings older than the retention, daily.
func prune(ctx context.Context, st *store.Store, retention time.Duration, log *slog.Logger) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		if n, err := st.PruneResolved(ctx, time.Now().Add(-retention)); err != nil {
			log.Warn("pruning resolved findings failed", "err", err)
		} else if n > 0 {
			log.Info("pruned resolved findings", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
