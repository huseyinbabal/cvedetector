// Command agent discovers running container images in a Kubernetes cluster and
// reports the inventory to the cvedetector API. It never pulls or scans images
// and needs no internet access.
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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/huseyinbabal/cvedetector/apps/agent/internal/discovery"
	"github.com/huseyinbabal/cvedetector/apps/agent/internal/report"
	"github.com/huseyinbabal/cvedetector/pkg/inventory"
)

var version = "dev"

type config struct {
	cluster     string
	apiURL      string
	token       string
	tokenFile   string
	resync      time.Duration
	debounce    time.Duration
	listen      string
	kubeconfig  string
	kubeContext string
	includeNS   string
	excludeNS   string
	logLevel    string
	logFormat   string
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
	flag.StringVar(&c.cluster, "cluster", env("CLUSTER_NAME", ""), "cluster name shown in the UI (lowercase, digits, '-') [CLUSTER_NAME]")
	flag.StringVar(&c.apiURL, "api-url", env("API_URL", ""), "cvedetector API base URL [API_URL]")
	flag.StringVar(&c.token, "token", env("INGEST_TOKEN", ""), "bearer token for the API [INGEST_TOKEN]")
	flag.StringVar(&c.tokenFile, "token-file", env("INGEST_TOKEN_FILE", ""), "file containing the bearer token [INGEST_TOKEN_FILE]")
	flag.DurationVar(&c.resync, "resync", envDuration("RESYNC_INTERVAL", 10*time.Minute), "full pass and heartbeat interval [RESYNC_INTERVAL]")
	flag.DurationVar(&c.debounce, "debounce", envDuration("DEBOUNCE", 5*time.Second), "delay after pod changes before reporting [DEBOUNCE]")
	flag.StringVar(&c.listen, "listen", env("LISTEN_ADDR", ":8080"), "health and metrics listen address [LISTEN_ADDR]")
	flag.StringVar(&c.kubeconfig, "kubeconfig", env("KUBECONFIG", ""), "kubeconfig path; in-cluster config when empty and running in a pod")
	flag.StringVar(&c.kubeContext, "context", env("KUBE_CONTEXT", ""), "kubeconfig context")
	flag.StringVar(&c.includeNS, "namespaces", env("NAMESPACES_INCLUDE", ""), "comma-separated namespaces to include (default all) [NAMESPACES_INCLUDE]")
	flag.StringVar(&c.excludeNS, "exclude-namespaces", env("NAMESPACES_EXCLUDE", ""), "comma-separated namespaces to exclude [NAMESPACES_EXCLUDE]")
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

func (c *config) validate() error {
	if !inventory.ValidClusterName(c.cluster) {
		return fmt.Errorf("CLUSTER_NAME %q is invalid: use lowercase letters, digits and '-' (max 63)", c.cluster)
	}
	if c.apiURL == "" {
		return errors.New("API_URL is required")
	}
	if c.token == "" && c.tokenFile != "" {
		b, err := os.ReadFile(c.tokenFile)
		if err != nil {
			return fmt.Errorf("token file: %w", err)
		}
		c.token = strings.TrimSpace(string(b))
	}
	if c.token == "" {
		return errors.New("INGEST_TOKEN or INGEST_TOKEN_FILE is required")
	}
	return nil
}

func main() {
	cfg := parseConfig()
	log := newLogger(cfg.logLevel, cfg.logFormat)
	if err := cfg.validate(); err != nil {
		log.Error("invalid configuration", "err", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, log); err != nil {
		log.Error("agent stopped", "err", err)
		os.Exit(1)
	}
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

func restConfig(cfg config) (*rest.Config, error) {
	if cfg.kubeconfig == "" && cfg.kubeContext == "" {
		if rc, err := rest.InClusterConfig(); err == nil {
			return rc, nil
		}
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if cfg.kubeconfig != "" {
		rules.ExplicitPath = cfg.kubeconfig
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: cfg.kubeContext}).ClientConfig()
}

type agentMetrics struct {
	reports     *prometheus.CounterVec
	lastSuccess prometheus.Gauge
	pods        prometheus.Gauge
	images      prometheus.Gauge
}

func newMetrics(reg prometheus.Registerer) *agentMetrics {
	m := &agentMetrics{
		reports:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "cvedetector_agent_reports_total", Help: "Inventory reports by result (sent, skipped, error)."}, []string{"result"}),
		lastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{Name: "cvedetector_agent_last_report_success_timestamp_seconds", Help: "Unix time of the last report the API accepted."}),
		pods:        prometheus.NewGauge(prometheus.GaugeOpts{Name: "cvedetector_agent_pods", Help: "Running pods in the last pass."}),
		images:      prometheus.NewGauge(prometheus.GaugeOpts{Name: "cvedetector_agent_images", Help: "Distinct images in the last pass."}),
	}
	reg.MustRegister(m.reports, m.lastSuccess, m.pods, m.images)
	return m
}

func run(ctx context.Context, cfg config, log *slog.Logger) error {
	rc, err := restConfig(cfg)
	if err != nil {
		return fmt.Errorf("kubernetes config: %w", err)
	}
	rc.UserAgent = "cvedetector-agent/" + version
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return err
	}
	md, err := metadata.NewForConfig(rc)
	if err != nil {
		return err
	}
	disc, err := discovery.New(cs, md, discovery.Options{IncludeNamespaces: splitList(cfg.includeNS), ExcludeNamespaces: splitList(cfg.excludeNS)})
	if err != nil {
		return err
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	m := newMetrics(reg)
	var synced atomic.Bool

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if !synced.Load() {
			http.Error(w, "informer caches not synced", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{Addr: cfg.listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server", "err", err)
		}
	}()

	log.Info("starting", "version", version, "cluster", cfg.cluster, "api", cfg.apiURL)
	if err := disc.Start(ctx); err != nil {
		return err
	}
	synced.Store(true)

	sender := &report.Sender{URL: cfg.apiURL, Token: cfg.token}
	var (
		lastFP   string
		lastSent time.Time
		failures int
	)
	// pass builds a report and sends it when it changed or the heartbeat is due.
	// It returns the delay before a retry (0 when no retry is needed).
	pass := func() time.Duration {
		pods, err := disc.Pods()
		if err != nil {
			log.Error("listing pods", "err", err)
			return 0
		}
		r := report.Build(cfg.cluster, version, pods, time.Now())
		m.pods.Set(float64(len(pods)))
		m.images.Set(float64(len(r.Images)))
		fp := r.Fingerprint()
		if fp == lastFP && time.Since(lastSent) < cfg.resync && failures == 0 {
			m.reports.WithLabelValues("skipped").Inc()
			return 0
		}
		sctx, cancel := context.WithTimeout(ctx, time.Minute)
		err = sender.Send(sctx, &r)
		cancel()
		if err != nil {
			failures++
			m.reports.WithLabelValues("error").Inc()
			delay := min(time.Duration(1<<min(failures, 6))*time.Second, 2*time.Minute)
			log.Warn("report failed; will retry", "err", err, "in", delay)
			return delay
		}
		failures = 0
		lastFP, lastSent = fp, time.Now()
		m.reports.WithLabelValues("sent").Inc()
		m.lastSuccess.SetToCurrentTime()
		log.Debug("report sent", "images", len(r.Images), "workloads", len(r.Workloads))
		return 0
	}

	var retry <-chan time.Time
	schedule := func(d time.Duration) {
		if d > 0 {
			retry = time.After(d)
		}
	}
	schedule(pass())
	resync := time.NewTicker(cfg.resync)
	defer resync.Stop()
	var debounce <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return srv.Shutdown(shutdown)
		case <-disc.Changed():
			if debounce == nil {
				debounce = time.After(cfg.debounce)
			}
		case <-debounce:
			debounce = nil
			schedule(pass())
		case <-retry:
			retry = nil
			schedule(pass())
		case <-resync.C:
			schedule(pass())
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
