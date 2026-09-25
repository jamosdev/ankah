// Command attacker generates bot-flood style HTTP load against the demo edge
// so the DOTS filtering path can be exercised and measured. It is the load
// side of this self-contained Compose benchmark and makes no attempt to be
// stealthy or evasive: keep-alive is off, the User-Agent honestly says
// "dots-demo-attacker" so both protection layers can classify it, and every
// request is a plain GET /pi. It aims only at the two fixed demo vhosts
// resolved through the edge, and reports what happened as Prometheus metrics
// plus a small /sequence ring the smoke test reads to confirm alternation.
//
// The interesting measurement is deliberately honest: neither protection
// layer lets this traffic reach a backend, because the attacker never solves
// a challenge, so the load lands on the protection layer (Anubis challenge
// work, Ankah challenge work, or an edge connection reject once a DOTS ACL is
// installed), not on the Pi backend.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"dotsdemo/loadgen/envcfg"
	"dotsdemo/loadgen/outcome"
	"dotsdemo/loadgen/ready"
	"dotsdemo/loadgen/sched"
	"dotsdemo/loadgen/targets"
)

const userAgent = "dots-demo-attacker"

type config struct {
	targets       []targets.Target
	rps           float64
	concurrency   int
	requestPath   string
	timeout       time.Duration
	listen        string
	readyURLs     []string
	readyInterval time.Duration
	readyTimeout  time.Duration
}

func loadConfig() (config, error) {
	var cfg config
	var err error

	spec := envcfg.String("TARGETS", "anubis=http://anubis.test,ankah=http://ankah.test")
	if cfg.targets, err = targets.Parse(spec); err != nil {
		return cfg, err
	}
	if cfg.rps, err = envcfg.Float("ATTACK_RPS", 40); err != nil {
		return cfg, err
	}
	if cfg.concurrency, err = envcfg.Int("ATTACK_CONCURRENCY", 32); err != nil {
		return cfg, err
	}
	piN, err := envcfg.Int("PI_N", 200000)
	if err != nil {
		return cfg, err
	}
	cfg.requestPath = "/pi?n=" + strconv.Itoa(piN)
	if cfg.timeout, err = envcfg.Duration("REQUEST_TIMEOUT", 10*time.Second); err != nil {
		return cfg, err
	}
	cfg.listen = envcfg.String("LISTEN", ":9300")
	if cfg.readyInterval, err = envcfg.Duration("READY_INTERVAL", 2*time.Second); err != nil {
		return cfg, err
	}
	if cfg.readyTimeout, err = envcfg.Duration("READY_TIMEOUT", 180*time.Second); err != nil {
		return cfg, err
	}
	// By default a target is ready when its root answers through the edge.
	// READY_URLS overrides this for topologies where a different check fits.
	if custom := envcfg.String("READY_URLS", ""); custom != "" {
		if cfg.readyURLs, err = splitURLs(custom); err != nil {
			return cfg, err
		}
	} else {
		for _, t := range cfg.targets {
			cfg.readyURLs = append(cfg.readyURLs, t.URL("/"))
		}
	}
	return cfg, nil
}

// splitURLs parses READY_URLS: a comma-separated list of full URLs, each
// requiring a scheme and host.
func splitURLs(spec string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		u, err := url.Parse(part)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("READY_URLS entry %q is not a valid url", part)
		}
		out = append(out, part)
	}
	if len(out) == 0 {
		return nil, errors.New("READY_URLS was set but held no url")
	}
	return out, nil
}

// metrics holds the process-lifetime counters the attacker exports.
type metrics struct {
	issued    *prometheus.CounterVec
	completed *prometheus.CounterVec
	status    *prometheus.CounterVec
	duration  *prometheus.HistogramVec
	active    prometheus.Gauge
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		issued: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "attacker_requests_issued_total",
			Help: "Requests handed to a worker, by target.",
		}, []string{"target"}),
		completed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "attacker_requests_completed_total",
			Help: "Completed requests, by target and outcome.",
		}, []string{"target", "outcome"}),
		status: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "attacker_http_status_total",
			Help: "HTTP responses received, by target and status class.",
		}, []string{"target", "class"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "attacker_request_seconds",
			Help:    "Wall time per request, by target.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		}, []string{"target"}),
		active: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "attacker_active_requests",
			Help: "Requests currently in flight.",
		}),
	}
	reg.MustRegister(m.issued, m.completed, m.status, m.duration, m.active)
	return m
}

// seqRing keeps the most recent seq to target assignments in issue order so
// the smoke test can prove strict A, B alternation without parsing logs.
type seqRing struct {
	mu    sync.Mutex
	buf   []seqEntry
	max   int
	next  int
	total uint64
}

type seqEntry struct {
	Seq    uint64 `json:"seq"`
	Target string `json:"target"`
}

func newSeqRing(max int) *seqRing { return &seqRing{max: max} }

func (r *seqRing) record(seq uint64, target string) {
	r.mu.Lock()
	if len(r.buf) < r.max {
		r.buf = append(r.buf, seqEntry{seq, target})
	} else {
		r.buf[r.next] = seqEntry{seq, target}
		r.next = (r.next + 1) % r.max
	}
	r.total++
	r.mu.Unlock()
}

// snapshot returns the retained entries oldest first.
func (r *seqRing) snapshot() (entries []seqEntry, total uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) < r.max {
		entries = append(entries, r.buf...)
	} else {
		entries = append(entries, r.buf[r.next:]...)
		entries = append(entries, r.buf[:r.next]...)
	}
	return entries, r.total
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("attacker: configuration error: %v", err)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	m := newMetrics(reg)
	ring := newSeqRing(1024)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Serve metrics and the debug endpoints before the readiness wait so
	// Prometheus can scrape the warmup and health checks pass immediately.
	srv := &http.Server{Addr: cfg.listen, Handler: debugMux(reg, ring)}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("attacker: debug server: %v", err)
		}
	}()

	log.Printf("attacker: waiting for %d readiness url(s)", len(cfg.readyURLs))
	if err := ready.Wait(ctx, cfg.readyURLs, cfg.readyInterval, cfg.readyTimeout); err != nil {
		if ctx.Err() != nil {
			shutdown(srv)
			return
		}
		// Do not abort the demo on a slow backend: log and start anyway, so
		// the metrics still tell the operator what is happening.
		log.Printf("attacker: proceeding despite readiness wait: %v", err)
	}
	log.Printf("attacker: firing at %g req/s, concurrency %d, path %s", cfg.rps, cfg.concurrency, cfg.requestPath)

	client := outcome.NewClient(cfg.timeout, nil)
	s := &sched.Scheduler[targets.Target]{
		Targets:     cfg.targets,
		Rate:        cfg.rps,
		Concurrency: cfg.concurrency,
		Issued: func(seq uint64, t targets.Target) {
			m.issued.WithLabelValues(t.Name).Inc()
			ring.record(seq, t.Name)
			if seq < 20 || seq%1000 == 0 {
				log.Printf("attacker: seq %d -> %s", seq, t.Name)
			}
		},
		Do: func(ctx context.Context, seq uint64, t targets.Target) {
			m.active.Inc()
			defer m.active.Dec()
			reqCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
			defer cancel()
			req, err := outcome.NewRequest(reqCtx, t.URL(cfg.requestPath), userAgent)
			if err != nil {
				m.completed.WithLabelValues(t.Name, "error").Inc()
				return
			}
			start := time.Now()
			resp, err := client.Do(req)
			m.duration.WithLabelValues(t.Name).Observe(time.Since(start).Seconds())
			code := 0
			if resp != nil {
				code = resp.StatusCode
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			m.completed.WithLabelValues(t.Name, outcome.Result(code, err)).Inc()
			if err == nil {
				m.status.WithLabelValues(t.Name, outcome.StatusLabel(code)).Inc()
			}
		},
	}
	s.Run(ctx)
	log.Printf("attacker: stopping")
	shutdown(srv)
}

func debugMux(reg *prometheus.Registry, ring *seqRing) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/sequence", func(w http.ResponseWriter, _ *http.Request) {
		entries, total := ring.snapshot()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Total   uint64     `json:"total"`
			Entries []seqEntry `json:"entries"`
		}{total, entries})
	})
	return mux
}

func shutdown(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
