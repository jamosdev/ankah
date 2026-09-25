// Command legit-probe is the honest-client half of the benchmark. It sends a
// slow, steady stream of ordinary requests to the same two demo vhosts the
// attacker floods, so the dashboards can show that a real visitor keeps
// getting served while the flood is blocked.
//
// It behaves the way a cooperating client is meant to: the User-Agent is
// "dots-demo-legit" (which the Anubis demo policy allows), and when Ankah
// answers with its proof-of-work gate the probe solves it exactly as the
// browser page and solver.py do (parse the challenge, search for the SHA-256
// counter, answer the named session, or use /ankah/open for a bare pass
// challenge), keeps the resulting cookie, and reuses it until it is challenged
// again. Each attempt, including any solve time, is reported as a success or
// failure per target.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"dotsdemo/loadgen/ankahpow"
	"dotsdemo/loadgen/envcfg"
	"dotsdemo/loadgen/ready"
	"dotsdemo/loadgen/sched"
	"dotsdemo/loadgen/targets"
)

const userAgent = "dots-demo-legit"

type config struct {
	targets       []targets.Target
	rps           float64
	concurrency   int
	requestPath   string
	timeout       time.Duration
	listen        string
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
	if cfg.rps, err = envcfg.Float("PROBE_RPS", 1); err != nil {
		return cfg, err
	}
	if cfg.concurrency, err = envcfg.Int("PROBE_CONCURRENCY", 4); err != nil {
		return cfg, err
	}
	piN, err := envcfg.Int("PROBE_PI_N", 10000)
	if err != nil {
		return cfg, err
	}
	cfg.requestPath = "/pi?n=" + strconv.Itoa(piN)
	// The timeout must cover a proof-of-work solve, which is why it is longer
	// than the attacker's.
	if cfg.timeout, err = envcfg.Duration("REQUEST_TIMEOUT", 30*time.Second); err != nil {
		return cfg, err
	}
	cfg.listen = envcfg.String("LISTEN", ":9301")
	if cfg.readyInterval, err = envcfg.Duration("READY_INTERVAL", 2*time.Second); err != nil {
		return cfg, err
	}
	if cfg.readyTimeout, err = envcfg.Duration("READY_TIMEOUT", 180*time.Second); err != nil {
		return cfg, err
	}
	return cfg, nil
}

type metrics struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "probe_requests_total",
			Help: "Legit probe attempts, by target and result.",
		}, []string{"target", "result"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "probe_request_seconds",
			Help:    "Wall time per probe attempt including any proof-of-work solve, by target.",
			Buckets: []float64{.01, .05, .1, .25, .5, 1, 2.5, 5, 10, 20, 30},
		}, []string{"target"}),
	}
	reg.MustRegister(m.requests, m.duration)
	return m
}

// prober keeps one cookie jar so a pass earned from Ankah is reused on later
// attempts instead of being re-solved every second.
type prober struct {
	client      *http.Client
	requestPath string
}

func newProber(timeout time.Duration) (*prober, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &prober{
		client: &http.Client{
			Jar:     jar,
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy:             nil,
				DisableKeepAlives: true,
				ForceAttemptHTTP2: false,
				TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
			},
			// Do not follow redirects: the flows here answer inline (a 428
			// gate, then a 200), and following blindly would hide failures.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// attempt performs one visit, solving an Ankah challenge if one is returned,
// and reports success only when the final response is 2xx.
func (p *prober) attempt(ctx context.Context, t targets.Target) error {
	reqURL := t.URL(p.requestPath)
	code, body, err := p.get(ctx, reqURL)
	if err != nil {
		return err
	}
	if code >= 200 && code < 300 {
		return nil
	}
	challenge, session, perr := ankahpow.ParseGate(body)
	if perr != nil {
		return fmt.Errorf("status %d with no solvable challenge", code)
	}
	answer, err := ankahpow.Solve(challenge)
	if err != nil {
		return fmt.Errorf("solve: %w", err)
	}
	if err := p.open(ctx, t.BaseURL, challenge, session, answer); err != nil {
		return err
	}
	code, _, err = p.get(ctx, reqURL) // retry with the pass cookie now in the jar
	if err != nil {
		return err
	}
	if code < 200 || code >= 300 {
		return fmt.Errorf("still %d after solving", code)
	}
	return nil
}

func (p *prober) get(ctx context.Context, rawURL string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Close = true
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, "", err
	}
	return resp.StatusCode, string(body), nil
}

// open submits an answer the way Ankah's challenge page does: a gate that
// created a session is answered at /ankah/answer/<session>, which marks the
// session cookie solved; a bare challenge is exchanged for a pass cookie at
// /ankah/open.
func (p *prober) open(ctx context.Context, base, challenge, session string, answer uint64) error {
	target := base + "/ankah/answer/" + session + "?answer=" + strconv.FormatUint(answer, 10)
	if session == "" {
		q := url.Values{"challenge": {challenge}, "answer": {strconv.FormatUint(answer, 10)}}
		target = base + "/ankah/open?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Close = true
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("open returned %d", resp.StatusCode)
	}
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("legit-probe: configuration error: %v", err)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	m := newMetrics(reg)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{Addr: cfg.listen, Handler: debugMux(reg)}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("legit-probe: debug server: %v", err)
		}
	}()

	var readyURLs []string
	for _, t := range cfg.targets {
		readyURLs = append(readyURLs, t.URL("/"))
	}
	log.Printf("legit-probe: waiting for %d readiness url(s)", len(readyURLs))
	if err := ready.Wait(ctx, readyURLs, cfg.readyInterval, cfg.readyTimeout); err != nil {
		if ctx.Err() != nil {
			shutdown(srv)
			return
		}
		log.Printf("legit-probe: proceeding despite readiness wait: %v", err)
	}
	log.Printf("legit-probe: probing at %g req/s across %d target(s)", cfg.rps, len(cfg.targets))

	prb, err := newProber(cfg.timeout)
	if err != nil {
		log.Fatalf("legit-probe: %v", err)
	}
	prb.requestPath = cfg.requestPath
	s := &sched.Scheduler[targets.Target]{
		Targets:     cfg.targets,
		Rate:        cfg.rps,
		Concurrency: cfg.concurrency,
		Do: func(ctx context.Context, seq uint64, t targets.Target) {
			reqCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
			defer cancel()
			start := time.Now()
			err := prb.attempt(reqCtx, t)
			m.duration.WithLabelValues(t.Name).Observe(time.Since(start).Seconds())
			result := "success"
			if err != nil {
				result = "failure"
				log.Printf("legit-probe: %s attempt failed: %v", t.Name, err)
			}
			m.requests.WithLabelValues(t.Name, result).Inc()
		},
	}
	s.Run(ctx)
	log.Printf("legit-probe: stopping")
	shutdown(srv)
}

func debugMux(reg *prometheus.Registry) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok\n")
	})
	return mux
}

func shutdown(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
