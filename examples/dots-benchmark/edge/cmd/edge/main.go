// Command edge is the dots-benchmark upstream proxy: two HTTP/1.1 frontend
// addresses with a pre-HTTP ACL check, and an RFC 8783 DOTS data channel
// server provided by the go-dots router and controllers.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	dots_config "github.com/nttdots/go-dots/dots_server/config"
	"github.com/nttdots/go-dots/dots_server/models"
	data_models "github.com/nttdots/go-dots/dots_server/models/data"
	"github.com/nttdots/go-dots/dots_server/router"

	"dotsdemo/edge/acl"
	"dotsdemo/edge/admission"
	"dotsdemo/edge/dotsbridge"
	"dotsdemo/edge/proxy"
)

type frontend struct {
	name     string // metric label
	vhost    string
	listen   string
	upstream string
}

var (
	connAccepted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "edge_connections_accepted_total",
		Help: "TCP connections admitted by the ACL check and handed to net/http.",
	}, []string{"frontend"})
	connRejected = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "edge_connections_rejected_total",
		Help: "TCP connections closed by the ACL check before any HTTP parsing.",
	}, []string{"frontend"})
	httpRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "edge_http_requests_total",
		Help: "HTTP requests that reached the handler.",
	}, []string{"vhost"})
	upstreamForwards = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "edge_upstream_forwards_total",
		Help: "Requests forwarded upstream, by upstream response class.",
	}, []string{"vhost", "class"})
	aclChanges = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "edge_dots_acl_changes_total",
		Help: "ACL installs and withdrawals applied from the DOTS data channel.",
	}, []string{"op"})
	aclErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "edge_dots_acl_errors_total",
		Help: "ACL changes the edge refused.",
	}, []string{"op"})
	dotsRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "edge_dots_requests_total",
		Help: "DOTS data channel HTTP requests by method and status class.",
	}, []string{"method", "class"})
)

func main() {
	var (
		dotsConfig  = flag.String("dots-config", "/etc/edge/dots_server.yaml", "go-dots server configuration")
		debugListen = flag.String("debug-listen", "172.30.1.10:9100", "metrics, /acls and /readyz listener")
		anubis      = frontend{name: "anubis", vhost: "anubis.test"}
		ankah       = frontend{name: "ankah", vhost: "ankah.test"}
	)
	flag.StringVar(&anubis.listen, "anubis-listen", "172.30.0.10:80", "frontend address for anubis.test")
	flag.StringVar(&anubis.upstream, "anubis-upstream", "http://anubis:8923", "anubis.test upstream")
	flag.StringVar(&ankah.listen, "ankah-listen", "172.30.0.11:80", "frontend address for ankah.test")
	flag.StringVar(&ankah.upstream, "ankah-upstream", "http://ankah:8080", "ankah.test upstream")
	flag.Parse()
	setUpLogging()

	table := acl.NewTable()
	reg := prometheus.NewRegistry()
	reg.MustRegister(connAccepted, connRejected, httpRequests, upstreamForwards,
		aclChanges, aclErrors, dotsRequests,
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "edge_dots_acls",
			Help: "DOTS ACLs currently installed in the edge.",
		}, func() float64 { a, _ := table.Counts(); return float64(a) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "edge_dots_acl_rules",
			Help: "Filtering rules (ACEs) currently installed in the edge.",
		}, func() float64 { _, r := table.Counts(); return float64(r) }),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
		prometheus.NewGoCollector(),
	)
	for _, fe := range []frontend{anubis, ankah} {
		connAccepted.WithLabelValues(fe.name)
		connRejected.WithLabelValues(fe.name)
		httpRequests.WithLabelValues(fe.vhost)
	}
	for _, op := range []string{"install", "withdraw"} {
		aclChanges.WithLabelValues(op)
		aclErrors.WithLabelValues(op)
	}

	var httpReady, dotsReady atomic.Bool
	transport := proxy.NewTransport()
	// The frontends open only once the DOTS data channel is serving, so a
	// client that can reach a frontend knows the filtering path is live.
	go func() {
		if err := serveDOTS(*dotsConfig, table); err != nil {
			log.Fatal(err)
		}
		dotsReady.Store(true)
		for _, fe := range []frontend{anubis, ankah} {
			if err := serveFrontend(fe, table, transport); err != nil {
				log.Fatal(err)
			}
		}
		httpReady.Store(true)
		log.Printf("frontends listening: %s=%s %s=%s", anubis.vhost, anubis.listen, ankah.vhost, ankah.listen)
	}()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/acls", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Rules []acl.Rule `json:"rules"`
		}{table.Snapshot()})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if !httpReady.Load() || !dotsReady.Load() {
			http.Error(w, fmt.Sprintf("http=%v dots=%v\n", httpReady.Load(), dotsReady.Load()), http.StatusServiceUnavailable)
			return
		}
		_, _ = fmt.Fprintln(w, "ready")
	})
	log.Printf("debug listener on %s", *debugListen)
	log.Fatal(http.ListenAndServe(*debugListen, mux))
}

func setUpLogging() {
	level, err := logrus.ParseLevel(os.Getenv("EDGE_DOTS_LOG_LEVEL"))
	if err != nil {
		level = logrus.WarnLevel
	}
	logrus.SetLevel(level)
}

func serveFrontend(fe frontend, table *acl.Table, transport http.RoundTripper) error {
	upstream, err := url.Parse(fe.upstream)
	if err != nil {
		return err
	}
	inner, err := net.Listen("tcp", fe.listen)
	if err != nil {
		return fmt.Errorf("%s: %w", fe.vhost, err)
	}
	ln := &admission.Listener{
		Listener: inner,
		Table:    table,
		Frontend: fe.name,
		OnAccept: func(f string) { connAccepted.WithLabelValues(f).Inc() },
		OnReject: func(f string) { connRejected.WithLabelValues(f).Inc() },
	}
	handler := proxy.NewHandler(fe.vhost, upstream, transport, proxy.Hooks{
		Request: func(v string) { httpRequests.WithLabelValues(v).Inc() },
		Forward: func(v, class string) { upstreamForwards.WithLabelValues(v, class).Inc() },
	})
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       30 * time.Second,
		// HTTP/1.1 only: no TLS on the frontends, so no ALPN h2.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ErrorLog:     log.New(os.Stderr, fe.vhost+": ", log.LstdFlags),
	}
	go func() { log.Fatal(srv.Serve(ln)) }()
	return nil
}

func serveDOTS(configPath string, table *acl.Table) error {
	if _, err := dots_config.LoadServerConfig(configPath); err != nil {
		return fmt.Errorf("go-dots config: %w", err)
	}
	cfg := dots_config.GetServerSystemConfig()
	if err := waitForDatabase(); err != nil {
		return err
	}
	models.RegisterExternalACLHandler(&dotsbridge.Bridge{
		Table:    table,
		OnChange: func(op string) { aclChanges.WithLabelValues(op).Inc() },
		OnError:  func(op string) { aclErrors.WithLabelValues(op).Inc() },
	})
	go data_models.ManageExpiredAliasAndAcl(cfg.LifetimeConfiguration.ManageLifetimeInterval)

	caPEM, err := os.ReadFile(cfg.SecureFile.CertFile)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("DOTS client CA: no certificates")
	}
	cert, err := tls.LoadX509KeyPair(cfg.SecureFile.ServerCertFile, cfg.SecureFile.ServerKeyFile)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(cfg.Network.BindAddress, strconv.Itoa(cfg.Network.DataChannelPort))
	ln, err := tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           countDOTS(router.CreateRouter()),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          log.New(os.Stderr, "dots: ", log.LstdFlags),
	}
	go func() { log.Fatal(srv.Serve(ln)) }()
	log.Printf("DOTS data channel (go-dots router) on https://%s%s", addr, cfg.Network.HrefPathname)
	return nil
}

func waitForDatabase() error {
	deadline := time.Now().Add(3 * time.Minute)
	for {
		engine, err := models.ConnectDB()
		if err == nil {
			if err = engine.Ping(); err == nil {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("database not reachable: %w", err)
		}
		log.Printf("waiting for go-dots database: %v", err)
		time.Sleep(2 * time.Second)
	}
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

func countDOTS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rec, r)
		method := r.Method
		switch method {
		case http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete:
		default:
			method = "other"
		}
		dotsRequests.WithLabelValues(method, fmt.Sprintf("%dxx", rec.code/100)).Inc()
		log.Printf("dots %s %s -> %d", r.Method, r.URL.Path, rec.code)
	})
}
