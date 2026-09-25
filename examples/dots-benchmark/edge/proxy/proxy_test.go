package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

type seen struct {
	mu      sync.Mutex
	headers http.Header
	host    string
	remote  string
}

func backend(t *testing.T, name string, s *seen) *url.URL {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.headers = r.Header.Clone()
		s.host = r.Host
		s.remote = r.RemoteAddr
		s.mu.Unlock()
		w.Header().Set("Ankah-Proxy-Action", "block")
		_, _ = io.WriteString(w, name)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return u
}

type counter struct {
	mu       sync.Mutex
	requests map[string]int
	forwards map[string]int
}

func newCounter() *counter {
	return &counter{requests: map[string]int{}, forwards: map[string]int{}}
}

func (c *counter) hooks() Hooks {
	return Hooks{
		Request: func(v string) { c.mu.Lock(); c.requests[v]++; c.mu.Unlock() },
		Forward: func(v, class string) { c.mu.Lock(); c.forwards[v+"/"+class]++; c.mu.Unlock() },
	}
}

func do(t *testing.T, h http.Handler, host string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "http://"+host+"/pi?n=10", nil)
	req.Host = host
	req.RemoteAddr = "172.30.0.20:40000"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestVhostRouting(t *testing.T) {
	var sa, sk seen
	c := newCounter()
	anubis := NewHandler("anubis.test", backend(t, "anubis", &sa), NewTransport(), c.hooks())
	ankah := NewHandler("ankah.test", backend(t, "ankah", &sk), NewTransport(), c.hooks())

	if rec := do(t, anubis, "anubis.test", nil); rec.Body.String() != "anubis" {
		t.Fatalf("anubis.test routed to %q", rec.Body.String())
	}
	if rec := do(t, ankah, "ANKAH.test:80", nil); rec.Body.String() != "ankah" {
		t.Fatalf("ankah.test routed to %q", rec.Body.String())
	}
	if c.forwards["anubis.test/2xx"] != 1 || c.forwards["ankah.test/2xx"] != 1 {
		t.Fatalf("forward counts %v", c.forwards)
	}
	if sk.host != "ankah.test" {
		t.Fatalf("upstream Host %q", sk.host)
	}
}

func TestUnknownOrMismatchedHostIsRejected(t *testing.T) {
	var s seen
	c := newCounter()
	anubis := NewHandler("anubis.test", backend(t, "anubis", &s), NewTransport(), c.hooks())
	for _, host := range []string{"example.com", "ankah.test", ""} {
		rec := do(t, anubis, host, nil)
		if rec.Code != http.StatusMisdirectedRequest {
			t.Errorf("host %q: status %d", host, rec.Code)
		}
	}
	if s.headers != nil {
		t.Fatal("a rejected host reached the upstream")
	}
	if len(c.forwards) != 0 || c.requests["anubis.test"] != 3 {
		t.Fatalf("requests %v forwards %v", c.requests, c.forwards)
	}
}

func TestForwardingHeadersAreRebuiltFromThePeer(t *testing.T) {
	var s seen
	h := NewHandler("ankah.test", backend(t, "ankah", &s), NewTransport(), Hooks{})
	rec := do(t, h, "ankah.test", map[string]string{
		"X-Forwarded-For":   "203.0.113.9, 198.51.100.7",
		"X-Real-Ip":         "203.0.113.9",
		"Forwarded":         "for=203.0.113.9",
		"X-Forwarded-Host":  "evil.example",
		"X-Forwarded-Proto": "https",
	})
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if got := s.headers.Values("X-Forwarded-For"); len(got) != 1 || got[0] != "172.30.0.20" {
		t.Fatalf("X-Forwarded-For %q", got)
	}
	if got := s.headers.Get("X-Real-Ip"); got != "172.30.0.20" {
		t.Fatalf("X-Real-Ip %q", got)
	}
	if got := s.headers.Get("Forwarded"); got != "" {
		t.Fatalf("Forwarded leaked: %q", got)
	}
	if got := s.headers.Get("X-Forwarded-Host"); got != "ankah.test" {
		t.Fatalf("X-Forwarded-Host %q", got)
	}
	if got := s.headers.Get("X-Forwarded-Proto"); got != "http" {
		t.Fatalf("X-Forwarded-Proto %q", got)
	}
	if rec.Header().Get("Ankah-Proxy-Action") != "" {
		t.Fatal("private upstream signalling reached the client")
	}
}

func TestUpstreamErrorIsCounted(t *testing.T) {
	c := newCounter()
	dead, _ := url.Parse("http://127.0.0.1:1")
	h := NewHandler("ankah.test", dead, NewTransport(), c.hooks())
	if rec := do(t, h, "ankah.test", nil); rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d", rec.Code)
	}
	if c.forwards["ankah.test/error"] != 1 {
		t.Fatalf("forwards %v", c.forwards)
	}
}
