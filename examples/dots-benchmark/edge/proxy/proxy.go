// Package proxy is the edge's HTTP/1.1 virtual host reverse proxy.
package proxy

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Hooks receive metric events. Vhost and class values come from fixed sets.
type Hooks struct {
	Request func(vhost string)
	Forward func(vhost, class string)
}

// Handler serves exactly one virtual host. Each frontend address has its own
// Handler, so a request for ankah.test sent to the Anubis address cannot
// bypass a destination-scoped filter on the Ankah address.
type Handler struct {
	Vhost string
	proxy *httputil.ReverseProxy
	hooks Hooks
}

func NewHandler(vhost string, upstream *url.URL, transport http.RoundTripper, hooks Hooks) *Handler {
	h := &Handler{Vhost: vhost, hooks: hooks}
	h.proxy = &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Rewrite has already removed Forwarded and X-Forwarded-*
			// from the outbound request. X-Real-Ip is not covered, and
			// nothing the client sent may name the client address.
			pr.Out.Header.Del("X-Real-Ip")
			pr.SetURL(upstream)
			pr.Out.Host = vhost
			pr.SetXForwarded()
			if ip, ok := PeerIP(pr.In.RemoteAddr); ok {
				pr.Out.Header.Set("X-Real-Ip", ip.String())
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			// Private Ankah-to-proxy signalling never reaches clients.
			resp.Header.Del("Ankah-Proxy-Action")
			h.forward(statusClass(resp.StatusCode))
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			h.forward("error")
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	return h
}

func (h *Handler) forward(class string) {
	if h.hooks.Forward != nil {
		h.hooks.Forward(h.Vhost, class)
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.hooks.Request != nil {
		h.hooks.Request(h.Vhost)
	}
	if NormalizeHost(r.Host) != h.Vhost {
		http.Error(w, "unknown host for this address", http.StatusMisdirectedRequest)
		return
	}
	h.proxy.ServeHTTP(w, r)
}

// NormalizeHost lower-cases a Host value and drops any port.
func NormalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(host, ".")
}

// PeerIP extracts the socket peer from Request.RemoteAddr.
func PeerIP(remoteAddr string) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

func statusClass(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500 && code < 600:
		return "5xx"
	}
	return "other"
}

// NewTransport returns the pooled transport used towards backends. Pooling
// here is deliberate: only the attacker side of the edge uses new
// connections for every request.
func NewTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   128,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ForceAttemptHTTP2:     false,
	}
}
