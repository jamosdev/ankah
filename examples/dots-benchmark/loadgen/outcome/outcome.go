// Package outcome classifies request results into small fixed label sets
// and builds HTTP clients that never reuse a connection.
package outcome

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Status codes that get their own label; everything else is "other".
var knownStatus = map[int]string{
	200: "200", 302: "302", 303: "303", 400: "400", 403: "403", 404: "404",
	421: "421", 428: "428", 429: "429", 500: "500", 502: "502", 503: "503",
}

func StatusLabel(code int) string {
	if s, ok := knownStatus[code]; ok {
		return s
	}
	return "other"
}

// Result is the outcome label for a completed request.
func Result(code int, err error) string {
	if err != nil {
		return ErrorLabel(err)
	}
	switch {
	case code == http.StatusPreconditionRequired || code == http.StatusFound:
		// Both protection layers answer an unsolved client with 428
		// (Ankah by design, Anubis by the demo policy); Ankah sends 302
		// to command-line clients.
		return "challenged"
	case code >= 200 && code < 300:
		return "ok"
	case code >= 400 && code < 500:
		return "http_4xx"
	case code >= 500:
		return "http_5xx"
	}
	return "http_other"
}

// ErrorLabel names a transport failure. "reset" is what an early edge
// reject looks like from the client.
func ErrorLabel(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE),
		errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF),
		strings.Contains(err.Error(), "connection reset"),
		strings.Contains(err.Error(), "server closed idle connection"):
		return "reset"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	}
	return "error"
}

// NewClient returns an HTTP/1.1 client that opens a new TCP connection for
// every request. onDial, if set, runs once per new connection.
func NewClient(timeout time.Duration, onDial func()) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			MaxIdleConns:      -1,
			ForceAttemptHTTP2: false,
			TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if onDial != nil {
					onDial()
				}
				return dialer.DialContext(ctx, network, addr)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// NewRequest builds a GET that asks the server to close the connection.
func NewRequest(ctx context.Context, rawURL, userAgent string) (*http.Request, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Close = true
	req.Header.Set("User-Agent", userAgent)
	return req, nil
}
