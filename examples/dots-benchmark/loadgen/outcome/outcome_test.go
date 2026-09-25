package outcome

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestEveryRequestUsesANewConnection(t *testing.T) {
	var conns atomic.Int64
	var mu sync.Mutex
	var closeHeaders []bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		closeHeaders = append(closeHeaders, r.Close)
		mu.Unlock()
		if r.ProtoMajor != 1 || r.ProtoMinor != 1 {
			t.Errorf("protocol %s", r.Proto)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	var dials atomic.Int64
	client := NewClient(2*time.Second, func() { dials.Add(1) })
	const n = 25
	for i := 0; i < n; i++ {
		req, err := NewRequest(context.Background(), srv.URL+"/pi?n=1", "dots-demo-attacker")
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if got := conns.Load(); got != n {
		t.Fatalf("%d requests used %d connections", n, got)
	}
	if got := dials.Load(); got != n {
		t.Fatalf("%d requests dialled %d times", n, got)
	}
	for i, c := range closeHeaders {
		if !c {
			t.Fatalf("request %d did not send Connection: close", i)
		}
	}
}

func TestResultLabels(t *testing.T) {
	for _, tc := range []struct {
		code int
		err  error
		want string
	}{
		{200, nil, "ok"},
		{428, nil, "challenged"},
		{302, nil, "challenged"},
		{421, nil, "http_4xx"},
		{502, nil, "http_5xx"},
		{0, syscall.ECONNRESET, "reset"},
		{0, io.EOF, "reset"},
		{0, syscall.ECONNREFUSED, "refused"},
		{0, context.DeadlineExceeded, "timeout"},
		{0, errors.New("boom"), "error"},
	} {
		if got := Result(tc.code, tc.err); got != tc.want {
			t.Errorf("Result(%d, %v) = %s, want %s", tc.code, tc.err, got, tc.want)
		}
	}
	if StatusLabel(418) != "other" || StatusLabel(428) != "428" {
		t.Fatal("status labels")
	}
}
