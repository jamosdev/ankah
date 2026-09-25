package admission

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"dotsdemo/edge/acl"
)

func serve(t *testing.T, tab *acl.Table) (addr string, accepted, rejected, handled *atomic.Int64) {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted, rejected, handled = new(atomic.Int64), new(atomic.Int64), new(atomic.Int64)
	l := &Listener{
		Listener: inner,
		Table:    tab,
		Frontend: "test",
		OnAccept: func(string) { accepted.Add(1) },
		OnReject: func(string) { rejected.Add(1) },
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handled.Add(1)
		_, _ = io.WriteString(w, "ok")
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return inner.Addr().String(), accepted, rejected, handled
}

func get(addr string) error {
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	resp, err := client.Get("http://" + addr + "/")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	return err
}

func TestUnmatchedConnectionReachesHTTP(t *testing.T) {
	addr, accepted, rejected, handled := serve(t, acl.NewTable())
	if err := get(addr); err != nil {
		t.Fatal(err)
	}
	if accepted.Load() != 1 || rejected.Load() != 0 || handled.Load() != 1 {
		t.Fatalf("accepted=%d rejected=%d handled=%d", accepted.Load(), rejected.Load(), handled.Load())
	}
}

func TestMatchedConnectionIsClosedBeforeHTTP(t *testing.T) {
	tab := acl.NewTable()
	addr, accepted, rejected, handled := serve(t, tab)
	port := netip.MustParseAddrPort(addr).Port()
	tab.Install("c1/a1", []acl.Rule{{
		Src:     netip.MustParsePrefix("127.0.0.1/32"),
		Dst:     netip.MustParsePrefix("127.0.0.1/32"),
		Proto:   acl.ProtoTCP,
		PortLow: port,
		PortHi:  port,
	}})
	for i := 0; i < 5; i++ {
		err := get(addr)
		if err == nil {
			t.Fatal("request through a blocked connection succeeded")
		}
		if !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, io.EOF) {
			t.Logf("client error (acceptable): %v", err)
		}
	}
	if rejected.Load() != 5 || accepted.Load() != 0 || handled.Load() != 0 {
		t.Fatalf("accepted=%d rejected=%d handled=%d", accepted.Load(), rejected.Load(), handled.Load())
	}
	tab.Remove("c1/a1")
	if err := get(addr); err != nil {
		t.Fatalf("after removal: %v", err)
	}
	if handled.Load() != 1 {
		t.Fatalf("handled=%d after removal", handled.Load())
	}
}

func TestRuleForOtherPortDoesNotBlock(t *testing.T) {
	tab := acl.NewTable()
	addr, _, rejected, handled := serve(t, tab)
	port := netip.MustParseAddrPort(addr).Port()
	tab.Install("c1/a1", []acl.Rule{{
		Src:     netip.MustParsePrefix("127.0.0.1/32"),
		Dst:     netip.MustParsePrefix("127.0.0.1/32"),
		Proto:   acl.ProtoTCP,
		PortLow: port + 1,
		PortHi:  port + 1,
	}})
	if err := get(addr); err != nil {
		t.Fatal(err)
	}
	if rejected.Load() != 0 || handled.Load() != 1 {
		t.Fatalf("rejected=%d handled=%d", rejected.Load(), handled.Load())
	}
}
