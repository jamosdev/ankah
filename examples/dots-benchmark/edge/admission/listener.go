// Package admission applies the ACL table to accepted TCP connections before
// they are handed to net/http, so a rejected connection is never parsed.
package admission

import (
	"net"
	"net/netip"

	"dotsdemo/edge/acl"
)

// Listener wraps a TCP listener. Frontend is a fixed, low-cardinality name
// for the address this listener serves and is only used for metrics.
type Listener struct {
	net.Listener
	Table    *acl.Table
	Frontend string
	OnAccept func(frontend string)
	OnReject func(frontend string)
}

func (l *Listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.admit(c) {
			if l.OnAccept != nil {
				l.OnAccept(l.Frontend)
			}
			return c, nil
		}
		// Linger 0 makes Close send RST, so the client sees an immediate
		// reset rather than a normal end of stream.
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = c.Close()
		if l.OnReject != nil {
			l.OnReject(l.Frontend)
		}
	}
}

func (l *Listener) admit(c net.Conn) bool {
	remote, rok := addrPort(c.RemoteAddr())
	local, lok := addrPort(c.LocalAddr())
	if !rok || !lok {
		return true
	}
	_, hit := l.Table.Match(remote.Addr(), local.Addr(), acl.ProtoTCP, local.Port())
	return !hit
}

func addrPort(a net.Addr) (netip.AddrPort, bool) {
	if tcp, ok := a.(*net.TCPAddr); ok {
		return tcp.AddrPort(), true
	}
	ap, err := netip.ParseAddrPort(a.String())
	return ap, err == nil
}
