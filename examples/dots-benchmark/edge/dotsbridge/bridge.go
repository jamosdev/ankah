// Package dotsbridge connects the go-dots External-ACL blocker to the edge
// ACL table. go-dots has already authenticated the client, checked the
// destination against the customer's address range and validated the ACL
// before these methods run.
package dotsbridge

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	types "github.com/nttdots/go-dots/dots_common/types/data"

	"dotsdemo/edge/acl"
)

// Bridge implements models.ExternalACLHandler.
type Bridge struct {
	Table    *acl.Table
	OnChange func(op string)
	OnError  func(op string)
}

func Key(customerID int, aclID int64) string {
	return fmt.Sprintf("customer-%d/acl-%d", customerID, aclID)
}

func (b *Bridge) InstallACL(customerID int, aclID int64, a *types.ACL) error {
	rules, err := Convert(a)
	if err != nil {
		b.event(b.OnError, "install")
		return err
	}
	b.Table.Install(Key(customerID, aclID), rules)
	b.event(b.OnChange, "install")
	return nil
}

func (b *Bridge) RemoveACL(customerID int, aclID int64, name string) error {
	// Removing an ACL the table no longer holds (for example after an edge
	// restart) is not an error: the requested end state already holds.
	b.Table.Remove(Key(customerID, aclID))
	b.event(b.OnChange, "withdraw")
	return nil
}

func (b *Bridge) event(f func(string), op string) {
	if f != nil {
		f(op)
	}
}

// Convert turns an RFC 8783 ACL into edge rules. Any match the edge cannot
// enforce exactly is refused, so a rule is never silently widened.
func Convert(a *types.ACL) ([]acl.Rule, error) {
	if a == nil || len(a.ACEs.ACE) == 0 {
		return nil, errors.New("ACL has no entries")
	}
	rules := make([]acl.Rule, 0, len(a.ACEs.ACE))
	for _, ace := range a.ACEs.ACE {
		r, err := convertACE(ace)
		if err != nil {
			return nil, fmt.Errorf("ace %q: %w", ace.Name, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func convertACE(ace types.ACE) (acl.Rule, error) {
	r := acl.Rule{Name: ace.Name, PortLow: 0, PortHi: 65535}
	if ace.Actions == nil || ace.Actions.Forwarding == nil {
		return r, errors.New("missing forwarding action")
	}
	if *ace.Actions.Forwarding != types.ForwardingAction_Drop {
		return r, fmt.Errorf("forwarding action %q is not supported (only drop)", *ace.Actions.Forwarding)
	}
	m := ace.Matches
	if m == nil {
		return r, errors.New("missing matches")
	}
	if m.ICMP != nil {
		return r, errors.New("icmp matches are not supported")
	}
	var proto *uint8
	switch {
	case m.IPv4 != nil && m.IPv6 == nil:
		v := m.IPv4
		if v.DSCP != nil || v.ECN != nil || v.Length != nil || v.TTL != nil || v.IHL != nil ||
			v.Flags != nil || v.Offset != nil || v.Identification != nil || v.Fragment != nil {
			return r, errors.New("only ipv4 source, destination and protocol are supported")
		}
		src, err := prefix((*types.IPPrefix)(v.SourceIPv4Network), true)
		if err != nil {
			return r, err
		}
		dst, err := prefix((*types.IPPrefix)(v.DestinationIPv4Network), true)
		if err != nil {
			return r, err
		}
		r.Src, r.Dst, proto = src, dst, v.Protocol
	case m.IPv6 != nil && m.IPv4 == nil:
		v := m.IPv6
		if v.DSCP != nil || v.ECN != nil || v.Length != nil || v.TTL != nil ||
			v.FlowLabel != nil || v.Fragment != nil {
			return r, errors.New("only ipv6 source, destination and protocol are supported")
		}
		src, err := prefix((*types.IPPrefix)(v.SourceIPv6Network), false)
		if err != nil {
			return r, err
		}
		dst, err := prefix((*types.IPPrefix)(v.DestinationIPv6Network), false)
		if err != nil {
			return r, err
		}
		r.Src, r.Dst, proto = src, dst, v.Protocol
	default:
		return r, errors.New("exactly one of ipv4 or ipv6 matches is required")
	}
	if proto != nil {
		r.Proto = *proto
	}
	var ports *types.PortRangeOrOperator
	switch {
	case m.TCP != nil && m.UDP != nil:
		return r, errors.New("both tcp and udp matches")
	case m.TCP != nil:
		t := m.TCP
		if t.SequenceNumber != nil || t.AcknowledgementNumber != nil || t.DataOffset != nil ||
			t.Reserved != nil || t.Flags != nil || t.WindowSize != nil || t.UrgentPointer != nil ||
			t.Options != nil || t.FlagsBitmask != nil || t.SourcePort != nil {
			return r, errors.New("only the tcp destination port is supported")
		}
		if err := setProto(&r, acl.ProtoTCP); err != nil {
			return r, err
		}
		ports = t.DestinationPort
	case m.UDP != nil:
		u := m.UDP
		if u.Length != nil || u.SourcePort != nil {
			return r, errors.New("only the udp destination port is supported")
		}
		if err := setProto(&r, acl.ProtoUDP); err != nil {
			return r, err
		}
		ports = u.DestinationPort
	}
	if ports != nil {
		lo, hi, err := portRange(ports)
		if err != nil {
			return r, err
		}
		r.PortLow, r.PortHi = lo, hi
	}
	return r, nil
}

func setProto(r *acl.Rule, p uint8) error {
	if r.Proto != acl.ProtoAny && r.Proto != p {
		return fmt.Errorf("protocol %d conflicts with layer 4 match", r.Proto)
	}
	r.Proto = p
	return nil
}

// prefix converts a go-dots prefix. A missing prefix matches everything.
func prefix(p *types.IPPrefix, v4 bool) (netip.Prefix, error) {
	if p == nil {
		if v4 {
			return netip.MustParsePrefix("0.0.0.0/0"), nil
		}
		return netip.MustParsePrefix("::/0"), nil
	}
	ip := p.IP
	if v4 {
		ip = ip.To4()
	} else if ip.To4() == nil {
		ip = ip.To16()
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || (v4 && ip == nil) {
		return netip.Prefix{}, fmt.Errorf("invalid address %v", net.IP(p.IP))
	}
	pfx, err := addr.Prefix(p.Length)
	if err != nil {
		return netip.Prefix{}, err
	}
	return pfx, nil
}

func portRange(p *types.PortRangeOrOperator) (uint16, uint16, error) {
	if p.LowerPort != nil {
		lo := uint16(*p.LowerPort)
		hi := lo
		if p.UpperPort != nil {
			hi = uint16(*p.UpperPort)
		}
		return lo, hi, nil
	}
	if p.Port == nil {
		return 0, 0, errors.New("port match without a port")
	}
	port := uint16(*p.Port)
	op := types.Operator_EQ
	if p.Operator != nil {
		op = *p.Operator
	}
	switch op {
	case types.Operator_EQ:
		return port, port, nil
	case types.Operator_LTE:
		return 0, port, nil
	case types.Operator_GTE:
		return port, 65535, nil
	}
	return 0, 0, fmt.Errorf("port operator %q is not supported", op)
}
