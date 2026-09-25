// Package acl holds the edge's in-memory filtering rules.
//
// Readers (the accept loop) load an immutable snapshot through an atomic
// pointer and never take a lock. Writers (DOTS installs and withdrawals)
// serialise on a mutex and publish a fresh copy.
package acl

import (
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
)

const (
	ProtoAny = 0
	ProtoTCP = 6
	ProtoUDP = 17
)

// Rule matches one source and destination prefix pair. Proto 0 matches any
// protocol. The destination port range is inclusive; 0-65535 matches any.
type Rule struct {
	ACL     string       `json:"acl"`
	Name    string       `json:"name"`
	Src     netip.Prefix `json:"src"`
	Dst     netip.Prefix `json:"dst"`
	Proto   uint8        `json:"proto"`
	PortLow uint16       `json:"port_low"`
	PortHi  uint16       `json:"port_high"`
}

// Matches reports whether a flow from src to dst:port over proto hits r.
func (r Rule) Matches(src, dst netip.Addr, proto uint8, port uint16) bool {
	src, dst = src.Unmap(), dst.Unmap()
	if r.Proto != ProtoAny && r.Proto != proto {
		return false
	}
	if port < r.PortLow || port > r.PortHi {
		return false
	}
	return r.Src.Contains(src) && r.Dst.Contains(dst)
}

// Table is safe for concurrent use.
type Table struct {
	mu    sync.Mutex
	acls  map[string][]Rule
	rules atomic.Pointer[[]Rule]
}

func NewTable() *Table {
	t := &Table{acls: map[string][]Rule{}}
	empty := []Rule{}
	t.rules.Store(&empty)
	return t
}

// Match returns the first matching rule.
func (t *Table) Match(src, dst netip.Addr, proto uint8, port uint16) (Rule, bool) {
	for _, r := range *t.rules.Load() {
		if r.Matches(src, dst, proto, port) {
			return r, true
		}
	}
	return Rule{}, false
}

// Install replaces every rule belonging to key with rules.
func (t *Table) Install(key string, rules []Rule) {
	t.mu.Lock()
	defer t.mu.Unlock()
	copied := make([]Rule, len(rules))
	for i, r := range rules {
		r.ACL = key
		r.Src, r.Dst = r.Src.Masked(), r.Dst.Masked()
		copied[i] = r
	}
	t.acls[key] = copied
	t.publish()
}

// Remove deletes the rules for key and reports whether any existed.
func (t *Table) Remove(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.acls[key]; !ok {
		return false
	}
	delete(t.acls, key)
	t.publish()
	return true
}

// Snapshot returns the current rules in a stable order.
func (t *Table) Snapshot() []Rule {
	rules := *t.rules.Load()
	return append([]Rule(nil), rules...)
}

// Counts returns the number of installed ACLs and rules.
func (t *Table) Counts() (acls, rules int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.acls), len(*t.rules.Load())
}

func (t *Table) publish() {
	keys := make([]string, 0, len(t.acls))
	for k := range t.acls {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	next := make([]Rule, 0, len(keys))
	for _, k := range keys {
		next = append(next, t.acls[k]...)
	}
	t.rules.Store(&next)
}
