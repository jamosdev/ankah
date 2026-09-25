package acl

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
)

var (
	attacker = netip.MustParseAddr("172.30.0.20")
	legit    = netip.MustParseAddr("172.30.0.21")
	anubis   = netip.MustParseAddr("172.30.0.10")
	ankah    = netip.MustParseAddr("172.30.0.11")
)

func demoRule() Rule {
	return Rule{
		Name:    "rule1",
		Src:     netip.MustParsePrefix("172.30.0.20/32"),
		Dst:     netip.MustParsePrefix("172.30.0.11/32"),
		Proto:   ProtoTCP,
		PortLow: 80,
		PortHi:  80,
	}
}

func TestPrefixMatching(t *testing.T) {
	r := demoRule()
	r.Src = netip.MustParsePrefix("172.30.0.0/28")
	for _, tc := range []struct {
		src  string
		want bool
	}{
		{"172.30.0.1", true},
		{"172.30.0.15", true},
		{"172.30.0.16", false},
		{"172.30.0.20", false},
		{"10.0.0.1", false},
	} {
		if got := r.Matches(netip.MustParseAddr(tc.src), ankah, ProtoTCP, 80); got != tc.want {
			t.Errorf("src %s: got %v want %v", tc.src, got, tc.want)
		}
	}
}

func TestIPv4MappedAddressesMatch(t *testing.T) {
	r := demoRule()
	mapped := netip.MustParseAddr("::ffff:172.30.0.20")
	if !r.Matches(mapped, netip.MustParseAddr("::ffff:172.30.0.11"), ProtoTCP, 80) {
		t.Fatal("IPv4-mapped IPv6 addresses should match IPv4 prefixes")
	}
}

func TestSourceAndDestinationMustBothMatch(t *testing.T) {
	tab := NewTable()
	tab.Install("c1/a1", []Rule{demoRule()})
	if _, hit := tab.Match(attacker, ankah, ProtoTCP, 80); !hit {
		t.Fatal("attacker to ankah VIP should be blocked")
	}
	if _, hit := tab.Match(legit, ankah, ProtoTCP, 80); hit {
		t.Fatal("another source to the same VIP must not be blocked")
	}
}

func TestNonMatchingDestinationIsNotBlocked(t *testing.T) {
	tab := NewTable()
	tab.Install("c1/a1", []Rule{demoRule()})
	if _, hit := tab.Match(attacker, anubis, ProtoTCP, 80); hit {
		t.Fatal("the same attacker must still reach the other VIP")
	}
}

func TestProtocolAndPortMatching(t *testing.T) {
	tab := NewTable()
	tab.Install("c1/a1", []Rule{demoRule()})
	if _, hit := tab.Match(attacker, ankah, ProtoUDP, 80); hit {
		t.Fatal("UDP must not match a TCP rule")
	}
	if _, hit := tab.Match(attacker, ankah, ProtoTCP, 443); hit {
		t.Fatal("port 443 must not match a port 80 rule")
	}
	anyRule := demoRule()
	anyRule.Proto, anyRule.PortLow, anyRule.PortHi = ProtoAny, 0, 65535
	tab.Install("c1/a2", []Rule{anyRule})
	if _, hit := tab.Match(attacker, ankah, ProtoUDP, 53); !hit {
		t.Fatal("protocol-any, port-any rule should match")
	}
}

func TestPortRange(t *testing.T) {
	r := demoRule()
	r.PortLow, r.PortHi = 8000, 8080
	for port, want := range map[uint16]bool{7999: false, 8000: true, 8080: true, 8081: false} {
		if got := r.Matches(attacker, ankah, ProtoTCP, port); got != want {
			t.Errorf("port %d: got %v want %v", port, got, want)
		}
	}
}

func TestRemove(t *testing.T) {
	tab := NewTable()
	tab.Install("c1/a1", []Rule{demoRule()})
	if !tab.Remove("c1/a1") {
		t.Fatal("remove of an installed ACL should report true")
	}
	if tab.Remove("c1/a1") {
		t.Fatal("second remove should report false")
	}
	if _, hit := tab.Match(attacker, ankah, ProtoTCP, 80); hit {
		t.Fatal("removed rule still matches")
	}
	if a, r := tab.Counts(); a != 0 || r != 0 {
		t.Fatalf("counts after remove: %d acls %d rules", a, r)
	}
}

func TestInstallReplacesSameKey(t *testing.T) {
	tab := NewTable()
	tab.Install("c1/a1", []Rule{demoRule(), demoRule()})
	tab.Install("c1/a1", []Rule{demoRule()})
	if a, r := tab.Counts(); a != 1 || r != 1 {
		t.Fatalf("got %d acls %d rules, want 1 and 1", a, r)
	}
}

func TestSnapshotIsACopy(t *testing.T) {
	tab := NewTable()
	tab.Install("c1/a1", []Rule{demoRule()})
	snap := tab.Snapshot()
	snap[0].Dst = netip.MustParsePrefix("0.0.0.0/0")
	if _, hit := tab.Match(attacker, anubis, ProtoTCP, 80); hit {
		t.Fatal("mutating a snapshot changed the table")
	}
}

func TestConcurrentReadsAndUpdates(t *testing.T) {
	tab := NewTable()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// The Anubis VIP is never blocked, whatever the writers do.
				if _, hit := tab.Match(attacker, anubis, ProtoTCP, 80); hit {
					t.Error("unrelated destination matched during concurrent update")
					return
				}
				tab.Match(attacker, ankah, ProtoTCP, 80)
			}
		}()
	}
	for i := 0; i < 2000; i++ {
		key := fmt.Sprintf("c1/a%d", i%17)
		if i%3 == 0 {
			tab.Remove(key)
		} else {
			tab.Install(key, []Rule{demoRule()})
		}
	}
	close(stop)
	wg.Wait()
	tab.Install("c1/final", []Rule{demoRule()})
	if _, hit := tab.Match(attacker, ankah, ProtoTCP, 80); !hit {
		t.Fatal("final install not visible")
	}
}
