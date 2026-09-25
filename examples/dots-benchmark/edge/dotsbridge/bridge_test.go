package dotsbridge

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	types "github.com/nttdots/go-dots/dots_common/types/data"

	"dotsdemo/edge/acl"
)

// demoACL is the body Ankah sends, parsed with the go-dots types.
const demoACL = `{"ietf-dots-data-channel:acls":{"acl":[{"name":"ankah-172-30-0-20",
"type":"ipv4-acl-type","activation-type":"immediate","aces":{"ace":[{"name":"block",
"matches":{"ipv4":{"source-ipv4-network":"172.30.0.20/32","destination-ipv4-network":"172.30.0.11/32","protocol":6},
"tcp":{"destination-port-range-or-operator":{"operator":"eq","port":80}}},
"actions":{"forwarding":"drop"}}]}}]}}`

func parse(t *testing.T, body string) *types.ACL {
	t.Helper()
	var req struct {
		ACLs types.ACLs `json:"ietf-dots-data-channel:acls"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	return &req.ACLs.ACL[0]
}

func TestConvertDemoACL(t *testing.T) {
	rules, err := Convert(parse(t, demoACL))
	if err != nil {
		t.Fatal(err)
	}
	want := acl.Rule{
		Name:    "block",
		Src:     netip.MustParsePrefix("172.30.0.20/32"),
		Dst:     netip.MustParsePrefix("172.30.0.11/32"),
		Proto:   acl.ProtoTCP,
		PortLow: 80,
		PortHi:  80,
	}
	if len(rules) != 1 || rules[0] != want {
		t.Fatalf("got %+v", rules)
	}
}

func TestUnsupportedMatchesAreRefused(t *testing.T) {
	for name, body := range map[string]string{
		"accept":      strings.Replace(demoACL, `"drop"`, `"accept"`, 1),
		"source port": strings.Replace(demoACL, `"tcp":{`, `"tcp":{"source-port-range-or-operator":{"operator":"eq","port":1},`, 1),
		"ttl":         strings.Replace(demoACL, `"protocol":6`, `"protocol":6,"ttl":3`, 1),
		"neq":         strings.Replace(demoACL, `"eq"`, `"neq"`, 1),
		"udp proto":   strings.Replace(demoACL, `"protocol":6`, `"protocol":17`, 1),
	} {
		if _, err := Convert(parse(t, body)); err == nil {
			t.Errorf("%s: expected refusal", name)
		}
	}
}

func TestBridgeInstallAndRemove(t *testing.T) {
	tab := acl.NewTable()
	var changes []string
	b := &Bridge{Table: tab, OnChange: func(op string) { changes = append(changes, op) }}
	if err := b.InstallACL(1, 7, parse(t, demoACL)); err != nil {
		t.Fatal(err)
	}
	attacker := netip.MustParseAddr("172.30.0.20")
	if _, hit := tab.Match(attacker, netip.MustParseAddr("172.30.0.11"), acl.ProtoTCP, 80); !hit {
		t.Fatal("installed ACL does not match")
	}
	if _, hit := tab.Match(attacker, netip.MustParseAddr("172.30.0.10"), acl.ProtoTCP, 80); hit {
		t.Fatal("installed ACL matches the other VIP")
	}
	if err := b.RemoveACL(1, 7, "ankah-172-30-0-20"); err != nil {
		t.Fatal(err)
	}
	if a, _ := tab.Counts(); a != 0 {
		t.Fatal("ACL not removed")
	}
	if strings.Join(changes, ",") != "install,withdraw" {
		t.Fatalf("changes %v", changes)
	}
}
