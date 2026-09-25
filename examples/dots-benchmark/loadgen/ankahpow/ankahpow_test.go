package ankahpow

import (
	"crypto/sha256"
	"strconv"
	"testing"
)

func TestSolve(t *testing.T) {
	nonce := "0123456789abcdef0123456789abcdef"
	challenge := nonce + ".1700000000.12.deadbeef"
	n, err := Solve(challenge)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(nonce + ":" + strconv.FormatUint(n, 10)))
	if sum[0] != 0 || sum[1]>>4 != 0 {
		t.Fatalf("answer %d does not have 12 leading zero bits: %x", n, sum[:2])
	}
	for c := uint64(0); c < n; c++ {
		s := sha256.Sum256([]byte(nonce + ":" + strconv.FormatUint(c, 10)))
		if s[0] == 0 && s[1]>>4 == 0 {
			t.Fatalf("smaller answer %d exists", c)
		}
	}
}

func TestParseGate(t *testing.T) {
	html := `<body data-challenge='0123456789abcdef0123456789abcdef.1.18.ab' data-session='00112233445566778899aabbccddeeff' data-worker='x'>`
	c, s, err := ParseGate(html)
	if err != nil || c != "0123456789abcdef0123456789abcdef.1.18.ab" || s != "00112233445566778899aabbccddeeff" {
		t.Fatalf("%q %q %v", c, s, err)
	}
	if _, _, err := ParseGate("<html>"); err == nil {
		t.Fatal("expected error")
	}
}
