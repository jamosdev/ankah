// Package ankahpow solves Ankah's proof of work the way its browser page
// does: find the smallest counter where SHA-256("<nonce>:<counter>") starts
// with the challenge's number of zero bits.
package ankahpow

import (
	"crypto/sha256"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var (
	challengeAttr = regexp.MustCompile(`data-challenge='([0-9a-f.]+)'`)
	sessionAttr   = regexp.MustCompile(`data-session='([0-9a-f]{32})'`)
)

// ParseGate extracts the challenge and session id from Ankah's HTML gate.
func ParseGate(html string) (challenge, session string, err error) {
	c := challengeAttr.FindStringSubmatch(html)
	s := sessionAttr.FindStringSubmatch(html)
	if c == nil || s == nil {
		return "", "", errors.New("no Ankah challenge in response")
	}
	return c[1], s[1], nil
}

// Solve returns the answer counter for a challenge.
func Solve(challenge string) (uint64, error) {
	parts := strings.Split(challenge, ".")
	if len(parts) != 4 || len(parts[0]) != 32 {
		return 0, errors.New("invalid challenge")
	}
	bits, err := strconv.Atoi(parts[2])
	if err != nil || bits < 8 || bits > 24 {
		return 0, errors.New("unsupported difficulty")
	}
	full, rem := bits/8, bits%8
	prefix := []byte(parts[0] + ":")
	buf := make([]byte, 0, len(prefix)+20)
	for counter := uint64(0); counter < 1<<35; counter++ {
		buf = strconv.AppendUint(append(buf[:0], prefix...), counter, 10)
		sum := sha256.Sum256(buf)
		ok := true
		for i := 0; i < full; i++ {
			if sum[i] != 0 {
				ok = false
				break
			}
		}
		if ok && (rem == 0 || sum[full]>>(8-rem) == 0) {
			return counter, nil
		}
	}
	return 0, errors.New("search exhausted")
}
