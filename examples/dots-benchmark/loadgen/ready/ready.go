// Package ready gates a load generator until the demo edge and its backends
// answer. A generator that starts firing before the frontends are up would
// record a burst of dial errors that mean nothing, so both binaries wait
// here first.
package ready

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// userAgent keeps readiness probes out of the attacker and legit metrics on
// the backends, which classify clients by User-Agent.
const userAgent = "dots-demo-ready"

// probe reports whether one URL answers well enough to start load. Any
// completed HTTP response counts as ready, including a challenge, because it
// proves the frontend and its upstream are reachable. A gateway error means
// the upstream is still starting, and a transport error means nothing
// answered at all.
func probe(ctx context.Context, client *http.Client, rawURL string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", userAgent)
	req.Close = true
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return false
	}
	return true
}

// Wait polls each URL until all answer, ctx is done, or timeout elapses.
// Each URL drops out of the poll set once it first answers.
func Wait(ctx context.Context, urls []string, interval, timeout time.Duration) error {
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	deadline := time.Now().Add(timeout)
	pending := append([]string(nil), urls...)
	for {
		var still []string
		for _, u := range pending {
			if !probe(ctx, client, u) {
				still = append(still, u)
			}
		}
		pending = still
		if len(pending) == 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("not ready after %s: %v", timeout, pending)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}
