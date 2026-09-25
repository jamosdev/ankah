package ready

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestWaitReturnsWhenAllAnswer(t *testing.T) {
	var hits atomic.Int64
	// Answers 503 for the first two calls, then 428 (a challenge, which
	// counts as ready).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusPreconditionRequired)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Wait(ctx, []string{srv.URL}, 5*time.Millisecond, 5*time.Second); err != nil {
		t.Fatalf("Wait returned %v", err)
	}
	if hits.Load() < 3 {
		t.Fatalf("Wait stopped polling too early after %d hits", hits.Load())
	}
}

func TestWaitTimesOut(t *testing.T) {
	// A URL that never answers (closed port) must make Wait time out rather
	// than block forever.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := Wait(ctx, []string{url}, 5*time.Millisecond, 100*time.Millisecond); err == nil {
		t.Fatal("Wait did not time out on an unreachable URL")
	}
}
