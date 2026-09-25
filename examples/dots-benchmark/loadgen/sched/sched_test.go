package sched

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStrictAlternationUnderConcurrency(t *testing.T) {
	var (
		mu        sync.Mutex
		issued    []string
		completed []uint64
		inflight  atomic.Int64
		peak      atomic.Int64
	)
	ctx, cancel := context.WithCancel(context.Background())
	s := &Scheduler[string]{
		Targets:     []string{"anubis", "ankah"},
		Concurrency: 8,
		Issued: func(seq uint64, target string) {
			mu.Lock()
			issued = append(issued, target)
			n := len(issued)
			mu.Unlock()
			if n == 400 {
				cancel()
			}
		},
		Do: func(ctx context.Context, seq uint64, target string) {
			n := inflight.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			// The ankah target is much slower and jittery, so
			// completions interleave out of issue order.
			d := time.Duration(rand.Intn(200)) * time.Microsecond
			if target == "ankah" {
				d = time.Duration(1+rand.Intn(3)) * time.Millisecond
			}
			time.Sleep(d)
			inflight.Add(-1)
			mu.Lock()
			completed = append(completed, seq)
			mu.Unlock()
		},
	}
	s.Run(ctx)
	mu.Lock()
	defer mu.Unlock()
	if len(issued) < 400 {
		t.Fatalf("issued %d", len(issued))
	}
	for i, target := range issued {
		want := s.Targets[i%2]
		if target != want {
			t.Fatalf("issue %d went to %s, want %s", i, target, want)
		}
	}
	if peak.Load() > 8 {
		t.Fatalf("concurrency peaked at %d", peak.Load())
	}
	if peak.Load() < 2 {
		t.Fatalf("requests never overlapped (peak %d)", peak.Load())
	}
	outOfOrder := false
	for i := 1; i < len(completed); i++ {
		if completed[i] < completed[i-1] {
			outOfOrder = true
			break
		}
	}
	if !outOfOrder {
		t.Fatal("completions stayed in issue order; the test did not exercise concurrency")
	}
	if len(completed) != len(issued) {
		t.Fatalf("Run returned with %d of %d requests still running", len(issued)-len(completed), len(issued))
	}
}

func TestRateLimit(t *testing.T) {
	var n atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	s := &Scheduler[int]{
		Targets:     []int{0, 1},
		Rate:        40,
		Concurrency: 4,
		Do:          func(context.Context, uint64, int) { n.Add(1) },
	}
	s.Run(ctx)
	if got := n.Load(); got < 10 || got > 25 {
		t.Fatalf("%d requests in 0.5s at 40/s", got)
	}
}
