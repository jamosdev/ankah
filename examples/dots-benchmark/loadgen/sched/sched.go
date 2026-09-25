// Package sched issues requests to a fixed list of targets in strict
// round-robin order with bounded concurrency and an optional rate limit.
//
// Issuance order is decided by a single goroutine, so request n always goes
// to Targets[n % len(Targets)] no matter how requests complete. When every
// worker slot is busy the issuer waits; it never skips a target, so a slow
// target slows both targets equally instead of shifting load.
package sched

import (
	"context"
	"time"
)

type Scheduler[T any] struct {
	Targets     []T
	Rate        float64 // issues per second; 0 means as fast as slots allow
	Concurrency int
	// Issued is called on the issuing goroutine, in order, before Do starts.
	Issued func(seq uint64, target T)
	// Do runs on its own goroutine.
	Do func(ctx context.Context, seq uint64, target T)
}

// Run issues requests until ctx is done, then waits for in-flight work.
func (s *Scheduler[T]) Run(ctx context.Context) {
	conc := s.Concurrency
	if conc < 1 {
		conc = 1
	}
	slots := make(chan struct{}, conc)
	var tick <-chan time.Time
	if s.Rate > 0 {
		ticker := time.NewTicker(time.Duration(float64(time.Second) / s.Rate))
		defer ticker.Stop()
		tick = ticker.C
	}
	defer func() {
		for i := 0; i < conc; i++ {
			slots <- struct{}{}
		}
	}()
	for seq := uint64(0); ; seq++ {
		if tick != nil {
			select {
			case <-ctx.Done():
				return
			case <-tick:
			}
		}
		select {
		case <-ctx.Done():
			return
		case slots <- struct{}{}:
		}
		target := s.Targets[seq%uint64(len(s.Targets))]
		if s.Issued != nil {
			s.Issued(seq, target)
		}
		go func(seq uint64, target T) {
			defer func() { <-slots }()
			s.Do(ctx, seq, target)
		}(seq, target)
	}
}
