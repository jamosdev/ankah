package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dotsdemo/loadgen/targets"
)

// The gate uses difficulty 8 (one zero byte) so the solve is instant.
const testChallenge = "0123456789abcdef0123456789abcdef.1700000000.8.ab"

func answerSolves(challenge string, answer uint64) bool {
	nonce := challenge[:32]
	sum := sha256.Sum256([]byte(nonce + ":" + strconv.FormatUint(answer, 10)))
	return sum[0] == 0
}

// fakeAnkah models the parts of Ankah's browser flow the probe touches: a
// 428 gate that sets the ankah_sid session cookie and names that session,
// and /ankah/answer/<session> which checks the answer and marks the session
// solved. It counts gates and answers so the test can prove the solved
// session is reused rather than re-solved.
func fakeAnkah(t *testing.T) (*httptest.Server, *atomic.Int64, *atomic.Int64) {
	const session = "00112233445566778899aabbccddeeff"
	var gates, opens atomic.Int64
	var solved atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/pi", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("ankah_sid"); err == nil && c.Value == session && solved.Load() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"pi":3.14}`))
			return
		}
		gates.Add(1)
		http.SetCookie(w, &http.Cookie{Name: "ankah_sid", Value: session, Path: "/"})
		w.WriteHeader(http.StatusPreconditionRequired)
		fmt.Fprintf(w, "<body data-challenge='%s' data-session='%s'>", testChallenge, session)
	})
	mux.HandleFunc("/ankah/answer/", func(w http.ResponseWriter, r *http.Request) {
		opens.Add(1)
		answer, _ := strconv.ParseUint(r.URL.Query().Get("answer"), 10, 64)
		c, err := r.Cookie("ankah_sid")
		if r.Method != http.MethodPost || r.URL.Path != "/ankah/answer/"+session ||
			err != nil || c.Value != session || !answerSolves(testChallenge, answer) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		solved.Store(true)
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &gates, &opens
}

func TestAttemptSolvesThenReusesPass(t *testing.T) {
	srv, gates, opens := fakeAnkah(t)
	prb, err := newProber(10 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	prb.requestPath = "/pi?n=1"
	tg := targets.Target{Name: "ankah", BaseURL: srv.URL}

	if err := prb.attempt(context.Background(), tg); err != nil {
		t.Fatalf("first attempt: %v", err)
	}
	if gates.Load() != 1 || opens.Load() != 1 {
		t.Fatalf("first attempt did gates=%d opens=%d, want 1/1", gates.Load(), opens.Load())
	}
	// The solved session cookie is now in the jar, so the second attempt must not need
	// another gate or solve.
	if err := prb.attempt(context.Background(), tg); err != nil {
		t.Fatalf("second attempt: %v", err)
	}
	if opens.Load() != 1 {
		t.Fatalf("second attempt solved again (opens=%d)", opens.Load())
	}
}

func TestAttemptAllowPathSucceedsWithoutSolving(t *testing.T) {
	var opens atomic.Int64
	// An Anubis-style ALLOW: the legit User-Agent is served directly.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ankah/open" || strings.HasPrefix(r.URL.Path, "/ankah/answer/") {
			opens.Add(1)
		}
		if r.Header.Get("User-Agent") != userAgent {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	prb, err := newProber(10 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	prb.requestPath = "/pi?n=1"
	if err := prb.attempt(context.Background(), targets.Target{Name: "anubis", BaseURL: srv.URL}); err != nil {
		t.Fatalf("allow-path attempt: %v", err)
	}
	if opens.Load() != 0 {
		t.Fatal("allow path tried to solve a challenge")
	}
}
