package main

import (
	"strconv"
	"testing"
)

func TestSeqRingKeepsIssueOrder(t *testing.T) {
	r := newSeqRing(4)
	for seq := uint64(0); seq < 3; seq++ {
		r.record(seq, "t"+strconv.FormatUint(seq, 10))
	}
	entries, total := r.snapshot()
	if total != 3 || len(entries) != 3 {
		t.Fatalf("total=%d len=%d, want 3/3", total, len(entries))
	}
	for i, e := range entries {
		if e.Seq != uint64(i) {
			t.Fatalf("entry %d has seq %d", i, e.Seq)
		}
	}
}

func TestSeqRingWrapsOldestFirst(t *testing.T) {
	r := newSeqRing(4)
	for seq := uint64(0); seq < 10; seq++ {
		r.record(seq, "x")
	}
	entries, total := r.snapshot()
	if total != 10 {
		t.Fatalf("total = %d, want 10", total)
	}
	if len(entries) != 4 {
		t.Fatalf("kept %d entries, want 4", len(entries))
	}
	// The last four issued were seq 6,7,8,9, oldest first.
	for i, e := range entries {
		if want := uint64(6 + i); e.Seq != want {
			t.Fatalf("entry %d has seq %d, want %d", i, e.Seq, want)
		}
	}
}

func TestSplitURLs(t *testing.T) {
	got, err := splitURLs(" http://a.test/ , http://b.test ")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "http://a.test/" || got[1] != "http://b.test" {
		t.Fatalf("splitURLs = %v", got)
	}
	for _, bad := range []string{"", " , ", "notaurl", "://nohost"} {
		if _, err := splitURLs(bad); err == nil {
			t.Fatalf("splitURLs(%q) accepted an invalid list", bad)
		}
	}
}
