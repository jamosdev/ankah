package targets

import "testing"

func TestParseOrderAndTrim(t *testing.T) {
	got, err := Parse(" anubis=http://anubis.test/ , ankah=http://ankah.test ")
	if err != nil {
		t.Fatal(err)
	}
	want := []Target{
		{Name: "anubis", BaseURL: "http://anubis.test"},
		{Name: "ankah", BaseURL: "http://ankah.test"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d targets, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("target %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, spec := range []string{
		"",
		"   ",
		"noequals",
		"name=",
		"=http://x",
		"a=http://x,a=http://y",
		"a=://nohost",
		"a=notaurl",
	} {
		if _, err := Parse(spec); err == nil {
			t.Fatalf("Parse(%q) accepted an invalid spec", spec)
		}
	}
}

func TestURL(t *testing.T) {
	tg := Target{Name: "ankah", BaseURL: "http://ankah.test"}
	if got := tg.URL("/pi?n=1"); got != "http://ankah.test/pi?n=1" {
		t.Fatalf("URL with slash = %q", got)
	}
	if got := tg.URL("pi"); got != "http://ankah.test/pi" {
		t.Fatalf("URL without slash = %q", got)
	}
	if got := tg.URL(""); got != "http://ankah.test" {
		t.Fatalf("URL empty = %q", got)
	}
}
