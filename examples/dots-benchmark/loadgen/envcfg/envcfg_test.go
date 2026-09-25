package envcfg

import (
	"testing"
	"time"
)

func TestString(t *testing.T) {
	t.Setenv("X_STR", "value")
	if got := String("X_STR", "def"); got != "value" {
		t.Fatalf("String set = %q", got)
	}
	t.Setenv("X_STR", "")
	if got := String("X_STR", "def"); got != "def" {
		t.Fatalf("String empty = %q, want default", got)
	}
	if got := String("X_MISSING", "def"); got != "def" {
		t.Fatalf("String unset = %q, want default", got)
	}
}

func TestInt(t *testing.T) {
	if got, err := Int("X_MISSING", 7); err != nil || got != 7 {
		t.Fatalf("Int unset = %d, %v", got, err)
	}
	t.Setenv("X_INT", "42")
	if got, err := Int("X_INT", 7); err != nil || got != 42 {
		t.Fatalf("Int set = %d, %v", got, err)
	}
	t.Setenv("X_INT", "not-a-number")
	if _, err := Int("X_INT", 7); err == nil {
		t.Fatal("Int accepted a non-number")
	}
}

func TestFloat(t *testing.T) {
	if got, err := Float("X_MISSING", 1.5); err != nil || got != 1.5 {
		t.Fatalf("Float unset = %v, %v", got, err)
	}
	t.Setenv("X_FLOAT", "40")
	if got, err := Float("X_FLOAT", 1.5); err != nil || got != 40 {
		t.Fatalf("Float set = %v, %v", got, err)
	}
	t.Setenv("X_FLOAT", "fast")
	if _, err := Float("X_FLOAT", 1.5); err == nil {
		t.Fatal("Float accepted a non-number")
	}
}

func TestDuration(t *testing.T) {
	if got, err := Duration("X_MISSING", 3*time.Second); err != nil || got != 3*time.Second {
		t.Fatalf("Duration unset = %v, %v", got, err)
	}
	t.Setenv("X_DUR", "250ms")
	if got, err := Duration("X_DUR", time.Second); err != nil || got != 250*time.Millisecond {
		t.Fatalf("Duration set = %v, %v", got, err)
	}
	t.Setenv("X_DUR", "soon")
	if _, err := Duration("X_DUR", time.Second); err == nil {
		t.Fatal("Duration accepted an invalid value")
	}
}
