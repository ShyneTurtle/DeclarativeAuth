package store

import (
	"testing"
	"time"
)

func TestComputeBackoff_BelowThreshold(t *testing.T) {
	p := LockoutParams{Threshold: 5, BackoffBase: time.Second, BackoffMax: 15 * time.Minute}
	if _, locked := ComputeBackoff(5, p); locked {
		t.Fatal("expected no lockout at exactly the threshold")
	}
}

func TestComputeBackoff_DoublingAboveThreshold(t *testing.T) {
	p := LockoutParams{Threshold: 5, BackoffBase: time.Second, BackoffMax: 15 * time.Minute}
	d1, locked1 := ComputeBackoff(6, p)
	d2, locked2 := ComputeBackoff(7, p)
	d3, locked3 := ComputeBackoff(8, p)
	if !locked1 || !locked2 || !locked3 {
		t.Fatal("expected lockout above threshold")
	}
	if d1 != time.Second {
		t.Fatalf("expected 1s backoff at count=6, got %v", d1)
	}
	if d2 != 2*time.Second {
		t.Fatalf("expected 2s backoff at count=7, got %v", d2)
	}
	if d3 != 4*time.Second {
		t.Fatalf("expected 4s backoff at count=8, got %v", d3)
	}
}

func TestComputeBackoff_CappedAtMax(t *testing.T) {
	p := LockoutParams{Threshold: 5, BackoffBase: time.Second, BackoffMax: 10 * time.Second}
	d, locked := ComputeBackoff(30, p)
	if !locked {
		t.Fatal("expected lockout")
	}
	if d != p.BackoffMax {
		t.Fatalf("expected backoff capped at %v, got %v", p.BackoffMax, d)
	}
}
