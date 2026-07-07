//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"declarativeauth/internal/config"
)

func TestLockout_LocksAfterThresholdAndClearsOnSuccess(t *testing.T) {
	pool := setupPool(t)
	holder := &config.SnapshotHolder{}
	snap, err := config.LoadIdentity(fixturePath("valid"))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	holder.Set(snap)

	params := defaultLockoutParams() // threshold=3, backoffBase=200ms
	authenticator := buildAuthenticator(pool, holder, params)

	encoded, _ := authenticator.Hasher.Hash("Secret123!")
	if err := authenticator.Credentials.Upsert(context.Background(), "jsmith", encoded); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	ctx := context.Background()
	for i := 0; i < params.Threshold; i++ {
		if _, err := authenticator.Authenticate(ctx, "jsmith", "wrong", "203.0.113.9"); err == nil {
			t.Fatal("expected failure for wrong password")
		}
	}

	// One more failure past the threshold should now trip the lockout.
	if _, err := authenticator.Authenticate(ctx, "jsmith", "wrong", "203.0.113.9"); err == nil {
		t.Fatal("expected failure")
	}

	// Even the correct password must now be rejected while locked out.
	if _, err := authenticator.Authenticate(ctx, "jsmith", "Secret123!", "203.0.113.9"); err == nil {
		t.Fatal("expected lockout to reject even a correct password")
	}

	time.Sleep(params.BackoffMax + 100*time.Millisecond)

	if _, err := authenticator.Authenticate(ctx, "jsmith", "Secret123!", "203.0.113.9"); err != nil {
		t.Fatalf("expected success after backoff expired, got %v", err)
	}

	// A successful auth clears the counter; the next wrong attempt should be
	// treated as failure #1, not a continuation of the prior lockout.
	if _, err := authenticator.Authenticate(ctx, "jsmith", "wrong", "203.0.113.9"); err == nil {
		t.Fatal("expected failure for wrong password")
	}
	if _, err := authenticator.Authenticate(ctx, "jsmith", "Secret123!", "203.0.113.9"); err != nil {
		t.Fatalf("expected success (counter should have reset after prior success), got %v", err)
	}
}
