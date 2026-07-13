//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"declarativeauth/internal/auth"
	"declarativeauth/internal/config"
	"declarativeauth/internal/store"
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

// TestLockout_DimensionsAreIndependentlyConfigurable proves the account and
// IP dimensions genuinely don't affect each other: each has its own
// LockoutParams, and each can be disabled (Threshold <= 0) without touching
// the other. Operators can run either, both, or neither.
func TestLockout_DimensionsAreIndependentlyConfigurable(t *testing.T) {
	pool := setupPool(t)
	holder := &config.SnapshotHolder{}
	snap, err := config.LoadIdentity(fixturePath("valid"))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	holder.Set(snap)

	quickParams := store.LockoutParams{Threshold: 3, BackoffBase: 200 * time.Millisecond, BackoffMax: 2 * time.Second, Window: time.Hour}
	disabledParams := store.LockoutParams{Threshold: 0}

	newAuthenticator := func(userParams, ipParams store.LockoutParams) *auth.Authenticator {
		a := &auth.Authenticator{
			Snapshot:    holder.Get,
			Credentials: &store.CredentialStore{Pool: pool},
			Hasher:      &auth.Hasher{Params: auth.DefaultArgon2Params},
			RateLimiter: &auth.RateLimiter{
				Lockouts: &store.LockoutStore{Pool: pool},
				Params:   userParams,
				IPParams: ipParams,
			},
		}
		encoded, _ := a.Hasher.Hash("Secret123!")
		if err := a.Credentials.Upsert(context.Background(), "jsmith", encoded); err != nil {
			t.Fatalf("seed credential: %v", err)
		}
		return a
	}
	ctx := context.Background()

	t.Run("account dimension only: IP spray never locks, one account still does", func(t *testing.T) {
		a := newAuthenticator(quickParams, disabledParams)
		attackerIP := "203.0.113.101"

		// Many distinct unknown usernames from one IP, well past what the
		// account threshold would allow for any single one of them -- the
		// IP dimension is disabled, so this must never lock that IP.
		for i := 0; i < 10; i++ {
			_, _ = a.Authenticate(ctx, fmt.Sprintf("no-such-user-%d", i), "guess", attackerIP)
		}
		if _, err := a.Authenticate(ctx, "jsmith", "Secret123!", attackerIP); err != nil {
			t.Fatalf("expected the disabled IP dimension to never lock this IP, got %v", err)
		}

		// But hammering the *same* account past its own threshold must
		// still lock -- the account dimension is independently enabled.
		for i := 0; i <= quickParams.Threshold; i++ {
			_, _ = a.Authenticate(ctx, "jsmith", "wrong", "203.0.113.102")
		}
		if _, err := a.Authenticate(ctx, "jsmith", "Secret123!", "203.0.113.102"); err == nil {
			t.Fatal("expected the account dimension to still lock jsmith after repeated failures")
		}
	})

	t.Run("IP dimension only: account never locks, shared IP still does", func(t *testing.T) {
		a := newAuthenticator(disabledParams, quickParams)
		sharedIP := "203.0.113.201"

		// Hammer jsmith's own account well past what the account threshold
		// would allow -- disabled, so it must never lock jsmith out.
		for i := 0; i <= quickParams.Threshold+5; i++ {
			_, _ = a.Authenticate(ctx, "jsmith", "wrong", fmt.Sprintf("198.51.100.%d", i+1))
		}
		if _, err := a.Authenticate(ctx, "jsmith", "Secret123!", "198.51.100.250"); err != nil {
			t.Fatalf("expected the disabled account dimension to never lock jsmith, got %v", err)
		}

		// But spraying many distinct usernames from one shared IP must
		// still lock that IP once its own threshold is exceeded.
		for i := 0; i <= quickParams.Threshold; i++ {
			_, _ = a.Authenticate(ctx, fmt.Sprintf("no-such-user-%d", i), "guess", sharedIP)
		}
		if _, err := a.Authenticate(ctx, "jsmith", "Secret123!", sharedIP); err == nil {
			t.Fatal("expected the IP dimension to lock out this shared IP after repeated failures")
		}
	})

	t.Run("both disabled: nothing ever locks", func(t *testing.T) {
		a := newAuthenticator(disabledParams, disabledParams)
		ip := "203.0.113.250"
		for i := 0; i < 20; i++ {
			_, _ = a.Authenticate(ctx, "jsmith", "wrong", ip)
		}
		if _, err := a.Authenticate(ctx, "jsmith", "Secret123!", ip); err != nil {
			t.Fatalf("expected no lockout at all with both dimensions disabled, got %v", err)
		}
	})
}
