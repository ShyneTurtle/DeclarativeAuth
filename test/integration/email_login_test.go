//go:build integration

package integration

import (
	"context"
	"testing"

	"declarativeauth/internal/auth"
	"declarativeauth/internal/config"
)

func TestAuthenticate_EmailLogin(t *testing.T) {
	pool := setupPool(t)
	holder := &config.SnapshotHolder{}
	snap, err := config.LoadIdentity(fixturePath("valid"))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	holder.Set(snap)

	authenticator := buildAuthenticator(pool, holder, defaultLockoutParams())
	encoded, _ := authenticator.Hasher.Hash("Secret123!")
	if err := authenticator.Credentials.Upsert(context.Background(), "jsmith", encoded, auth.NTHash("Secret123!")); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	ctx := context.Background()
	result, err := authenticator.Authenticate(ctx, "jsmith@example.com", "Secret123!", "203.0.113.10")
	if err != nil {
		t.Fatalf("expected email login to succeed, got %v", err)
	}
	if result.Username != "jsmith" {
		t.Fatalf("expected canonical username %q, got %q", "jsmith", result.Username)
	}

	if _, err := authenticator.Authenticate(ctx, "jsmith@example.com", "wrong", "203.0.113.10"); err == nil {
		t.Fatal("expected failure for wrong password via email login")
	}

	if _, err := authenticator.Authenticate(ctx, "no-such-address@example.com", "whatever", "203.0.113.10"); err == nil {
		t.Fatal("expected failure for unknown email")
	}
}

func TestAuthenticate_UsernameAndEmailShareLockoutBudget(t *testing.T) {
	pool := setupPool(t)
	holder := &config.SnapshotHolder{}
	snap, err := config.LoadIdentity(fixturePath("valid"))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	holder.Set(snap)

	params := defaultLockoutParams() // threshold=3
	authenticator := buildAuthenticator(pool, holder, params)
	encoded, _ := authenticator.Hasher.Hash("Secret123!")
	if err := authenticator.Credentials.Upsert(context.Background(), "jsmith", encoded, auth.NTHash("Secret123!")); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	ctx := context.Background()
	// Alternate identifiers across failed attempts -- if lockout state were
	// keyed on the raw identifier instead of the resolved username, this
	// would take 2x the threshold to trip. threshold+1 failures are needed
	// to trip the lockout (see TestLockout_LocksAfterThresholdAndClearsOnSuccess).
	identifiers := []string{"jsmith", "jsmith@example.com", "jsmith", "jsmith@example.com"}
	for _, id := range identifiers {
		if _, err := authenticator.Authenticate(ctx, id, "wrong", "203.0.113.11"); err == nil {
			t.Fatalf("expected failure for wrong password via %q", id)
		}
	}

	if _, err := authenticator.Authenticate(ctx, "jsmith@example.com", "Secret123!", "203.0.113.11"); err == nil {
		t.Fatal("expected lockout to reject even a correct password after threshold failures across identifiers")
	}
}
