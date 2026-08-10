//go:build integration

package integration

import (
	"context"
	"testing"

	"declarativeauth/internal/auth"
	"declarativeauth/internal/config"
	"declarativeauth/internal/store"
)

// TestAuthenticate_BackfillsMissingNTHashOnSuccessfulLogin covers the lazy
// backfill in auth.Authenticator.Authenticate: a credential row that
// predates the NT hash column (or was created before Samba integration was
// configured) gets nt_hash/samba_rid filled in on its next successful
// login, without requiring a password reset.
func TestAuthenticate_BackfillsMissingNTHashOnSuccessfulLogin(t *testing.T) {
	pool := setupPool(t)
	holder := &config.SnapshotHolder{}
	snap, err := config.LoadIdentity(fixturePath("valid"))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	holder.Set(snap)

	authenticator := buildAuthenticator(pool, holder, defaultLockoutParams())
	encoded, err := authenticator.Hasher.Hash("Secret123!")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	// Simulate a pre-existing row from before nt_hash existed: written
	// directly, bypassing CredentialStore.Upsert (which always computes it).
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		INSERT INTO credentials (username, password_hash, password_set_at, must_reset, updated_at)
		VALUES ($1, $2, now(), false, now())`,
		"jsmith", encoded); err != nil {
		t.Fatalf("seed legacy credential: %v", err)
	}

	creds := &store.CredentialStore{Pool: pool}
	before, err := creds.Get(ctx, "jsmith")
	if err != nil {
		t.Fatalf("get before login: %v", err)
	}
	if before.NTHash != "" || before.SambaRID != 0 {
		t.Fatalf("expected no NT hash/RID before any login, got %+v", before)
	}

	if _, err := authenticator.Authenticate(ctx, "jsmith", "Secret123!", "203.0.113.20"); err != nil {
		t.Fatalf("expected login to succeed, got %v", err)
	}

	after, err := creds.Get(ctx, "jsmith")
	if err != nil {
		t.Fatalf("get after login: %v", err)
	}
	if after.NTHash != auth.NTHash("Secret123!") {
		t.Fatalf("expected NT hash to be backfilled after a successful login, got %q", after.NTHash)
	}
	if after.SambaRID == 0 {
		t.Fatal("expected a RID to be assigned alongside the backfilled NT hash")
	}

	// A wrong password must never trigger a write (nothing plaintext to
	// derive from, and the row is invisible to Samba until logged in with
	// the right password anyway).
	rid := after.SambaRID
	if _, err := authenticator.Authenticate(ctx, "jsmith", "Secret123!", "203.0.113.20"); err != nil {
		t.Fatalf("expected second login to succeed, got %v", err)
	}
	again, err := creds.Get(ctx, "jsmith")
	if err != nil {
		t.Fatalf("get after second login: %v", err)
	}
	if again.SambaRID != rid {
		t.Fatalf("expected the RID to stay stable across logins, got %d then %d", rid, again.SambaRID)
	}
}

// TestCredentialStore_Upsert_KeepsRIDStableAcrossPasswordChanges guards
// against a regression where a password change on an existing user could
// silently strand samba_rid at NULL forever (only the very first Upsert
// call for a username assigned one; a subsequent password change on the ON
// CONFLICT path needs to preserve it, not just leave it untouched from a
// state where it was never set to begin with).
func TestCredentialStore_Upsert_KeepsRIDStableAcrossPasswordChanges(t *testing.T) {
	pool := setupPool(t)
	creds := &store.CredentialStore{Pool: pool}
	ctx := context.Background()

	if err := creds.Upsert(ctx, "jsmith", "hash-v1", auth.NTHash("v1")); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	first, err := creds.Get(ctx, "jsmith")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if first.SambaRID == 0 {
		t.Fatal("expected a RID to be assigned on first upsert")
	}
	if first.NTHash != auth.NTHash("v1") {
		t.Fatalf("unexpected NT hash: %q", first.NTHash)
	}

	if err := creds.Upsert(ctx, "jsmith", "hash-v2", auth.NTHash("v2")); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	second, err := creds.Get(ctx, "jsmith")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if second.SambaRID != first.SambaRID {
		t.Fatalf("expected RID to stay stable across a password change, got %d then %d", first.SambaRID, second.SambaRID)
	}
	if second.NTHash != auth.NTHash("v2") {
		t.Fatalf("expected NT hash to be updated to the new password's, got %q", second.NTHash)
	}

	all, err := creds.AllSambaCredentials(ctx)
	if err != nil {
		t.Fatalf("AllSambaCredentials: %v", err)
	}
	got, ok := all["jsmith"]
	if !ok {
		t.Fatal("expected jsmith in AllSambaCredentials")
	}
	if got.RID != second.SambaRID || got.NTHash != second.NTHash {
		t.Fatalf("AllSambaCredentials returned %+v, want RID=%d NTHash=%q", got, second.SambaRID, second.NTHash)
	}
}
