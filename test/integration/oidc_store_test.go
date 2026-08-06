//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"declarativeauth/internal/store"

	"github.com/google/uuid"
)

func TestOIDCCodeStore_RedeemIsSingleUse(t *testing.T) {
	pool := setupPool(t)
	codes := &store.OIDCCodeStore{Pool: pool}
	ctx := context.Background()

	ac := store.OIDCAuthCode{
		Code: "test-code-1", ClientID: "c1", Username: "jsmith", RedirectURI: "http://cb",
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := codes.Insert(ctx, ac); err != nil {
		t.Fatalf("insert: %v", err)
	}

	got, err := codes.Redeem(ctx, "test-code-1")
	if err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	if got.Username != "jsmith" || got.ClientID != "c1" {
		t.Fatalf("unexpected redeemed code: %+v", got)
	}

	if _, err := codes.Redeem(ctx, "test-code-1"); err != store.ErrNotFound {
		t.Fatalf("expected ErrNotFound on replay, got %v", err)
	}
}

func TestOIDCCodeStore_RedeemExpiredFails(t *testing.T) {
	pool := setupPool(t)
	codes := &store.OIDCCodeStore{Pool: pool}
	ctx := context.Background()

	ac := store.OIDCAuthCode{
		Code: "expired-code", ClientID: "c1", Username: "jsmith", RedirectURI: "http://cb",
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	if err := codes.Insert(ctx, ac); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := codes.Redeem(ctx, "expired-code"); err != store.ErrNotFound {
		t.Fatalf("expected ErrNotFound for an expired code, got %v", err)
	}
}

func TestOIDCCodeStore_RedeemUnknownFails(t *testing.T) {
	pool := setupPool(t)
	codes := &store.OIDCCodeStore{Pool: pool}
	if _, err := codes.Redeem(context.Background(), "no-such-code"); err != store.ErrNotFound {
		t.Fatalf("expected ErrNotFound for an unknown code, got %v", err)
	}
}

func TestOIDCCodeStore_DeleteExpired(t *testing.T) {
	pool := setupPool(t)
	codes := &store.OIDCCodeStore{Pool: pool}
	ctx := context.Background()

	if err := codes.Insert(ctx, store.OIDCAuthCode{
		Code: "old", ClientID: "c1", Username: "jsmith", RedirectURI: "http://cb", ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("insert expired: %v", err)
	}
	if err := codes.Insert(ctx, store.OIDCAuthCode{
		Code: "fresh", ClientID: "c1", Username: "jsmith", RedirectURI: "http://cb", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("insert fresh: %v", err)
	}

	n, err := codes.DeleteExpired(ctx)
	if err != nil {
		t.Fatalf("delete expired: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 expired code deleted, got %d", n)
	}
	if _, err := codes.Redeem(ctx, "fresh"); err != nil {
		t.Fatalf("expected the fresh code to survive cleanup: %v", err)
	}
}

func TestOIDCKeyStore_RotateIfDue_BootstrapsAndOverlapsOnRotation(t *testing.T) {
	pool := setupPool(t)
	keys := &store.OIDCKeyStore{Pool: pool}
	ctx := context.Background()

	genES256 := func() (store.OIDCSigningKey, error) {
		return store.OIDCSigningKey{Kid: randomKid(t), Algorithm: "ES256", PrivateKeyPEM: "placeholder"}, nil
	}

	rotated, err := keys.RotateIfDue(ctx, time.Hour, time.Hour, genES256)
	if err != nil {
		t.Fatalf("bootstrap rotate: %v", err)
	}
	if !rotated {
		t.Fatal("expected the first call (no current key yet) to bootstrap a key")
	}

	active, err := keys.Active(ctx)
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if len(active) != 1 || !active[0].IsCurrent {
		t.Fatalf("expected exactly one current key after bootstrap, got %+v", active)
	}
	firstKid := active[0].Kid

	// Not due yet (interval far in the future): no-op.
	rotated, err = keys.RotateIfDue(ctx, time.Hour, time.Hour, genES256)
	if err != nil {
		t.Fatalf("no-op rotate: %v", err)
	}
	if rotated {
		t.Fatal("expected no rotation before the interval elapses")
	}

	// Due immediately: rotates, retiring the old key into its overlap window
	// rather than deleting it outright.
	rotated, err = keys.RotateIfDue(ctx, 0, time.Hour, genES256)
	if err != nil {
		t.Fatalf("due rotate: %v", err)
	}
	if !rotated {
		t.Fatal("expected rotation once the interval has elapsed")
	}

	active, err = keys.Active(ctx)
	if err != nil {
		t.Fatalf("active after rotation: %v", err)
	}
	if len(active) != 2 {
		t.Fatalf("expected both the retired (still-in-overlap) and new key to be active, got %+v", active)
	}
	sawOldRetired, sawNewCurrent := false, false
	for _, k := range active {
		if k.Kid == firstKid {
			sawOldRetired = !k.IsCurrent && k.RetireAt != nil
		} else if k.IsCurrent {
			sawNewCurrent = true
		}
	}
	if !sawOldRetired {
		t.Error("expected the old key to be retired (not current, with a retire_at) but still active")
	}
	if !sawNewCurrent {
		t.Error("expected a new current key")
	}
}

func randomKid(t *testing.T) string {
	t.Helper()
	return t.Name() + "-" + time.Now().Format("150405.000000000")
}

func TestSessionStore_RotateRefreshToken_Success(t *testing.T) {
	pool := setupPool(t)
	sessions := &store.SessionStore{Pool: pool}
	ctx := context.Background()

	id := uuid.New()
	if err := sessions.Create(ctx, store.Session{
		ID: id, Username: "jsmith", ClientID: "c1", Scope: "openid",
		RefreshTokenHash: "hash-v1", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	sess, err := sessions.RotateRefreshToken(ctx, id, "hash-v1", "hash-v2", time.Now().Add(2*time.Hour))
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if sess.Username != "jsmith" || sess.ClientID != "c1" || sess.Scope != "openid" {
		t.Fatalf("unexpected session: %+v", sess)
	}

	// The old hash must no longer work; the new one must.
	if _, err := sessions.RotateRefreshToken(ctx, id, "hash-v1", "hash-v3", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("expected the old (rotated-away) hash to be rejected")
	}
	fresh, err := sessions.GetByID(ctx, id)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if fresh.RefreshTokenHash != "hash-v2" {
		t.Fatalf("expected the hash to still be hash-v2 after a rejected rotation, got %q", fresh.RefreshTokenHash)
	}
}

func TestSessionStore_RotateRefreshToken_ReuseRevokesSession(t *testing.T) {
	pool := setupPool(t)
	sessions := &store.SessionStore{Pool: pool}
	ctx := context.Background()

	id := uuid.New()
	if err := sessions.Create(ctx, store.Session{
		ID: id, Username: "jsmith", ClientID: "c1",
		RefreshTokenHash: "hash-v1", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Legitimate rotation.
	if _, err := sessions.RotateRefreshToken(ctx, id, "hash-v1", "hash-v2", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// Replaying the now-stale first-generation hash must be detected as
	// reuse and revoke the session outright.
	if _, err := sessions.RotateRefreshToken(ctx, id, "hash-v1", "hash-vX", time.Now().Add(time.Hour)); err != store.ErrRefreshTokenReused {
		t.Fatalf("expected ErrRefreshTokenReused, got %v", err)
	}

	// The session is now revoked, so even the *current* (second-generation)
	// hash must be rejected too.
	if _, err := sessions.RotateRefreshToken(ctx, id, "hash-v2", "hash-v3", time.Now().Add(time.Hour)); err != store.ErrNotFound {
		t.Fatalf("expected the revoked session to reject even its current hash, got %v", err)
	}
}

func TestSessionStore_RotateRefreshToken_UnknownSession(t *testing.T) {
	pool := setupPool(t)
	sessions := &store.SessionStore{Pool: pool}
	if _, err := sessions.RotateRefreshToken(context.Background(), uuid.New(), "a", "b", time.Now().Add(time.Hour)); err != store.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSessionStore_RotateRefreshToken_ExpiredSession(t *testing.T) {
	pool := setupPool(t)
	sessions := &store.SessionStore{Pool: pool}
	ctx := context.Background()

	id := uuid.New()
	if err := sessions.Create(ctx, store.Session{
		ID: id, Username: "jsmith", ClientID: "c1",
		RefreshTokenHash: "hash-v1", ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := sessions.RotateRefreshToken(ctx, id, "hash-v1", "hash-v2", time.Now().Add(time.Hour)); err != store.ErrNotFound {
		t.Fatalf("expected ErrNotFound for an expired session, got %v", err)
	}
}
