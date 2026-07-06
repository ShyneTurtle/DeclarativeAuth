//go:build integration

package integration

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"declarativeauth/internal/auth"
	"declarativeauth/internal/config"
	"declarativeauth/internal/store"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set, skipping integration test")
	}
	return dsn
}

func setupPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testDSN(t)
	if err := store.Migrate(dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := store.Open(context.Background(), dsn, 5)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)

	// Ensure a clean slate for tables this package writes to, so tests are
	// independent of prior runs / other test files.
	ctx := context.Background()
	for _, table := range []string{"credentials", "login_lockouts", "login_audit", "sessions", "password_reset_tokens", "webauthn_credentials", "webauthn_ceremonies"} {
		if _, err := pool.Exec(ctx, "DELETE FROM "+table); err != nil {
			t.Fatalf("cleaning %s: %v", table, err)
		}
	}
	return pool
}

func buildAuthenticator(pool *pgxpool.Pool, holder *config.SnapshotHolder, pepper string, params store.LockoutParams) *auth.Authenticator {
	return &auth.Authenticator{
		Snapshot:    holder.Get,
		Credentials: &store.CredentialStore{Pool: pool},
		Hasher:      &auth.Hasher{Pepper: []byte(pepper), Params: auth.DefaultArgon2Params},
		RateLimiter: &auth.RateLimiter{
			Lockouts: &store.LockoutStore{Pool: pool},
			Params:   params,
		},
	}
}

func defaultLockoutParams() store.LockoutParams {
	return store.LockoutParams{
		Threshold:   3,
		BackoffBase: 200 * time.Millisecond,
		BackoffMax:  2 * time.Second,
		Window:      time.Hour,
	}
}

func poolFor(t *testing.T, dsn string) (*pgxpool.Pool, error) {
	t.Helper()
	return store.Open(context.Background(), dsn, 5)
}

func seedPassword(t *testing.T, pool *pgxpool.Pool, username, password, pepper string) {
	t.Helper()
	hasher := &auth.Hasher{Pepper: []byte(pepper), Params: auth.DefaultArgon2Params}
	encoded, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	creds := &store.CredentialStore{Pool: pool}
	if err := creds.Upsert(context.Background(), username, encoded); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}
