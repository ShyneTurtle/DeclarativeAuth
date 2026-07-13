package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LockoutStore provides persisted brute-force backoff state, shared across
// LDAP bind and OIDC/web login and across replicas.
type LockoutStore struct {
	Pool *pgxpool.Pool
}

// LockoutParams are the configurable backoff parameters (Section 6b).
type LockoutParams struct {
	Threshold   int
	BackoffBase time.Duration
	BackoffMax  time.Duration
	Window      time.Duration
}

// IsLocked reports whether key is currently locked out.
func (s *LockoutStore) IsLocked(ctx context.Context, key string) (bool, error) {
	var lockedUntil *time.Time
	err := s.Pool.QueryRow(ctx,
		`SELECT locked_until FROM login_lockouts WHERE lockout_key = $1`, key).Scan(&lockedUntil)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return lockedUntil != nil && lockedUntil.After(time.Now()), nil
}

// RecordFailure increments the failure counter for key and computes a new
// locked_until using exponential backoff with a cap, resetting the counter
// first if the last failure fell outside the configured window.
func (s *LockoutStore) RecordFailure(ctx context.Context, key string, p LockoutParams) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var count int
	var lastFailure time.Time
	err = tx.QueryRow(ctx,
		`SELECT failure_count, last_failure_at FROM login_lockouts WHERE lockout_key = $1 FOR UPDATE`,
		key).Scan(&count, &lastFailure)
	now := time.Now()
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		count = 0
	} else if now.Sub(lastFailure) > p.Window {
		count = 0
	}
	count++

	var lockedUntil *time.Time
	if backoff, locked := ComputeBackoff(count, p); locked {
		lu := now.Add(backoff)
		lockedUntil = &lu
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO login_lockouts (lockout_key, failure_count, first_failure_at, last_failure_at, locked_until)
		VALUES ($1, $2, $3, $3, $4)
		ON CONFLICT (lockout_key) DO UPDATE
		SET failure_count = $2, last_failure_at = $3, locked_until = $4`,
		key, count, now, lockedUntil)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Reset clears the lockout counter for key, called on successful auth.
func (s *LockoutStore) Reset(ctx context.Context, key string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM login_lockouts WHERE lockout_key = $1`, key)
	return err
}

// ComputeBackoff is the pure exponential-backoff-with-cap function: given the
// current failure count and configured params, returns the lockout duration
// and whether a lockout should be applied at all. Exported and dependency-free
// so it can be unit-tested without Postgres.
//
// Threshold <= 0 means the lockout is disabled outright (never locks,
// regardless of count) -- not "lock on the very first failure", which is
// what a naive count <= p.Threshold check would do at Threshold == 0. This
// is the config-disabled default; see DECLARATIVEAUTH_RATE_LIMIT_THRESHOLD.
func ComputeBackoff(count int, p LockoutParams) (time.Duration, bool) {
	if p.Threshold <= 0 {
		return 0, false
	}
	if count <= p.Threshold {
		return 0, false
	}
	backoff := p.BackoffBase * time.Duration(1<<uint(count-p.Threshold-1))
	if backoff > p.BackoffMax || backoff <= 0 {
		backoff = p.BackoffMax
	}
	return backoff, true
}
