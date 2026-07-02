package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ResetToken is a password-reset (or first-password-setup) token; only its
// hash is ever persisted, the raw token is emailed once and never stored.
type ResetToken struct {
	TokenHash string
	Username  string
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// ResetTokenStore provides CRUD access to password_reset_tokens.
type ResetTokenStore struct {
	Pool *pgxpool.Pool
}

// Create inserts a new reset token hash for username with the given TTL.
func (s *ResetTokenStore) Create(ctx context.Context, tokenHash, username string, ttl time.Duration) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO password_reset_tokens (token_hash, username, expires_at)
		VALUES ($1, $2, now() + $3::interval)`,
		tokenHash, username, ttl.String())
	return err
}

// Peek reports whether tokenHash exists, is unexpired and unused, without
// consuming it. Used only to decide whether to render the "set a new
// password" form on GET; the authoritative, race-free check happens in
// Consume on the actual POST.
func (s *ResetTokenStore) Peek(ctx context.Context, tokenHash string) bool {
	var expiresAt time.Time
	var usedAt *time.Time
	err := s.Pool.QueryRow(ctx,
		`SELECT expires_at, used_at FROM password_reset_tokens WHERE token_hash = $1`,
		tokenHash).Scan(&expiresAt, &usedAt)
	if err != nil {
		return false
	}
	return usedAt == nil && time.Now().Before(expiresAt)
}

// ConsumeResult is returned by Consume.
type ConsumeResult struct {
	Username string
}

// Consume validates and marks a token used, inside a transaction to prevent
// double-use races. Returns ErrNotFound for missing/expired/already-used
// tokens (deliberately not distinguished, to avoid leaking state).
func (s *ResetTokenStore) Consume(ctx context.Context, tokenHash string) (*ConsumeResult, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var username string
	var expiresAt time.Time
	var usedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT username, expires_at, used_at FROM password_reset_tokens
		WHERE token_hash = $1 FOR UPDATE`, tokenHash).Scan(&username, &expiresAt, &usedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if usedAt != nil || time.Now().After(expiresAt) {
		return nil, ErrNotFound
	}

	if _, err := tx.Exec(ctx,
		`UPDATE password_reset_tokens SET used_at = now() WHERE token_hash = $1`, tokenHash); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &ConsumeResult{Username: username}, nil
}
