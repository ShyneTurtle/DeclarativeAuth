package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OIDCAuthCode is a short-lived authorization code minted at /authorize and
// redeemed exactly once at /token.
type OIDCAuthCode struct {
	Code                string
	ClientID            string
	Username            string
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

// OIDCCodeStore provides CRUD access to oidc_authorization_codes. DB-backed
// (rather than the in-memory map an earlier version used) so a code minted
// by one replica can be redeemed by another behind a load balancer.
type OIDCCodeStore struct {
	Pool *pgxpool.Pool
}

// Insert stores a new authorization code.
func (s *OIDCCodeStore) Insert(ctx context.Context, ac OIDCAuthCode) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO oidc_authorization_codes
			(code, client_id, username, redirect_uri, scope, nonce, code_challenge, code_challenge_method, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		ac.Code, ac.ClientID, ac.Username, ac.RedirectURI, ac.Scope, ac.Nonce, ac.CodeChallenge, ac.CodeChallengeMethod, ac.ExpiresAt)
	return err
}

// Redeem validates and consumes a code (single-use, unexpired), inside a
// transaction with row locking to prevent double-redemption races across
// replicas. Returns ErrNotFound for a missing/expired/already-used code,
// deliberately not distinguished, to avoid leaking state.
func (s *OIDCCodeStore) Redeem(ctx context.Context, code string) (*OIDCAuthCode, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var ac OIDCAuthCode
	var usedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT client_id, username, redirect_uri, scope, nonce, code_challenge, code_challenge_method, expires_at, used_at
		FROM oidc_authorization_codes WHERE code = $1 FOR UPDATE`, code).Scan(
		&ac.ClientID, &ac.Username, &ac.RedirectURI, &ac.Scope, &ac.Nonce, &ac.CodeChallenge, &ac.CodeChallengeMethod, &ac.ExpiresAt, &usedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if usedAt != nil || time.Now().After(ac.ExpiresAt) {
		return nil, ErrNotFound
	}

	if _, err := tx.Exec(ctx, `UPDATE oidc_authorization_codes SET used_at = now() WHERE code = $1`, code); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	ac.Code = code
	return &ac, nil
}

// DeleteExpired removes authorization codes past their expiry, called
// periodically so the table doesn't grow unbounded.
func (s *OIDCCodeStore) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM oidc_authorization_codes WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
