package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RevokedTokenStore denylists individual JWT access/ID tokens by their jti
// claim, ahead of their natural expiry. Self-contained JWTs otherwise have
// no server-side revocation point -- this table is that point, checked at
// /userinfo (see Provider.handleUserinfo) and by /introspect.
type RevokedTokenStore struct {
	Pool *pgxpool.Pool
}

// Revoke denylists jti until expiresAt (the token's own exp claim -- no
// point keeping the row after the token would have expired naturally
// anyway). Idempotent.
func (s *RevokedTokenStore) Revoke(ctx context.Context, jti string, expiresAt time.Time) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO oidc_revoked_tokens (jti, expires_at) VALUES ($1, $2)
		ON CONFLICT (jti) DO NOTHING`, jti, expiresAt)
	return err
}

// IsRevoked reports whether jti has been revoked and hasn't naturally
// expired since (an expired-and-revoked row is treated as not-revoked --
// the token itself is already invalid on expiry grounds, and the row is
// pruned separately by DeleteExpired).
func (s *RevokedTokenStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	var expiresAt time.Time
	err := s.Pool.QueryRow(ctx, `SELECT expires_at FROM oidc_revoked_tokens WHERE jti = $1`, jti).Scan(&expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return time.Now().Before(expiresAt), nil
}

// DeleteExpired removes denylist rows past their expiry, called
// periodically so the table doesn't grow unbounded.
func (s *RevokedTokenStore) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM oidc_revoked_tokens WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
