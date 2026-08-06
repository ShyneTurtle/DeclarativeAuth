package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OIDCSigningKey is a JWT signing key row: either an ES256 (P-256) or RS256
// (RSA) key, PKCS8/PEM-encoded.
type OIDCSigningKey struct {
	Kid           string
	Algorithm     string
	PrivateKeyPEM string
	IsCurrent     bool
	CreatedAt     time.Time
	RetireAt      *time.Time
}

// OIDCKeyStore provides CRUD access to oidc_signing_keys, the replica-shared
// replacement for the earlier in-process, unrotated signing key.
type OIDCKeyStore struct {
	Pool *pgxpool.Pool
}

// Active returns every key still valid for JWT verification: the current
// signer plus any recently-retired key still inside its overlap window.
func (s *OIDCKeyStore) Active(ctx context.Context) ([]OIDCSigningKey, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT kid, algorithm, private_key_pem, is_current, created_at, retire_at
		FROM oidc_signing_keys
		WHERE retire_at IS NULL OR retire_at > now()
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []OIDCSigningKey
	for rows.Next() {
		var k OIDCSigningKey
		if err := rows.Scan(&k.Kid, &k.Algorithm, &k.PrivateKeyPEM, &k.IsCurrent, &k.CreatedAt, &k.RetireAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// Lookup fetches a single key by kid, including retired/expired ones -- the
// caller is responsible for checking RetireAt itself if that distinction
// matters to it.
func (s *OIDCKeyStore) Lookup(ctx context.Context, kid string) (*OIDCSigningKey, error) {
	var k OIDCSigningKey
	err := s.Pool.QueryRow(ctx, `
		SELECT kid, algorithm, private_key_pem, is_current, created_at, retire_at
		FROM oidc_signing_keys WHERE kid = $1`, kid).Scan(
		&k.Kid, &k.Algorithm, &k.PrivateKeyPEM, &k.IsCurrent, &k.CreatedAt, &k.RetireAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &k, nil
}

// RotateIfDue atomically checks the current signing key's age against
// interval and, if rotation is due (including the bootstrap case of no
// current key at all), retires it -- with an overlap window during which it
// remains valid for verification, so tokens it already signed don't
// suddenly fail -- and installs a freshly generated key as the new current
// signer. Locks the current key's row for the check so concurrent replicas
// racing the same rotation serialize: the first commits the rotation, the
// rest see an up-to-date key and no-op. genKey is only called when rotation
// is actually due, since key generation is comparatively expensive and most
// calls find nothing to do.
func (s *OIDCKeyStore) RotateIfDue(ctx context.Context, interval, overlap time.Duration, genKey func() (OIDCSigningKey, error)) (rotated bool, err error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)

	var currentKid string
	var createdAt time.Time
	err = tx.QueryRow(ctx, `SELECT kid, created_at FROM oidc_signing_keys WHERE is_current = true FOR UPDATE`).Scan(&currentKid, &createdAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	hasCurrent := err == nil
	if hasCurrent && time.Now().Before(createdAt.Add(interval)) {
		return false, nil
	}

	newKey, err := genKey()
	if err != nil {
		return false, err
	}

	if hasCurrent {
		if _, err := tx.Exec(ctx, `
			UPDATE oidc_signing_keys SET is_current = false, retire_at = now() + $2::interval WHERE kid = $1`,
			currentKid, overlap.String()); err != nil {
			return false, err
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO oidc_signing_keys (kid, algorithm, private_key_pem, is_current, created_at)
		VALUES ($1, $2, $3, true, now())`,
		newKey.Kid, newKey.Algorithm, newKey.PrivateKeyPEM); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}
