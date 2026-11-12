package store

import (
	"context"
	"errors"
	"time"

	"declarativeauth/internal/totp"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrInvalidTOTPCode is returned by ConfirmEnrollment for a wrong code or
// when there is no pending enrolment to confirm.
var ErrInvalidTOTPCode = errors.New("invalid totp code")

// TOTPStore persists each user's authenticator-app secret, sealed with
// Cipher. See migration 00015 for the pending/active split.
type TOTPStore struct {
	Pool   *pgxpool.Pool
	Cipher *totp.Cipher
}

// IsEnrolled reports whether username has a confirmed secret.
func (s *TOTPStore) IsEnrolled(ctx context.Context, username string) (bool, error) {
	var enrolled bool
	err := s.Pool.QueryRow(ctx, `SELECT secret_enc IS NOT NULL FROM user_totp WHERE username = $1`, username).Scan(&enrolled)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return enrolled, err
}

// BeginEnrollment generates a new pending secret (replacing any earlier
// pending one, leaving the active secret untouched) and returns it.
func (s *TOTPStore) BeginEnrollment(ctx context.Context, username string) ([]byte, error) {
	secret, err := totp.GenerateSecret()
	if err != nil {
		return nil, err
	}
	sealed, err := s.Cipher.Seal(secret, username)
	if err != nil {
		return nil, err
	}
	_, err = s.Pool.Exec(ctx, `
		INSERT INTO user_totp (username, pending_secret_enc, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (username) DO UPDATE SET pending_secret_enc = $2, updated_at = now()`,
		username, sealed)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// PendingSecret returns the unconfirmed secret for username, or nil if none.
func (s *TOTPStore) PendingSecret(ctx context.Context, username string) ([]byte, error) {
	var sealed []byte
	err := s.Pool.QueryRow(ctx, `SELECT pending_secret_enc FROM user_totp WHERE username = $1`, username).Scan(&sealed)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && sealed == nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.Cipher.Open(sealed, username)
}

// ConfirmEnrollment promotes the pending secret to active if code is valid
// for it. The accepted step is recorded so that same code can't then be
// replayed to log in.
func (s *TOTPStore) ConfirmEnrollment(ctx context.Context, username, code string, now time.Time) error {
	secret, err := s.PendingSecret(ctx, username)
	if err != nil {
		return err
	}
	if secret == nil {
		return ErrInvalidTOTPCode
	}
	step, ok := totp.Verify(secret, code, now, 0)
	if !ok {
		return ErrInvalidTOTPCode
	}
	sealed, err := s.Cipher.Seal(secret, username)
	if err != nil {
		return err
	}
	_, err = s.Pool.Exec(ctx, `
		UPDATE user_totp
		SET secret_enc = $2, pending_secret_enc = NULL, last_step = $3, confirmed_at = now(), updated_at = now()
		WHERE username = $1`, username, sealed, step)
	return err
}

// Remove deletes username's TOTP enrolment entirely.
func (s *TOTPStore) Remove(ctx context.Context, username string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM user_totp WHERE username = $1`, username)
	return err
}

// Verify checks a login code against username's active secret and, on
// success, atomically records the step so the code can't be reused. A user
// with no active secret never verifies.
func (s *TOTPStore) Verify(ctx context.Context, username, code string) (bool, error) {
	var sealed []byte
	var last int64
	err := s.Pool.QueryRow(ctx, `SELECT secret_enc, last_step FROM user_totp WHERE username = $1`, username).Scan(&sealed, &last)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && sealed == nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	secret, err := s.Cipher.Open(sealed, username)
	if err != nil {
		return false, err
	}
	step, ok := totp.Verify(secret, code, time.Now(), last)
	if !ok {
		return false, nil
	}
	// The WHERE clause makes acceptance race-safe: of two concurrent binds
	// presenting the same code, only one UPDATE matches.
	tag, err := s.Pool.Exec(ctx, `UPDATE user_totp SET last_step = $2 WHERE username = $1 AND last_step < $2`, username, step)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}
