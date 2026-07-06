package store

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// maxMFAAttempts bounds how many wrong codes a single email-MFA challenge
// accepts before it's permanently rejected, independent of its expiry --
// a short-lived challenge with a 6-digit code still needs its own guess
// budget, since expiry alone (10 minutes) would otherwise allow a fast
// automated guesser a lot of attempts.
const maxMFAAttempts = 5

// ErrChallengeNotFound covers a missing, expired, already-consumed, or
// permanently-locked-out email-MFA challenge -- deliberately not
// distinguished further to the caller, mirroring how login errors are
// generalized to avoid leaking state to an attacker.
var ErrChallengeNotFound = errors.New("mfa challenge not found or expired")

// ErrInvalidCode is returned by EmailChallengeStore.Verify when the
// challenge exists and still has attempts remaining, but the submitted code
// doesn't match.
var ErrInvalidCode = errors.New("invalid code")

// UserMFASettingsStore persists each user's own self-service email-MFA
// preference -- the non-declarative half of MFA enforcement. See
// auth.MFAPolicy, which ORs this against the declarative group/user
// settings resolved from the identity snapshot (identity.Snapshot.
// MFARequiredByDeclaration) to reach the final enforcement decision.
type UserMFASettingsStore struct {
	Pool *pgxpool.Pool
}

// IsEnabled reports whether username has self-enabled email MFA. A user
// with no row here has never opted in, so this defaults to false.
func (s *UserMFASettingsStore) IsEnabled(ctx context.Context, username string) (bool, error) {
	var enabled bool
	err := s.Pool.QueryRow(ctx, `SELECT enabled FROM user_mfa_settings WHERE username = $1`, username).Scan(&enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return enabled, nil
}

// SetEnabled upserts username's self-service MFA preference.
func (s *UserMFASettingsStore) SetEnabled(ctx context.Context, username string, enabled bool) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO user_mfa_settings (username, enabled, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (username) DO UPDATE SET enabled = $2, updated_at = now()`,
		username, enabled)
	return err
}

// EmailChallengeStore persists in-flight email-OTP MFA challenges between a
// successful password login and code verification -- the same "server-side
// ceremony state, referenced by an opaque cookie value" pattern as
// WebAuthnCeremonyStore and ResetTokenStore.
type EmailChallengeStore struct {
	Pool *pgxpool.Pool
}

// EmailChallenge is the resolved result of a successfully verified (or
// peeked) challenge.
type EmailChallenge struct {
	Username string
	ReturnTo string
}

// Create stores a new challenge, self-cleaning already-expired rows first
// (same housekeeping approach as WebAuthnCeremonyStore.Save) so this table
// doesn't grow unbounded from abandoned login attempts.
func (s *EmailChallengeStore) Create(ctx context.Context, id, username, codeHash, returnTo string, ttl time.Duration) error {
	if _, err := s.Pool.Exec(ctx, `DELETE FROM mfa_email_challenges WHERE expires_at < now()`); err != nil {
		return err
	}
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO mfa_email_challenges (id, username, code_hash, return_to, expires_at)
		VALUES ($1, $2, $3, $4, now() + $5)`,
		id, username, codeHash, returnTo, ttl)
	return err
}

// Verify checks codeHash against the stored challenge, consuming it
// (one-time use) on success. On a wrong code it increments the attempt
// counter and returns ErrInvalidCode, until maxMFAAttempts is reached, at
// which point (and after expiry, or if the id is unknown/already consumed)
// it returns ErrChallengeNotFound instead -- so a caller can't distinguish
// "wrong code, try again" from "this challenge is now dead" beyond what
// ErrInvalidCode already conveys.
func (s *EmailChallengeStore) Verify(ctx context.Context, id, codeHash string) (*EmailChallenge, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var ch EmailChallenge
	var storedHash string
	var attempts int
	err = tx.QueryRow(ctx, `
		SELECT username, code_hash, return_to, attempts FROM mfa_email_challenges
		WHERE id = $1 AND consumed_at IS NULL AND expires_at > now()
		FOR UPDATE`, id).Scan(&ch.Username, &storedHash, &ch.ReturnTo, &attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrChallengeNotFound
	}
	if err != nil {
		return nil, err
	}
	if attempts >= maxMFAAttempts {
		return nil, ErrChallengeNotFound
	}

	if subtle.ConstantTimeCompare([]byte(storedHash), []byte(codeHash)) != 1 {
		if _, err := tx.Exec(ctx, `UPDATE mfa_email_challenges SET attempts = attempts + 1 WHERE id = $1`, id); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, ErrInvalidCode
	}

	if _, err := tx.Exec(ctx, `UPDATE mfa_email_challenges SET consumed_at = now() WHERE id = $1`, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &ch, nil
}

// Peek returns the username/return_to for a still-live (not consumed,
// not expired) challenge without checking a code or consuming it, for the
// "resend code" action.
func (s *EmailChallengeStore) Peek(ctx context.Context, id string) (*EmailChallenge, error) {
	var ch EmailChallenge
	err := s.Pool.QueryRow(ctx, `
		SELECT username, return_to FROM mfa_email_challenges
		WHERE id = $1 AND consumed_at IS NULL AND expires_at > now()`, id).Scan(&ch.Username, &ch.ReturnTo)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrChallengeNotFound
	}
	if err != nil {
		return nil, err
	}
	return &ch, nil
}

// Delete removes a challenge outright, used when superseding it with a
// freshly generated one on "resend code".
func (s *EmailChallengeStore) Delete(ctx context.Context, id string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM mfa_email_challenges WHERE id = $1`, id)
	return err
}
