package store

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Session is a refresh-token-backed session, shared by OIDC refresh tokens
// and the web login cookie.
type Session struct {
	ID               uuid.UUID
	Username         string
	RefreshTokenHash string
	ClientID         string
	// Scope is the OIDC scope the session was granted, so a refresh can
	// reissue an ID token with the same claims. Unused (empty) for the web
	// login cookie.
	Scope string
	// IssuedAt is when the session was first created -- i.e. when the user
	// actually authenticated. Unlike ExpiresAt, refresh token rotation
	// doesn't touch it, so it doubles as OIDC's auth_time for max_age
	// checks (see oidcserver.Provider.handleAuthorize).
	IssuedAt  time.Time
	ExpiresAt time.Time
	UserAgent string
	IPAddress net.IP
	RevokedAt *time.Time
}

// ErrRefreshTokenReused is returned by RotateRefreshToken when the
// presented secret doesn't match a live, non-revoked session's current
// secret -- see RotateRefreshToken's doc comment for why that's treated as
// reuse rather than a plain invalid token.
var ErrRefreshTokenReused = errors.New("refresh token reused")

// SessionStore provides CRUD access to the sessions table.
type SessionStore struct {
	Pool *pgxpool.Pool
}

// Create inserts a new session row.
func (s *SessionStore) Create(ctx context.Context, sess Session) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO sessions (id, username, refresh_token_hash, client_id, scope, expires_at, user_agent, ip_address)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		sess.ID, sess.Username, sess.RefreshTokenHash, sess.ClientID, sess.Scope, sess.ExpiresAt, sess.UserAgent, ipOrNil(sess.IPAddress))
	return err
}

// GetByID returns the session row for id, or ErrNotFound.
func (s *SessionStore) GetByID(ctx context.Context, id uuid.UUID) (*Session, error) {
	row := s.Pool.QueryRow(ctx, `
		SELECT id, username, refresh_token_hash, client_id, scope, issued_at, expires_at, user_agent, revoked_at
		FROM sessions WHERE id = $1`, id)
	var sess Session
	var clientID *string
	var userAgent *string
	if err := row.Scan(&sess.ID, &sess.Username, &sess.RefreshTokenHash, &clientID, &sess.Scope, &sess.IssuedAt, &sess.ExpiresAt, &userAgent, &sess.RevokedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if clientID != nil {
		sess.ClientID = *clientID
	}
	if userAgent != nil {
		sess.UserAgent = *userAgent
	}
	return &sess, nil
}

// RotateRefreshToken validates and rotates a refresh token in one
// transaction: id must reference a non-revoked, unexpired session whose
// current secret hash equals oldHash. On success it installs newHash as the
// session's new secret (rotation) and extends ExpiresAt to newExpiresAt,
// returning the session.
//
// On a hash mismatch against a live, non-revoked, unexpired session, the
// session is revoked outright rather than just rejected (ErrRefreshTokenReused),
// implementing refresh token reuse detection: these are opaque,
// machine-generated bearer tokens, not user-typed passwords, so there's no
// legitimate reason for a client to hold a stale secret for a still-live
// session ID -- the only realistic explanation is a replay of a token that
// was already rotated away (or otherwise stolen), which is exactly the
// signal OAuth's refresh token rotation guidance says should revoke the
// whole session, not just deny the one request.
func (s *SessionStore) RotateRefreshToken(ctx context.Context, id uuid.UUID, oldHash, newHash string, newExpiresAt time.Time) (*Session, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	row := tx.QueryRow(ctx, `
		SELECT id, username, refresh_token_hash, client_id, scope, expires_at, user_agent, revoked_at
		FROM sessions WHERE id = $1 FOR UPDATE`, id)
	var sess Session
	var clientID *string
	var userAgent *string
	if err := row.Scan(&sess.ID, &sess.Username, &sess.RefreshTokenHash, &clientID, &sess.Scope, &sess.ExpiresAt, &userAgent, &sess.RevokedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if clientID != nil {
		sess.ClientID = *clientID
	}
	if sess.RevokedAt != nil || time.Now().After(sess.ExpiresAt) {
		return nil, ErrNotFound
	}
	if subtle.ConstantTimeCompare([]byte(sess.RefreshTokenHash), []byte(oldHash)) != 1 {
		if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE id = $1`, id); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, ErrRefreshTokenReused
	}

	if _, err := tx.Exec(ctx, `UPDATE sessions SET refresh_token_hash = $2, expires_at = $3 WHERE id = $1`,
		id, newHash, newExpiresAt); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	sess.RefreshTokenHash = newHash
	sess.ExpiresAt = newExpiresAt
	return &sess, nil
}

// Revoke marks a session revoked by ID.
func (s *SessionStore) Revoke(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE id = $1`, id)
	return err
}

// RevokeAllForUser revokes every active session for username ("log out
// everywhere").
func (s *SessionStore) RevokeAllForUser(ctx context.Context, username string) error {
	_, err := s.Pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = now() WHERE username = $1 AND revoked_at IS NULL`,
		username)
	return err
}

// CountActive returns the number of non-revoked, non-expired sessions, for
// the declarativeauth_active_sessions gauge.
func (s *SessionStore) CountActive(ctx context.Context) (int64, error) {
	var n int64
	err := s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > now()`).Scan(&n)
	return n, err
}

func ipOrNil(ip net.IP) any {
	if ip == nil {
		return nil
	}
	return ip.String()
}
