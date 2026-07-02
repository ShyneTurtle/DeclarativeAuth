package store

import (
	"context"
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
	ExpiresAt        time.Time
	UserAgent        string
	IPAddress        net.IP
	RevokedAt        *time.Time
}

// SessionStore provides CRUD access to the sessions table.
type SessionStore struct {
	Pool *pgxpool.Pool
}

// Create inserts a new session row.
func (s *SessionStore) Create(ctx context.Context, sess Session) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO sessions (id, username, refresh_token_hash, client_id, expires_at, user_agent, ip_address)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		sess.ID, sess.Username, sess.RefreshTokenHash, sess.ClientID, sess.ExpiresAt, sess.UserAgent, ipOrNil(sess.IPAddress))
	return err
}

// GetByID returns the session row for id, or ErrNotFound.
func (s *SessionStore) GetByID(ctx context.Context, id uuid.UUID) (*Session, error) {
	row := s.Pool.QueryRow(ctx, `
		SELECT id, username, refresh_token_hash, client_id, expires_at, user_agent, revoked_at
		FROM sessions WHERE id = $1`, id)
	var sess Session
	var clientID *string
	var userAgent *string
	if err := row.Scan(&sess.ID, &sess.Username, &sess.RefreshTokenHash, &clientID, &sess.ExpiresAt, &userAgent, &sess.RevokedAt); err != nil {
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
