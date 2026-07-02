package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a lookup finds no matching row.
var ErrNotFound = errors.New("not found")

// Credential is a user's stored password hash and reset flag.
type Credential struct {
	Username     string
	PasswordHash string
	MustReset    bool
}

// CredentialStore provides CRUD access to the credentials table.
type CredentialStore struct {
	Pool *pgxpool.Pool
}

// Get returns the credential row for username, or ErrNotFound if the user
// has never had a password set (the bootstrap state).
func (s *CredentialStore) Get(ctx context.Context, username string) (*Credential, error) {
	row := s.Pool.QueryRow(ctx,
		`SELECT username, password_hash, must_reset FROM credentials WHERE username = $1`,
		username)
	var c Credential
	if err := row.Scan(&c.Username, &c.PasswordHash, &c.MustReset); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &c, nil
}

// Upsert sets (or replaces) the password hash for username, clearing
// must_reset.
func (s *CredentialStore) Upsert(ctx context.Context, username, passwordHash string) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO credentials (username, password_hash, password_set_at, must_reset, updated_at)
		VALUES ($1, $2, now(), false, now())
		ON CONFLICT (username) DO UPDATE
		SET password_hash = EXCLUDED.password_hash,
		    password_set_at = now(),
		    must_reset = false,
		    updated_at = now()`,
		username, passwordHash)
	return err
}
