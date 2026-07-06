package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrExpired is returned when a one-time record (e.g. a WebAuthn ceremony)
// is found but has already passed its expiry.
var ErrExpired = errors.New("expired")

// StoredCredential is a registered passkey together with the display name
// the owner chose for it and the store-managed bookkeeping timestamps.
type StoredCredential struct {
	Username   string
	Name       string
	Credential webauthn.Credential
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// WebAuthnCredentialStore persists registered passkeys (the long-lived
// public key credential records used by both registration and login).
type WebAuthnCredentialStore struct {
	Pool *pgxpool.Pool
}

// Create stores a newly registered passkey for username, under a
// caller-chosen display name (e.g. "MacBook Touch ID") so the owner can
// later tell their passkeys apart on the account page.
func (s *WebAuthnCredentialStore) Create(ctx context.Context, username, name string, cred webauthn.Credential) error {
	data, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	_, err = s.Pool.Exec(ctx, `
		INSERT INTO webauthn_credentials (credential_id, username, name, data, created_at)
		VALUES ($1, $2, $3, $4, now())`,
		cred.ID, username, name, data)
	return err
}

// ListForUser returns every passkey registered for username, oldest first.
func (s *WebAuthnCredentialStore) ListForUser(ctx context.Context, username string) ([]StoredCredential, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT username, name, data, created_at, last_used_at
		FROM webauthn_credentials WHERE username = $1 ORDER BY created_at`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []StoredCredential
	for rows.Next() {
		sc, err := scanStoredCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// UpdateCredential rewrites the stored record for an existing passkey (its
// signature counter and backup-state flags change on every successful
// login) and stamps last_used_at. Must be called after every successful
// login so a cloned authenticator's signature counter can be detected on
// its next use.
func (s *WebAuthnCredentialStore) UpdateCredential(ctx context.Context, cred webauthn.Credential) error {
	data, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	ct, err := s.Pool.Exec(ctx, `
		UPDATE webauthn_credentials SET data = $2, last_used_at = now()
		WHERE credential_id = $1`, cred.ID, data)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes a passkey, scoped to username so a user can only ever
// delete their own credential.
func (s *WebAuthnCredentialStore) Delete(ctx context.Context, username string, credentialID []byte) error {
	ct, err := s.Pool.Exec(ctx, `
		DELETE FROM webauthn_credentials WHERE credential_id = $1 AND username = $2`,
		credentialID, username)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanStoredCredential(row rowScanner) (StoredCredential, error) {
	var sc StoredCredential
	var data []byte
	if err := row.Scan(&sc.Username, &sc.Name, &data, &sc.CreatedAt, &sc.LastUsedAt); err != nil {
		return StoredCredential{}, err
	}
	if err := json.Unmarshal(data, &sc.Credential); err != nil {
		return StoredCredential{}, err
	}
	return sc, nil
}

// WebAuthnCeremonyStore persists the short-lived challenge/session state
// generated between the "start" and "finish" steps of a registration or
// login ceremony. Kept in Postgres (not in-process memory) so it works
// correctly across multiple replicas behind a load balancer, exactly like
// password_reset_tokens.
type WebAuthnCeremonyStore struct {
	Pool *pgxpool.Pool
}

// Save stores sessionData under a caller-generated opaque id, expiring
// after ttl. As a side effect it opportunistically clears any already-
// expired ceremonies, since nothing else in the system does periodic
// cleanup of this small, short-lived table.
func (s *WebAuthnCeremonyStore) Save(ctx context.Context, id string, sessionData *webauthn.SessionData, ttl time.Duration) error {
	data, err := json.Marshal(sessionData)
	if err != nil {
		return err
	}
	if _, err := s.Pool.Exec(ctx, `DELETE FROM webauthn_ceremonies WHERE expires_at < now()`); err != nil {
		return err
	}
	_, err = s.Pool.Exec(ctx, `
		INSERT INTO webauthn_ceremonies (id, data, expires_at) VALUES ($1, $2, $3)`,
		id, data, time.Now().Add(ttl))
	return err
}

// Consume retrieves and deletes the ceremony state for id (one-time use --
// a given challenge must never be presentable twice), returning ErrNotFound
// if it doesn't exist and ErrExpired if its TTL has passed.
func (s *WebAuthnCeremonyStore) Consume(ctx context.Context, id string) (*webauthn.SessionData, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var data []byte
	var expiresAt time.Time
	row := tx.QueryRow(ctx, `SELECT data, expires_at FROM webauthn_ceremonies WHERE id = $1 FOR UPDATE`, id)
	if err := row.Scan(&data, &expiresAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM webauthn_ceremonies WHERE id = $1`, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	if time.Now().After(expiresAt) {
		return nil, ErrExpired
	}

	var sd webauthn.SessionData
	if err := json.Unmarshal(data, &sd); err != nil {
		return nil, err
	}
	return &sd, nil
}
