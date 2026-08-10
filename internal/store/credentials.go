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
	// NTHash is the Samba/NTLM "NT hash" (see auth.NTHash), empty until the
	// first successful password verification or set/reset after this field
	// was introduced -- Authenticate backfills it lazily since it's the
	// only place a plaintext password is available for an existing account
	// without asking the user to change it. Never derived from PasswordHash
	// itself, which is one-way Argon2id.
	NTHash    string
	SambaRID  int64
	MustReset bool
}

// SambaCredential is the subset of a Credential an LDAP search privileged
// via the samba-readers group is allowed to see: enough to populate a
// sambaSamAccount entry, nothing else.
type SambaCredential struct {
	NTHash string
	RID    int64
}

// CredentialStore provides CRUD access to the credentials table.
type CredentialStore struct {
	Pool *pgxpool.Pool
}

// Get returns the credential row for username, or ErrNotFound if the user
// has never had a password set (the bootstrap state).
func (s *CredentialStore) Get(ctx context.Context, username string) (*Credential, error) {
	row := s.Pool.QueryRow(ctx,
		`SELECT username, password_hash, COALESCE(nt_hash, ''), COALESCE(samba_rid, 0), must_reset
		 FROM credentials WHERE username = $1`,
		username)
	var c Credential
	if err := row.Scan(&c.Username, &c.PasswordHash, &c.NTHash, &c.SambaRID, &c.MustReset); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &c, nil
}

// Upsert sets (or replaces) the password hash and NT hash for username,
// clearing must_reset. A RID is assigned once -- either now, for a
// brand-new row, or on a later call, for a row that predates the NT hash
// column and never got one -- and kept stable afterwards regardless of how
// many more times the password changes. nextval() is evaluated by Postgres
// even on the ON CONFLICT update path whether or not its value ends up
// used, so a password change on a user that already has a RID still burns
// a sequence value; that just leaves a gap in the RID space, which is
// harmless (Windows/Samba SIDs are not required to be contiguous).
func (s *CredentialStore) Upsert(ctx context.Context, username, passwordHash, ntHash string) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO credentials (username, password_hash, nt_hash, samba_rid, password_set_at, must_reset, updated_at)
		VALUES ($1, $2, $3, nextval('samba_rid_seq'), now(), false, now())
		ON CONFLICT (username) DO UPDATE
		SET password_hash = EXCLUDED.password_hash,
		    nt_hash = EXCLUDED.nt_hash,
		    samba_rid = COALESCE(credentials.samba_rid, EXCLUDED.samba_rid),
		    password_set_at = now(),
		    must_reset = false,
		    updated_at = now()`,
		username, passwordHash, ntHash)
	return err
}

// SetNTHashIfMissing backfills ntHash (and assigns a RID) for an existing
// credential row that predates the NT hash column, or that was created
// before a samba-readers-group deployment existed to make use of it. A
// no-op once nt_hash is already set, so a successful login only ever pays
// this write once per user.
func (s *CredentialStore) SetNTHashIfMissing(ctx context.Context, username, ntHash string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE credentials
		SET nt_hash = $2,
		    samba_rid = COALESCE(samba_rid, nextval('samba_rid_seq')),
		    updated_at = now()
		WHERE username = $1 AND nt_hash IS NULL`,
		username, ntHash)
	return err
}

// AllSambaCredentials returns every user's NT hash + RID that has one,
// keyed by username -- fetched in one round-trip per privileged LDAP
// search rather than per matched entry.
func (s *CredentialStore) AllSambaCredentials(ctx context.Context) (map[string]SambaCredential, error) {
	rows, err := s.Pool.Query(ctx, `SELECT username, nt_hash, samba_rid FROM credentials WHERE nt_hash IS NOT NULL AND samba_rid IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]SambaCredential)
	for rows.Next() {
		var username, ntHash string
		var rid int64
		if err := rows.Scan(&username, &ntHash, &rid); err != nil {
			return nil, err
		}
		out[username] = SambaCredential{NTHash: ntHash, RID: rid}
	}
	return out, rows.Err()
}
