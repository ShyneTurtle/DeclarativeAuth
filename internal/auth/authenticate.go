package auth

import (
	"context"
	"errors"
	"log/slog"

	"declarativeauth/internal/identity"
	"declarativeauth/internal/store"
)

// Result is the outcome of a successful Authenticate call.
type Result struct {
	Username  string
	MustReset bool
}

// Reason enumerates why Authenticate rejected an attempt, for audit logging
// without leaking detail to the end user (avoids user enumeration).
type Reason string

const (
	ReasonLockedOut    Reason = "locked_out"
	ReasonUnknownUser  Reason = "unknown_user"
	ReasonDisabled     Reason = "disabled"
	ReasonNoCredential Reason = "no_credential_set"
	ReasonBadPassword  Reason = "bad_password"
)

// AuthError carries the rejection reason for logging/audit purposes.
type AuthError struct {
	Reason Reason
}

func (e *AuthError) Error() string { return string(e.Reason) }

// Authenticator ties identity.Snapshot + store.CredentialStore +
// Hasher + RateLimiter together into the single credential-check function
// used identically by LDAP bind and OIDC/web login.
type Authenticator struct {
	Snapshot    func() *identity.Snapshot
	Credentials *store.CredentialStore
	Hasher      *Hasher
	RateLimiter *RateLimiter
	Logger      *slog.Logger
}

// Authenticate verifies an identifier (username or email) plus password
// against the current identity snapshot and Postgres credentials, enforcing
// the enabled flag and persisted lockout — without ever running Argon2id on
// a locked-out request.
//
// The identifier is resolved to the canonical username up front (see
// identity.Snapshot.ResolveIdentifier), so brute-force lockout state,
// credential lookup, and the returned Result are always keyed on the same
// username regardless of which form the caller used — an attacker
// alternating between a user's username and email must not get separate
// lockout budgets for each.
func (a *Authenticator) Authenticate(ctx context.Context, identifier, password, sourceIP string) (*Result, error) {
	snap := a.Snapshot()
	username, known := snap.ResolveIdentifier(identifier)

	if a.RateLimiter != nil {
		locked, err := a.RateLimiter.IsLocked(ctx, username, sourceIP)
		if err != nil {
			return nil, err
		}
		if locked {
			return nil, &AuthError{Reason: ReasonLockedOut}
		}
	}

	user, ok := snap.Users[username]
	if !known || !ok {
		// Deliberately still pays the Argon2id cost (against a fixed dummy
		// hash, see Hasher.Dummy) before returning, rather than bailing out
		// immediately -- otherwise "unknown username" is measurably faster
		// than "known username, wrong password", a classic timing side
		// channel an attacker could use to enumerate valid usernames even
		// though every response body already looks identical.
		_, _ = a.Hasher.Verify(password, a.Hasher.Dummy())
		a.recordFailure(ctx, username, sourceIP)
		return nil, &AuthError{Reason: ReasonUnknownUser}
	}
	if !user.Enabled {
		_, _ = a.Hasher.Verify(password, a.Hasher.Dummy())
		a.recordFailure(ctx, username, sourceIP)
		return nil, &AuthError{Reason: ReasonDisabled}
	}

	// A declaratively-hashed user (identity.User.PasswordHash, set via
	// config.UserSpec.PasswordHash/PasswordHashFile) is entirely
	// config-managed: Postgres is never consulted for it, so a
	// self-service reset or `admin set-password` run against it (both of
	// which refuse to, see internal/web/reset.go and cmd_admin.go) could
	// never have had any effect anyway.
	storedHash := user.PasswordHash
	mustReset := false
	var cred *store.Credential
	if storedHash == "" {
		var err error
		cred, err = a.Credentials.Get(ctx, username)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				_, _ = a.Hasher.Verify(password, a.Hasher.Dummy())
				a.recordFailure(ctx, username, sourceIP)
				return nil, &AuthError{Reason: ReasonNoCredential}
			}
			return nil, err
		}
		storedHash = cred.PasswordHash
		mustReset = cred.MustReset
	}

	ok, err := a.Hasher.Verify(password, storedHash)
	if err != nil {
		return nil, err
	}
	if !ok {
		a.recordFailure(ctx, username, sourceIP)
		return nil, &AuthError{Reason: ReasonBadPassword}
	}

	// Backfill the Samba NT hash for a Postgres-backed credential that
	// predates it (or was never touched by a set-password/reset since):
	// this is the only remaining point a plaintext password is available
	// for an existing account without forcing a reset. A no-op query once
	// nt_hash is set. Declaratively-hashed accounts (cred == nil here)
	// never get one -- there is no plaintext to derive it from.
	if cred != nil && cred.NTHash == "" {
		if err := a.Credentials.SetNTHashIfMissing(ctx, username, NTHash(password)); err != nil && a.Logger != nil {
			a.Logger.Error("failed to backfill samba NT hash", "component", "auth", "username", username, "error", err)
		}
	}

	if a.RateLimiter != nil {
		if err := a.RateLimiter.RecordSuccess(ctx, username, sourceIP); err != nil {
			return nil, err
		}
	}
	return &Result{Username: username, MustReset: mustReset}, nil
}

func (a *Authenticator) recordFailure(ctx context.Context, username, sourceIP string) {
	if a.RateLimiter != nil {
		if err := a.RateLimiter.RecordFailure(ctx, username, sourceIP); err != nil && a.Logger != nil {
			a.Logger.Error("failed to record login failure for rate limiting", "component", "auth", "error", err)
		}
	}
}
