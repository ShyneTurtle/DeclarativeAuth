package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"declarativeauth/internal/auth"
	"declarativeauth/internal/config"
	"declarativeauth/internal/store"
)

func runAdmin(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: declarativeauth admin <set-password|hash-password> [flags]")
	}
	switch args[0] {
	case "set-password":
		return runAdminSetPassword(args[1:])
	case "hash-password":
		return runAdminHashPassword(args[1:])
	default:
		return fmt.Errorf("unknown admin subcommand %q", args[0])
	}
}

func runAdminSetPassword(args []string) error {
	fs := flag.NewFlagSet("admin set-password", flag.ExitOnError)
	dsn := fs.String("dsn", os.Getenv(config.EnvDatabaseDSN), "Postgres DSN (defaults to $"+config.EnvDatabaseDSN+")")
	username := fs.String("username", "", "username to set the password for")
	password := fs.String("password", "", "new password (avoid in shell history; prefer an env-var driven wrapper script)")
	defaultIdentityPath := os.Getenv(config.EnvIdentityPath)
	identityPath := fs.String("identity-path", defaultIdentityPath, "optional: identity directory to check against, so this refuses to write a Postgres credential that a passwordHash/passwordHashFile user would just ignore (defaults to $"+config.EnvIdentityPath+")")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" || *password == "" || *dsn == "" {
		return fmt.Errorf("-dsn (or $%s), -username and -password are required", config.EnvDatabaseDSN)
	}

	// Best-effort: if an identity directory is available, refuse for a
	// declaratively-hashed user rather than silently writing a Postgres
	// credential that internal/auth.Authenticator will never consult (see
	// identity.User.PasswordHash). If the directory can't be loaded (not
	// provided, not reachable from wherever this CLI happens to run), skip
	// the check rather than block on it -- this is a convenience guard, not
	// the source of truth.
	if *identityPath != "" {
		if snap, err := config.LoadIdentity(*identityPath); err == nil {
			if u, ok := snap.Users[*username]; ok && u.PasswordHash != "" {
				return fmt.Errorf("%s's password is set declaratively (passwordHash/passwordHashFile in the identity config) -- edit that instead, a Postgres credential here would be ignored", *username)
			}
		}
	}

	ctx := context.Background()
	pool, err := store.Open(ctx, *dsn, 2)
	if err != nil {
		return err
	}
	defer pool.Close()

	hasher := &auth.Hasher{Params: auth.DefaultArgon2Params}
	encoded, err := hasher.Hash(*password)
	if err != nil {
		return err
	}

	creds := &store.CredentialStore{Pool: pool}
	if err := creds.Upsert(ctx, *username, encoded, auth.NTHash(*password)); err != nil {
		return err
	}
	fmt.Printf("password set for %s\n", *username)
	return nil
}

// runAdminHashPassword prints an Argon2id hash for a password without
// touching Postgres or any identity file -- the intended way to compute the
// value for a user's declarative passwordHash field, or the content of a
// Docker/Kubernetes secret referenced via passwordHashFile, entirely
// offline (e.g. in CI when building the secret), replacing the
// init-container-that-runs-admin-set-password pattern.
func runAdminHashPassword(args []string) error {
	fs := flag.NewFlagSet("admin hash-password", flag.ExitOnError)
	password := fs.String("password", "", "password to hash (avoid in shell history; prefer an env-var driven wrapper script)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *password == "" {
		return fmt.Errorf("-password is required")
	}

	hasher := &auth.Hasher{Params: auth.DefaultArgon2Params}
	encoded, err := hasher.Hash(*password)
	if err != nil {
		return err
	}
	fmt.Println(encoded)
	return nil
}
