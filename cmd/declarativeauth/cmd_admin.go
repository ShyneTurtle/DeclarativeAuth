package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"declarativeauth/internal/auth"
	"declarativeauth/internal/store"
)

func runAdmin(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: declarativeauth admin <set-password> [flags]")
	}
	switch args[0] {
	case "set-password":
		return runAdminSetPassword(args[1:])
	default:
		return fmt.Errorf("unknown admin subcommand %q", args[0])
	}
}

func runAdminSetPassword(args []string) error {
	fs := flag.NewFlagSet("admin set-password", flag.ExitOnError)
	dsn := fs.String("dsn", os.Getenv("DATABASE_URL"), "Postgres DSN (defaults to $DATABASE_URL)")
	username := fs.String("username", "", "username to set the password for")
	password := fs.String("password", "", "new password (avoid in shell history; prefer an env-var driven wrapper script)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" || *password == "" || *dsn == "" {
		return fmt.Errorf("-dsn, -username and -password are required")
	}
	pepper := os.Getenv(auth.PepperEnvVar)
	if pepper == "" {
		return fmt.Errorf("%s is not set", auth.PepperEnvVar)
	}

	ctx := context.Background()
	pool, err := store.Open(ctx, *dsn, 2)
	if err != nil {
		return err
	}
	defer pool.Close()

	hasher := &auth.Hasher{Pepper: []byte(pepper), Params: auth.DefaultArgon2Params}
	encoded, err := hasher.Hash(*password)
	if err != nil {
		return err
	}

	creds := &store.CredentialStore{Pool: pool}
	if err := creds.Upsert(ctx, *username, encoded); err != nil {
		return err
	}
	fmt.Printf("password set for %s\n", *username)
	return nil
}
