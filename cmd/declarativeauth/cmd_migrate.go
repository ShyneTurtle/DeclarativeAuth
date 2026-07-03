package main

import (
	"flag"
	"fmt"
	"os"

	"declarativeauth/internal/config"
	"declarativeauth/internal/store"
)

func runMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	dsn := fs.String("dsn", os.Getenv(config.EnvDatabaseDSN), "Postgres DSN (defaults to $"+config.EnvDatabaseDSN+")")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dsn == "" {
		return fmt.Errorf("no DSN provided (use -dsn or $%s)", config.EnvDatabaseDSN)
	}
	if err := store.Migrate(*dsn); err != nil {
		return err
	}
	fmt.Println("migrations applied")
	return nil
}
