package main

import (
	"flag"
	"fmt"
	"os"

	"declarativeauth/internal/config"
)

func runValidateConfig(args []string) error {
	fs := flag.NewFlagSet("validate-config", flag.ExitOnError)
	defaultPath := os.Getenv(config.EnvIdentityPath)
	if defaultPath == "" {
		defaultPath = "/etc/declarativeauth/identity"
	}
	identityPath := fs.String("identity-path", defaultPath, "directory recursively scanned for identity YAML (users/groups/OIDC clients) (defaults to $"+config.EnvIdentityPath+")")
	if err := fs.Parse(args); err != nil {
		return err
	}

	snap, err := config.LoadIdentity(*identityPath)
	if err != nil {
		return err
	}

	disabled := 0
	for _, u := range snap.Users {
		if !u.Enabled {
			disabled++
		}
	}
	fmt.Printf("config valid: %d groups, %d users (%d disabled), %d oidc clients\n", len(snap.Groups), len(snap.Users), disabled, len(snap.OIDCClients))
	if len(snap.Users) == 0 {
		fmt.Println("warning: zero users declared -- no one can log in until at least one is declared")
	}
	return nil
}
