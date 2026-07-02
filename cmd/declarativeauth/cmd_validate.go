package main

import (
	"flag"
	"fmt"

	"declarativeauth/internal/config"
)

func runValidateConfig(args []string) error {
	fs := flag.NewFlagSet("validate-config", flag.ExitOnError)
	identityPath := fs.String("identity-path", "/etc/declarativeauth/identity", "directory containing users.yaml/groups.yaml")
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
	fmt.Printf("config valid: %d groups, %d users (%d disabled)\n", len(snap.Groups), len(snap.Users), disabled)
	return nil
}
