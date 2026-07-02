// Command declarativeauth is the DeclarativeAuth server and CLI.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "migrate":
		err = runMigrate(os.Args[2:])
	case "validate-config":
		err = runValidateConfig(os.Args[2:])
	case "admin":
		err = runAdmin(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: declarativeauth <command> [flags]

Commands:
  serve             Run the LDAP/OIDC/web/metrics server (default long-running process)
  migrate           Apply pending Postgres migrations and exit
  validate-config   Validate the declarative users/groups config and exit
  admin             Admin escape-hatch subcommands (set-password)`)
}
