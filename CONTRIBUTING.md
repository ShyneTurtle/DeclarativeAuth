# Contributing

## Local dev setup

This project was developed without a local Go toolchain, using a Docker-based
dev container (WSL on Windows). To reproduce it:

```sh
docker compose -f deploy/dev/docker-compose.dev.yml up -d --build
docker compose -f deploy/dev/docker-compose.dev.yml exec dev go build ./...
```

The dev container includes Go, `staticcheck`, `goose`, and `ldap-utils`, and
is networked with a Postgres and a mailcatcher service (matching what CI
uses). If you have Go 1.25+ installed natively, you can of course just work
directly against the repo instead.

> Note: `deploy/demo/docker-compose.yaml` and `deploy/compose/docker-compose.yaml`
> are *different* stacks — they build the production image for manual
> click-through testing (`deploy/demo/`, throwaway) or a homelab-ready
> single-instance deployment (`deploy/compose/`, persistent), rather than a
> Go toolchain dev environment. All three default to different Compose
> project names (derived from their directory), so running one won't
> recreate another's containers.

## Running tests

```sh
# Unit tests (fast, no external services)
go test ./...

# Integration tests (needs Postgres; mailcatcher optional -- reset/admin
# email tests skip themselves if unreachable)
DATABASE_URL="postgres://declarativeauth:declarativeauth@localhost:5432/declarativeauth?sslmode=disable" \
  go test ./test/integration/... -tags=integration
```

## Lint

```sh
gofmt -l .          # must produce no output
go vet ./...
staticcheck ./...   # go install honnef.co/go/tools/cmd/staticcheck@latest
```

All of the above run in CI (`.github/workflows/ci.yaml`) on every push/PR.

## Adding a migration

Add a new `internal/store/migrations/000NN_description.sql` file with
`-- +goose Up` / `-- +goose Down` sections (see existing migrations for the
pattern). Migrations run automatically on `declarativeauth serve` startup,
or standalone via `declarativeauth migrate`.

## Code conventions

- No comments explaining *what* code does when names already convey it;
  comments are reserved for non-obvious *why* (see `internal/config/watcher.go`
  for an example — why it watches a directory, not a file).
- Every exported identifier gets a doc comment.
- Each `internal/<pkg>` has a package-level doc comment on its main file
  explaining its single responsibility.
