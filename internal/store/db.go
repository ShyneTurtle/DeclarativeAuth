// Package store is the Postgres access layer: the system of record for
// everything the declarative YAML cannot express (credentials, sessions,
// reset tokens, audit history, lockouts, and future MFA secrets).
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Open creates a pgxpool connection pool with the given DSN and max
// connections, verifying connectivity with a bounded retry to ride out
// CloudNativePG failover during pod startup.
func Open(ctx context.Context, dsn string, maxConns int32) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing DSN: %w", err)
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}

	var pool *pgxpool.Pool
	var lastErr error
	backoff := 200 * time.Millisecond
	for attempt := 0; attempt < 5; attempt++ {
		pool, lastErr = pgxpool.NewWithConfig(ctx, cfg)
		if lastErr == nil {
			pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			lastErr = pool.Ping(pingCtx)
			cancel()
			if lastErr == nil {
				return pool, nil
			}
			pool.Close()
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 2*time.Second {
			backoff *= 2
		}
	}
	return nil, fmt.Errorf("connecting to postgres after retries: %w", lastErr)
}

// Migrate runs all embedded goose migrations against dsn, idempotently.
func Migrate(dsn string) error {
	connConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("parsing DSN: %w", err)
	}
	db := sql.OpenDB(stdlib.GetConnector(*connConfig))
	defer db.Close()

	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.Up(db, "migrations")
}
