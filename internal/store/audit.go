package store

import (
	"context"
	"net"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditEvent is one row written to login_audit.
type AuditEvent struct {
	Username  string
	EventType string
	SourceIP  net.IP
	UserAgent string
	Detail    string
}

// AuditStore writes to the login_audit table.
type AuditStore struct {
	Pool *pgxpool.Pool
}

// Write inserts an audit event. Failures are logged by the caller but never
// block the auth path (audit is best-effort observability, not a control).
func (s *AuditStore) Write(ctx context.Context, e AuditEvent) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO login_audit (username, event_type, source_ip, user_agent, detail)
		VALUES ($1, $2, $3, $4, $5)`,
		nullIfEmpty(e.Username), e.EventType, ipOrNil(e.SourceIP), e.UserAgent, e.Detail)
	return err
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
