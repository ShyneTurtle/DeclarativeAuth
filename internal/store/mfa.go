package store

import "github.com/jackc/pgx/v5/pgxpool"

// MFAStore is a placeholder repository for the future TOTP MFA extension.
// The mfa_totp_secrets/mfa_recovery_codes tables already exist (migration
// 00005) so that extension is additive-only; no application code reads or
// writes them yet.
type MFAStore struct {
	Pool *pgxpool.Pool
}
