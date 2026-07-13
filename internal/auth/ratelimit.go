package auth

import (
	"context"
	"time"

	"declarativeauth/internal/store"
)

// RateLimiter checks and records the persisted, configurable brute-force
// backoff across the per-account and per-IP dimensions. The two dimensions
// are independent: each has its own LockoutParams, and each can be disabled
// on its own (Threshold <= 0, see store.ComputeBackoff) without affecting
// the other. That independence matters because they defend against
// different things and have different failure modes -- the account
// dimension stops credential stuffing against one target but is itself a
// DoS lever for anyone who knows a username; the IP dimension slows a
// spray across many usernames from one machine but, at a shared egress IP
// (NAT/VPN/CGNAT), can lock out every user behind it. A deployment should
// be able to run one, both, or neither, tuned independently.
type RateLimiter struct {
	Lockouts *store.LockoutStore
	Params   store.LockoutParams // account dimension, keyed by username
	IPParams store.LockoutParams // IP dimension, keyed by source IP

	// KeyPrefix namespaces lockout keys so independent call sites sharing
	// the same underlying store (e.g. login vs. password-reset requests)
	// don't draw on the same failure budget -- a user retrying a typo'd
	// reset email shouldn't burn down their login lockout allowance, and
	// vice versa. Empty by default, matching the pre-existing "user:"/"ip:"
	// key format already persisted for login lockouts.
	KeyPrefix string
}

func (r *RateLimiter) userKey(username string) string { return r.KeyPrefix + "user:" + username }
func (r *RateLimiter) ipKey(sourceIP string) string   { return r.KeyPrefix + "ip:" + sourceIP }

// IsLocked reports whether either the account or the source IP is currently
// locked out. A dimension whose Threshold <= 0 is skipped entirely (no
// Postgres round-trip for a disabled dimension).
func (r *RateLimiter) IsLocked(ctx context.Context, username, sourceIP string) (bool, error) {
	if username != "" && r.Params.Threshold > 0 {
		locked, err := r.Lockouts.IsLocked(ctx, r.userKey(username))
		if err != nil || locked {
			return locked, err
		}
	}
	if sourceIP != "" && r.IPParams.Threshold > 0 {
		return r.Lockouts.IsLocked(ctx, r.ipKey(sourceIP))
	}
	return false, nil
}

// RecordFailure increments whichever dimensions are enabled.
func (r *RateLimiter) RecordFailure(ctx context.Context, username, sourceIP string) error {
	if username != "" && r.Params.Threshold > 0 {
		if err := r.Lockouts.RecordFailure(ctx, r.userKey(username), r.Params); err != nil {
			return err
		}
	}
	if sourceIP != "" && r.IPParams.Threshold > 0 {
		if err := r.Lockouts.RecordFailure(ctx, r.ipKey(sourceIP), r.IPParams); err != nil {
			return err
		}
	}
	return nil
}

// RecordSuccess clears whichever dimensions are enabled.
func (r *RateLimiter) RecordSuccess(ctx context.Context, username, sourceIP string) error {
	if username != "" && r.Params.Threshold > 0 {
		if err := r.Lockouts.Reset(ctx, r.userKey(username)); err != nil {
			return err
		}
	}
	if sourceIP != "" && r.IPParams.Threshold > 0 {
		if err := r.Lockouts.Reset(ctx, r.ipKey(sourceIP)); err != nil {
			return err
		}
	}
	return nil
}

// ParamsFromConfig converts config duration fields into store.LockoutParams.
func ParamsFromConfig(threshold int, base, max, window time.Duration) store.LockoutParams {
	return store.LockoutParams{
		Threshold:   threshold,
		BackoffBase: base,
		BackoffMax:  max,
		Window:      window,
	}
}
