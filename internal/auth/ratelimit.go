package auth

import (
	"context"
	"time"

	"declarativeauth/internal/store"
)

// RateLimiter checks and records the persisted, configurable brute-force
// backoff across both the per-account and per-IP dimensions.
type RateLimiter struct {
	Lockouts *store.LockoutStore
	Params   store.LockoutParams

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
// locked out.
func (r *RateLimiter) IsLocked(ctx context.Context, username, sourceIP string) (bool, error) {
	if username != "" {
		locked, err := r.Lockouts.IsLocked(ctx, r.userKey(username))
		if err != nil || locked {
			return locked, err
		}
	}
	if sourceIP != "" {
		return r.Lockouts.IsLocked(ctx, r.ipKey(sourceIP))
	}
	return false, nil
}

// RecordFailure increments both dimensions' counters.
func (r *RateLimiter) RecordFailure(ctx context.Context, username, sourceIP string) error {
	if username != "" {
		if err := r.Lockouts.RecordFailure(ctx, r.userKey(username), r.Params); err != nil {
			return err
		}
	}
	if sourceIP != "" {
		if err := r.Lockouts.RecordFailure(ctx, r.ipKey(sourceIP), r.Params); err != nil {
			return err
		}
	}
	return nil
}

// RecordSuccess clears both dimensions' counters.
func (r *RateLimiter) RecordSuccess(ctx context.Context, username, sourceIP string) error {
	if username != "" {
		if err := r.Lockouts.Reset(ctx, r.userKey(username)); err != nil {
			return err
		}
	}
	if sourceIP != "" {
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
