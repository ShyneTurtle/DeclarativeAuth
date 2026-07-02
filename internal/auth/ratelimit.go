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
}

// IsLocked reports whether either the account or the source IP is currently
// locked out.
func (r *RateLimiter) IsLocked(ctx context.Context, username, sourceIP string) (bool, error) {
	if username != "" {
		locked, err := r.Lockouts.IsLocked(ctx, "user:"+username)
		if err != nil || locked {
			return locked, err
		}
	}
	if sourceIP != "" {
		return r.Lockouts.IsLocked(ctx, "ip:"+sourceIP)
	}
	return false, nil
}

// RecordFailure increments both dimensions' counters.
func (r *RateLimiter) RecordFailure(ctx context.Context, username, sourceIP string) error {
	if username != "" {
		if err := r.Lockouts.RecordFailure(ctx, "user:"+username, r.Params); err != nil {
			return err
		}
	}
	if sourceIP != "" {
		if err := r.Lockouts.RecordFailure(ctx, "ip:"+sourceIP, r.Params); err != nil {
			return err
		}
	}
	return nil
}

// RecordSuccess clears both dimensions' counters.
func (r *RateLimiter) RecordSuccess(ctx context.Context, username, sourceIP string) error {
	if username != "" {
		if err := r.Lockouts.Reset(ctx, "user:"+username); err != nil {
			return err
		}
	}
	if sourceIP != "" {
		if err := r.Lockouts.Reset(ctx, "ip:"+sourceIP); err != nil {
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
