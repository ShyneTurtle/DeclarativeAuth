package auth

import "testing"

func TestRateLimiter_KeyPrefixNamespacesKeys(t *testing.T) {
	r := &RateLimiter{KeyPrefix: "reset:"}
	if got := r.userKey("jsmith"); got != "reset:user:jsmith" {
		t.Fatalf("expected namespaced user key, got %q", got)
	}
	if got := r.ipKey("203.0.113.1"); got != "reset:ip:203.0.113.1" {
		t.Fatalf("expected namespaced IP key, got %q", got)
	}

	unprefixed := &RateLimiter{}
	if got := unprefixed.userKey("jsmith"); got != "user:jsmith" {
		t.Fatalf("expected unprefixed user key to match the pre-existing login_lockouts key format, got %q", got)
	}
}
