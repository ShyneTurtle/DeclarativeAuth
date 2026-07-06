package auth

import (
	"context"
	"testing"

	"declarativeauth/internal/identity"
)

func TestMFAPolicy_Required_DeclarativeShortCircuitsBeforeSettings(t *testing.T) {
	snap := &identity.Snapshot{
		Users: map[string]identity.User{
			"forced": {Username: "forced", MFAEnabled: true},
			"plain":  {Username: "plain"},
		},
	}
	policy := &MFAPolicy{Snapshot: func() *identity.Snapshot { return snap }}

	// Settings is nil here: if "forced" didn't short-circuit on the
	// declarative check, this would panic on a nil pointer dereference
	// inside Required, not just return the wrong answer.
	required, err := policy.Required(context.Background(), "forced")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !required {
		t.Fatal("expected declaratively-forced user to require MFA")
	}

	required, err = policy.Required(context.Background(), "plain")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if required {
		t.Fatal("expected non-declared user with no self-service settings store to not require MFA")
	}
}
