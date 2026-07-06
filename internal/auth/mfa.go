package auth

import (
	"context"

	"declarativeauth/internal/identity"
	"declarativeauth/internal/store"
)

// MFAPolicy resolves whether a user must complete email-based MFA at
// login, combining the two independent sources that can require it: the
// declarative identity snapshot (a group's RequireMFA, or a user's own
// MFAEnabled override -- see identity.Snapshot.MFARequiredByDeclaration)
// and a user's own self-service preference, stored in Postgres since it
// isn't part of the declarative config. Either source alone is sufficient;
// a user can always turn MFA on for themselves even when not declaratively
// required, but can never turn off a declaratively-required MFA.
type MFAPolicy struct {
	Snapshot func() *identity.Snapshot
	Settings *store.UserMFASettingsStore
}

// Required reports whether username must complete email MFA at login.
func (p *MFAPolicy) Required(ctx context.Context, username string) (bool, error) {
	if p.Snapshot().MFARequiredByDeclaration(username) {
		return true, nil
	}
	if p.Settings == nil {
		return false, nil
	}
	return p.Settings.IsEnabled(ctx, username)
}
