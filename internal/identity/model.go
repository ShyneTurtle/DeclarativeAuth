// Package identity holds the core, DB-independent domain model: users, groups,
// and their resolved (flattened) group membership.
package identity

import "time"

// Group is a declared group, optionally itself a member of parent groups.
type Group struct {
	Name           string
	Description    string
	MemberOfGroups []string
	// RequireMFA, when true, means every member of this group -- direct or
	// transitive, same as any other membership property -- must complete
	// email-based MFA at login. See Snapshot.MFARequiredByDeclaration.
	RequireMFA bool
}

// User is a declared user with direct group memberships.
type User struct {
	Username       string
	Email          string
	FirstName      string
	Name           string
	DisplayName    string
	Enabled        bool
	MemberOfGroups []string
	// MFAEnabled declaratively forces email-based MFA on for this specific
	// user, regardless of group membership. This is separate from a user's
	// own self-service MFA preference (stored in Postgres, not here): the
	// declarative flag can only turn MFA on, never override a self-service
	// opt-in off.
	MFAEnabled bool
}

// DisplayNameOrDefault returns the user's explicit DisplayName if set,
// otherwise "FirstName Name" (whichever half is present), falling back to
// the username if neither is declared. This is the single source of truth
// for the LDAP "cn" attribute and the OIDC "name" claim, so both stay
// consistent.
func (u User) DisplayNameOrDefault() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	switch {
	case u.FirstName != "" && u.Name != "":
		return u.FirstName + " " + u.Name
	case u.FirstName != "":
		return u.FirstName
	case u.Name != "":
		return u.Name
	default:
		return u.Username
	}
}

// Snapshot is an immutable, fully-resolved view of the declarative identity
// config at a point in time. A new Snapshot is built on every successful
// config load/reload and swapped in atomically.
type Snapshot struct {
	Users             map[string]User
	Groups            map[string]Group
	FlattenedMemberOf map[string][]string
	LoadedAt          time.Time
	SourceHash        string
}

// IsMemberOf reports whether username is (transitively) a member of group.
func (s *Snapshot) IsMemberOf(username, group string) bool {
	for _, g := range s.FlattenedMemberOf[username] {
		if g == group {
			return true
		}
	}
	return false
}

// MFARequiredByDeclaration reports whether username is required to
// complete email-based MFA purely by declarative configuration: either
// their own User.MFAEnabled override, or membership (direct or transitive)
// in any group with Group.RequireMFA set. This does not account for a
// user's own self-service MFA preference, which lives in Postgres, not the
// declarative snapshot -- see auth.MFAPolicy for the combined decision.
func (s *Snapshot) MFARequiredByDeclaration(username string) bool {
	if u, ok := s.Users[username]; ok && u.MFAEnabled {
		return true
	}
	for _, g := range s.FlattenedMemberOf[username] {
		if grp, ok := s.Groups[g]; ok && grp.RequireMFA {
			return true
		}
	}
	return false
}

// UsernameForEmail finds the username whose declared email matches (linear
// scan; the identity set is small and this only runs on the reset/setup
// email-lookup path, not the login hot path).
func (s *Snapshot) UsernameForEmail(email string) (string, bool) {
	for username, u := range s.Users {
		if u.Email == email {
			return username, true
		}
	}
	return "", false
}

// ResolveIdentifier maps a user-supplied identifier -- typed into a login
// or password-reset form, so it could be either a username or an email --
// to the canonical username. An exact username match wins first (so a
// username that happens to look like an email still resolves to itself),
// falling back to a declared email match. This is the single place that
// definition lives, shared by every flow that accepts "username or email"
// (login, password reset) so they can never disagree on which account a
// given identifier means.
func (s *Snapshot) ResolveIdentifier(identifier string) (username string, ok bool) {
	if _, exists := s.Users[identifier]; exists {
		return identifier, true
	}
	if u, exists := s.UsernameForEmail(identifier); exists {
		return u, true
	}
	return identifier, false
}
