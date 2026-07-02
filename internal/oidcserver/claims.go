package oidcserver

import "declarativeauth/internal/identity"

// Claims builds the standard + "groups" claim set for a user from the
// current snapshot, shared between ID tokens and the userinfo endpoint so
// OIDC relying parties see the exact same flattened-group view LDAP clients
// get (Section 7 consistency guarantee).
func Claims(snap *identity.Snapshot, username string) map[string]any {
	u := snap.Users[username]
	return map[string]any{
		"sub":                username,
		"preferred_username": u.Username,
		"email":              u.Email,
		"name":               u.DisplayNameOrDefault(),
		"given_name":         u.FirstName,
		"family_name":        u.Name,
		"groups":             snap.FlattenedMemberOf[username],
	}
}
