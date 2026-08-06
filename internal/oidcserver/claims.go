package oidcserver

import (
	"strings"

	"declarativeauth/internal/identity"
)

// Claims builds the standard + "groups" claim set for a user from the
// current snapshot, gated by the granted scope (OIDC Core §5.4 least-
// disclosure: a client that only requested "openid" gets just sub, not
// profile/email/groups it never asked for), shared between ID tokens and
// the userinfo endpoint so OIDC relying parties see the exact same
// flattened-group view LDAP clients get (Section 7 consistency guarantee).
func Claims(snap *identity.Snapshot, username, scope string) map[string]any {
	u := snap.Users[username]
	has := hasScope(scope)

	claims := map[string]any{"sub": username}
	if has("profile") {
		claims["preferred_username"] = u.Username
		claims["name"] = u.DisplayNameOrDefault()
		claims["given_name"] = u.FirstName
		claims["family_name"] = u.Name
	}
	if has("email") {
		claims["email"] = u.Email
	}
	if has("groups") {
		claims["groups"] = snap.FlattenedMemberOf[username]
	}
	return claims
}

// hasScope returns a lookup closure over scope's space-separated tokens.
func hasScope(scope string) func(want string) bool {
	tokens := strings.Fields(scope)
	return func(want string) bool {
		for _, t := range tokens {
			if t == want {
				return true
			}
		}
		return false
	}
}
