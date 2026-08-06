package oidcserver

import "declarativeauth/internal/identity"

// RedirectURIAllowed reports whether uri is a registered redirect URI for client.
func RedirectURIAllowed(c identity.OIDCClient, uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// PostLogoutRedirectURIAllowed reports whether uri is a registered
// post-logout redirect URI for client (RP-Initiated Logout).
func PostLogoutRedirectURIAllowed(c identity.OIDCClient, uri string) bool {
	for _, u := range c.PostLogoutRedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}
