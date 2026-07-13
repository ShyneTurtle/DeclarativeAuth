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
