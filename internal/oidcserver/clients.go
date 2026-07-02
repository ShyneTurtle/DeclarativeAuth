package oidcserver

import "declarativeauth/internal/config"

// ClientRegistry is the statically declared set of OIDC relying parties.
type ClientRegistry struct {
	byID map[string]config.OIDCClient
}

// NewClientRegistry builds a registry from the server config's oidc.clients list.
func NewClientRegistry(clients []config.OIDCClient) *ClientRegistry {
	r := &ClientRegistry{byID: map[string]config.OIDCClient{}}
	for _, c := range clients {
		r.byID[c.ClientID] = c
	}
	return r
}

// Get returns the client and whether it exists.
func (r *ClientRegistry) Get(clientID string) (config.OIDCClient, bool) {
	c, ok := r.byID[clientID]
	return c, ok
}

// RedirectURIAllowed reports whether uri is a registered redirect URI for client.
func RedirectURIAllowed(c config.OIDCClient, uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}
