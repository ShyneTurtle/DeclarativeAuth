package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"declarativeauth/internal/identity"

	"sigs.k8s.io/yaml"
)

// LoadIdentity reads users.yaml/groups.yaml (or users.d/*.yaml, groups.d/*.yaml)
// and the optional oidc-clients.yaml (or oidc-clients.d/*.yaml) under dir,
// validates them, and returns a fully-resolved Snapshot.
func LoadIdentity(dir string) (*identity.Snapshot, error) {
	groupFiles, err := globOrSingle(dir, "groups.yaml", "groups.d", true)
	if err != nil {
		return nil, err
	}
	userFiles, err := globOrSingle(dir, "users.yaml", "users.d", true)
	if err != nil {
		return nil, err
	}
	// Optional: unlike users/groups, an OIDC-less deployment (LDAP-only, or
	// no relying parties registered yet) is entirely normal, so a missing
	// oidc-clients.yaml just means zero clients, not an error.
	clientFiles, err := globOrSingle(dir, "oidc-clients.yaml", "oidc-clients.d", false)
	if err != nil {
		return nil, err
	}

	groups := map[string]identity.Group{}
	var rawBytes []byte
	for _, f := range groupFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f, err)
		}
		rawBytes = append(rawBytes, b...)
		var gf GroupFile
		if err := yaml.UnmarshalStrict(b, &gf); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", f, err)
		}
		for _, g := range gf.Groups {
			if g.Name == "" {
				return nil, fmt.Errorf("%s: group with empty name", f)
			}
			if _, exists := groups[g.Name]; exists {
				return nil, fmt.Errorf("%s: duplicate group name %q", f, g.Name)
			}
			groups[g.Name] = identity.Group{
				Name:           g.Name,
				Description:    g.Description,
				MemberOfGroups: g.MemberOfGroups,
				RequireMFA:     g.RequireMFA,
			}
		}
	}

	users := map[string]identity.User{}
	emails := map[string]string{}
	for _, f := range userFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f, err)
		}
		rawBytes = append(rawBytes, b...)
		var uf UserFile
		if err := yaml.UnmarshalStrict(b, &uf); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", f, err)
		}
		for _, u := range uf.Users {
			if u.Username == "" {
				return nil, fmt.Errorf("%s: user with empty username", f)
			}
			if _, exists := users[u.Username]; exists {
				return nil, fmt.Errorf("%s: duplicate username %q", f, u.Username)
			}
			if u.Email != "" {
				if existing, ok := emails[u.Email]; ok {
					return nil, fmt.Errorf("%s: duplicate email %q (users %q and %q)", f, u.Email, existing, u.Username)
				}
				emails[u.Email] = u.Username
			}
			enabled := true
			if u.Enabled != nil {
				enabled = *u.Enabled
			}
			users[u.Username] = identity.User{
				Username:       u.Username,
				Email:          u.Email,
				FirstName:      u.FirstName,
				Name:           u.Name,
				DisplayName:    u.DisplayName,
				Enabled:        enabled,
				MemberOfGroups: u.MemberOfGroups,
				MFAEnabled:     u.MFAEnabled,
			}
		}
	}

	oidcClients := map[string]identity.OIDCClient{}
	for _, f := range clientFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f, err)
		}
		rawBytes = append(rawBytes, b...)
		var cf OIDCClientFile
		if err := yaml.UnmarshalStrict(b, &cf); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", f, err)
		}
		for _, c := range cf.Clients {
			if c.ClientID == "" {
				return nil, fmt.Errorf("%s: OIDC client with empty clientID", f)
			}
			if _, exists := oidcClients[c.ClientID]; exists {
				return nil, fmt.Errorf("%s: duplicate OIDC clientID %q", f, c.ClientID)
			}
			if len(c.RedirectURIs) == 0 {
				return nil, fmt.Errorf("%s: OIDC client %q has no redirectURIs", f, c.ClientID)
			}
			if !c.Public && c.ClientSecret == "" {
				return nil, fmt.Errorf("%s: confidential OIDC client %q (public: false) must set clientSecret", f, c.ClientID)
			}
			oidcClients[c.ClientID] = identity.OIDCClient{
				ClientID:     c.ClientID,
				RedirectURIs: c.RedirectURIs,
				Public:       c.Public,
				ClientSecret: c.ClientSecret,
			}
		}
	}

	if err := identity.CheckReferences(users, groups); err != nil {
		return nil, err
	}
	if err := identity.DetectCycle(groups); err != nil {
		return nil, err
	}

	flattened := identity.ResolveFlattenedMemberOf(users, groups)

	return &identity.Snapshot{
		Users:             users,
		Groups:            groups,
		OIDCClients:       oidcClients,
		FlattenedMemberOf: flattened,
		LoadedAt:          time.Now(),
		SourceHash:        hashBytes(rawBytes),
	}, nil
}

// globOrSingle returns [dir/single] if it exists, else dir/dirName/*.yaml.
// If required is false and neither exists, it returns (nil, nil) instead of
// an error.
func globOrSingle(dir, single, dirName string, required bool) ([]string, error) {
	singlePath := filepath.Join(dir, single)
	if _, err := os.Stat(singlePath); err == nil {
		return []string{singlePath}, nil
	}
	matches, err := filepath.Glob(filepath.Join(dir, dirName, "*.yaml"))
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		if !required {
			return nil, nil
		}
		return nil, fmt.Errorf("neither %s nor %s/*.yaml found under %s", single, dirName, dir)
	}
	return matches, nil
}
