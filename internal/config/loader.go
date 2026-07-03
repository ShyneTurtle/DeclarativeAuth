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
// under dir, validates them, and returns a fully-resolved Snapshot.
func LoadIdentity(dir string) (*identity.Snapshot, error) {
	groupFiles, err := globOrSingle(dir, "groups.yaml", "groups.d")
	if err != nil {
		return nil, err
	}
	userFiles, err := globOrSingle(dir, "users.yaml", "users.d")
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
		FlattenedMemberOf: flattened,
		LoadedAt:          time.Now(),
		SourceHash:        hashBytes(rawBytes),
	}, nil
}

// globOrSingle returns [dir/single] if it exists, else dir/dirName/*.yaml.
func globOrSingle(dir, single, dirName string) ([]string, error) {
	singlePath := filepath.Join(dir, single)
	if _, err := os.Stat(singlePath); err == nil {
		return []string{singlePath}, nil
	}
	matches, err := filepath.Glob(filepath.Join(dir, dirName, "*.yaml"))
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("neither %s nor %s/*.yaml found under %s", single, dirName, dir)
	}
	return matches, nil
}
