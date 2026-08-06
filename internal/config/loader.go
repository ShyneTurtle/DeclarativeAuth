package config

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"declarativeauth/internal/auth"
	"declarativeauth/internal/identity"

	"sigs.k8s.io/yaml"
)

// configAPIVersion is the apiVersion every recognized declarative config
// file must declare, alongside a recognized "kind" (see loadFile below).
const configAPIVersion = "declarativeauth.io/v1"

// fileHeader is the minimal shape peeked at to decide whether a YAML file
// under the identity directory is one of ours, and if so, which kind.
type fileHeader struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

// LoadIdentity recursively scans every .yaml/.yml file under dir (skipping
// dotfiles/dot-directories, e.g. Kubernetes ConfigMap/Secret's internal
// "..data" symlink and timestamped backing directories), parses the ones
// carrying a recognized header (apiVersion: declarativeauth.io/v1, kind:
// UserList | GroupList | OIDCClientList), and returns a fully-resolved
// Snapshot. A file without a recognized header -- wrong/missing apiVersion,
// unknown kind, or not even valid YAML -- is silently ignored, so the
// identity directory can be organized however you like: any file names,
// nested subdirectories, unrelated YAML mixed in. A file that DOES declare
// a recognized header is held to strict validation, though -- typos in a
// file that claims to be ours are a real error, not something to ignore.
//
// Both users.yaml-equivalent and groups.yaml-equivalent content are
// optional: zero declared groups is fine as long as no user references
// one (see identity.CheckReferences), and zero declared users doesn't fail
// the load at all -- callers (the CLI, the hot-reload watcher) are
// expected to warn about that themselves, since "no one can log in yet" is
// a legitimate transient state (e.g. bootstrapping a fresh deployment)
// rather than a config error.
func LoadIdentity(dir string) (*identity.Snapshot, error) {
	files, err := yamlFilesUnder(dir)
	if err != nil {
		return nil, err
	}

	groups := map[string]identity.Group{}
	users := map[string]identity.User{}
	emails := map[string]string{}
	oidcClients := map[string]identity.OIDCClient{}
	var rawBytes []byte

	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f, err)
		}

		var hdr fileHeader
		if err := yaml.Unmarshal(b, &hdr); err != nil {
			continue // not a YAML mapping we can even inspect -- not ours
		}
		if hdr.APIVersion != configAPIVersion {
			continue
		}

		switch hdr.Kind {
		case "GroupList":
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

		case "UserList":
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
				passwordHash, hashSourceBytes, err := resolvePasswordHash(dir, f, u)
				if err != nil {
					return nil, err
				}
				rawBytes = append(rawBytes, hashSourceBytes...)
				users[u.Username] = identity.User{
					Username:       u.Username,
					Email:          u.Email,
					FirstName:      u.FirstName,
					Name:           u.Name,
					DisplayName:    u.DisplayName,
					Enabled:        enabled,
					MemberOfGroups: u.MemberOfGroups,
					MFAEnabled:     u.MFAEnabled,
					PasswordHash:   passwordHash,
				}
			}

		case "OIDCClientList":
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
					ClientID:               c.ClientID,
					RedirectURIs:           c.RedirectURIs,
					PostLogoutRedirectURIs: c.PostLogoutRedirectURIs,
					Public:                 c.Public,
					ClientSecret:           c.ClientSecret,
				}
			}

		default:
			continue // recognized apiVersion, but not a kind this build knows -- ignore
		}

		rawBytes = append(rawBytes, b...)
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
		FlattenedMembers:  identity.ResolveFlattenedMembers(flattened),
		LoadedAt:          time.Now(),
		SourceHash:        hashBytes(rawBytes),
	}, nil
}

// resolvePasswordHash resolves a UserSpec's PasswordHash/PasswordHashFile
// into the hash string identity.User.PasswordHash should carry, plus the
// raw bytes actually read for it. Those raw bytes get folded into the
// overall SourceHash right alongside the containing file's own bytes, so a
// mounted secret's content -- not just the YAML that references it -- is
// part of what determines whether a reload actually changed anything (a
// rotated secret must count as a change even if users.yaml itself didn't).
func resolvePasswordHash(dir, f string, u UserSpec) (hash string, raw []byte, err error) {
	if u.PasswordHash != "" && u.PasswordHashFile != "" {
		return "", nil, fmt.Errorf("%s: user %q sets both passwordHash and passwordHashFile, use only one", f, u.Username)
	}
	if u.PasswordHash != "" {
		if !auth.ValidHashFormat(u.PasswordHash) {
			return "", nil, fmt.Errorf("%s: user %q passwordHash is not a recognized $argon2id$ hash", f, u.Username)
		}
		return u.PasswordHash, []byte(u.PasswordHash), nil
	}
	if u.PasswordHashFile != "" {
		path := u.PasswordHashFile
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", nil, fmt.Errorf("%s: user %q passwordHashFile %s: %w", f, u.Username, u.PasswordHashFile, err)
		}
		hash := strings.TrimSpace(string(b))
		if !auth.ValidHashFormat(hash) {
			return "", nil, fmt.Errorf("%s: user %q passwordHashFile %s does not contain a recognized $argon2id$ hash", f, u.Username, u.PasswordHashFile)
		}
		return hash, b, nil
	}
	return "", nil, nil
}

// yamlFilesUnder recursively finds every *.yaml/*.yml file under dir, in a
// deterministic (sorted) order so SourceHash is stable across reloads that
// change nothing. Dotfiles and dot-directories are skipped -- most notably
// Kubernetes ConfigMap/Secret volumes, where the mount root contains a
// "..data" symlink (to the real, timestamped backing directory) alongside
// the individual key symlinks at the top level; without this skip, walking
// into "..data" would visit every declared file a second time under a
// different path and every entry would come back "duplicate".
func yamlFilesUnder(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != dir && strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(name, ".") {
			return nil
		}
		switch strings.ToLower(filepath.Ext(name)) {
		case ".yaml", ".yml":
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}
