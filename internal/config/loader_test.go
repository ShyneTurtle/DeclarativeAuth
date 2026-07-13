package config

import (
	"os"
	"path/filepath"
	"testing"
)

func fixture(name string) string {
	return filepath.Join("..", "..", "test", "fixtures", name)
}

// withUsersAndGroups writes the "valid" fixture's users.yaml/groups.yaml
// (required by LoadIdentity) into a fresh temp dir, then oidc-clients.yaml
// content on top, so oidc-clients-specific tests don't need their own
// dedicated users.yaml/groups.yaml fixtures.
func withUsersAndGroups(t *testing.T, oidcClientsYAML string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"users.yaml", "groups.yaml"} {
		b, err := os.ReadFile(filepath.Join(fixture("valid"), name))
		if err != nil {
			t.Fatalf("read fixture %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if oidcClientsYAML != "" {
		if err := os.WriteFile(filepath.Join(dir, "oidc-clients.yaml"), []byte(oidcClientsYAML), 0o644); err != nil {
			t.Fatalf("write oidc-clients.yaml: %v", err)
		}
	}
	return dir
}

func TestLoadIdentity_Valid(t *testing.T) {
	snap, err := LoadIdentity(fixture("valid"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snap.Users) != 3 {
		t.Fatalf("expected 3 users, got %d", len(snap.Users))
	}
	if len(snap.Groups) != 5 {
		t.Fatalf("expected 5 groups, got %d", len(snap.Groups))
	}
	// jsmith is in oncall -> backend-team + platform-team -> engineering (diamond)
	want := []string{"backend-team", "engineering", "oncall", "platform-team"}
	got := snap.FlattenedMemberOf["jsmith"]
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if snap.Users["contractor1"].Enabled {
		t.Fatal("expected contractor1 to be disabled")
	}
}

func TestLoadIdentity_Cycle(t *testing.T) {
	_, err := LoadIdentity(fixture("cycle"))
	if err == nil {
		t.Fatal("expected cycle error, got nil")
	}
}

func TestLoadIdentity_MissingDir(t *testing.T) {
	_, err := LoadIdentity(fixture("does-not-exist"))
	if err == nil {
		t.Fatal("expected error for missing directory, got nil")
	}
}

func TestLoadIdentity_MFAFields(t *testing.T) {
	snap, err := LoadIdentity(fixture("mfa"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !snap.Groups["secure-team"].RequireMFA {
		t.Fatal("expected secure-team.RequireMFA to be true")
	}
	if snap.Groups["regular-team"].RequireMFA {
		t.Fatal("expected regular-team.RequireMFA to be false")
	}
	if !snap.Users["byuserflag"].MFAEnabled {
		t.Fatal("expected byuserflag.MFAEnabled to be true")
	}
	if snap.Users["nomfa"].MFAEnabled {
		t.Fatal("expected nomfa.MFAEnabled to be false")
	}

	if !snap.MFARequiredByDeclaration("bysecuregroup") {
		t.Fatal("expected bysecuregroup to require MFA via group membership")
	}
	if !snap.MFARequiredByDeclaration("byuserflag") {
		t.Fatal("expected byuserflag to require MFA via per-user override")
	}
	if snap.MFARequiredByDeclaration("nomfa") {
		t.Fatal("expected nomfa to not require MFA")
	}
}

func TestLoadIdentity_OIDCClientsAbsent(t *testing.T) {
	snap, err := LoadIdentity(withUsersAndGroups(t, ""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snap.OIDCClients) != 0 {
		t.Fatalf("expected no OIDC clients when oidc-clients.yaml is absent, got %d", len(snap.OIDCClients))
	}
}

func TestLoadIdentity_OIDCClientsValid(t *testing.T) {
	snap, err := LoadIdentity(withUsersAndGroups(t, `
apiVersion: declarativeauth.io/v1
kind: OIDCClientList
clients:
  - clientID: spa
    redirectURIs: ["http://localhost:9000/callback"]
    public: true
  - clientID: confidential
    redirectURIs: ["https://app.example.com/callback"]
    public: false
    clientSecret: s3cret
`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snap.OIDCClients) != 2 {
		t.Fatalf("expected 2 OIDC clients, got %d", len(snap.OIDCClients))
	}
	spa, ok := snap.OIDCClients["spa"]
	if !ok || !spa.Public || len(spa.RedirectURIs) != 1 || spa.RedirectURIs[0] != "http://localhost:9000/callback" {
		t.Errorf("unexpected spa client: %+v", spa)
	}
	conf, ok := snap.OIDCClients["confidential"]
	if !ok || conf.Public || conf.ClientSecret != "s3cret" {
		t.Errorf("unexpected confidential client: %+v", conf)
	}
}

func TestLoadIdentity_OIDCClientsDuplicateID(t *testing.T) {
	_, err := LoadIdentity(withUsersAndGroups(t, `
apiVersion: declarativeauth.io/v1
kind: OIDCClientList
clients:
  - clientID: dup
    redirectURIs: ["http://a.example.com/callback"]
    public: true
  - clientID: dup
    redirectURIs: ["http://b.example.com/callback"]
    public: true
`))
	if err == nil {
		t.Fatal("expected error for duplicate clientID, got nil")
	}
}

func TestLoadIdentity_OIDCClientsNoRedirectURIs(t *testing.T) {
	_, err := LoadIdentity(withUsersAndGroups(t, `
apiVersion: declarativeauth.io/v1
kind: OIDCClientList
clients:
  - clientID: no-redirects
    redirectURIs: []
    public: true
`))
	if err == nil {
		t.Fatal("expected error for a client with no redirectURIs, got nil")
	}
}

func TestLoadIdentity_OIDCClientsConfidentialWithoutSecret(t *testing.T) {
	_, err := LoadIdentity(withUsersAndGroups(t, `
apiVersion: declarativeauth.io/v1
kind: OIDCClientList
clients:
  - clientID: no-secret
    redirectURIs: ["https://app.example.com/callback"]
    public: false
`))
	if err == nil {
		t.Fatal("expected error for a confidential client without a clientSecret, got nil")
	}
}

// TestLoadIdentity_ArbitraryLayout is the core of the "no hardcoded
// filenames" behavior: content split across nested subdirectories with
// non-conventional names, discovered purely by each file's own
// apiVersion/kind header, plus an unrelated YAML file (no recognized
// header at all) mixed in that must be silently ignored rather than
// erroring.
func TestLoadIdentity_ArbitraryLayout(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	write("teams/engineering.yaml", `
apiVersion: declarativeauth.io/v1
kind: GroupList
groups:
  - name: engineering
    memberOfGroups: []
`)
	write("people/jsmith.yml", `
apiVersion: declarativeauth.io/v1
kind: UserList
users:
  - username: jsmith
    email: jsmith@example.com
    enabled: true
    memberOfGroups: [engineering]
`)
	write("apps/spa.yaml", `
apiVersion: declarativeauth.io/v1
kind: OIDCClientList
clients:
  - clientID: spa
    redirectURIs: ["http://localhost:9000/callback"]
    public: true
`)
	// Unrelated YAML: valid YAML, but no recognized header at all -- must
	// not cause an error and must not be mistaken for one of ours.
	write("notes/README.yaml", "title: just some notes\nnotAConfigFile: true\n")

	snap, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snap.Groups) != 1 || snap.Groups["engineering"].Name != "engineering" {
		t.Fatalf("expected 1 group 'engineering', got %+v", snap.Groups)
	}
	if len(snap.Users) != 1 || snap.Users["jsmith"].Email != "jsmith@example.com" {
		t.Fatalf("expected 1 user 'jsmith', got %+v", snap.Users)
	}
	if len(snap.OIDCClients) != 1 {
		t.Fatalf("expected 1 OIDC client, got %+v", snap.OIDCClients)
	}
}

// TestLoadIdentity_IgnoresWrongAPIVersion covers a file that looks almost
// right (has apiVersion/kind, valid YAML) but declares a different
// apiVersion -- must be ignored, not misinterpreted.
func TestLoadIdentity_IgnoresWrongAPIVersion(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "users.yaml"), []byte(`
apiVersion: something-else/v2
kind: UserList
users:
  - username: shouldnotload
    enabled: true
`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	snap, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snap.Users) != 0 {
		t.Fatalf("expected the mismatched-apiVersion file to be ignored, got users: %+v", snap.Users)
	}
}

// TestLoadIdentity_EmptyDirNoError covers the "zero users is not a load
// error" requirement -- LoadIdentity itself stays silent about it (callers
// like the watcher and the CLI are responsible for warning).
func TestLoadIdentity_EmptyDirNoError(t *testing.T) {
	snap, err := LoadIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error for an empty identity dir: %v", err)
	}
	if len(snap.Users) != 0 || len(snap.Groups) != 0 || len(snap.OIDCClients) != 0 {
		t.Fatalf("expected an entirely empty snapshot, got %+v", snap)
	}
}

// TestLoadIdentity_SkipsKubernetesConfigMapInternals simulates the layout
// Kubernetes actually mounts a ConfigMap volume as: a "..data" symlink to a
// timestamped real directory holding the actual content, plus one symlink
// per key at the mount root pointing through "..data". Without skipping
// dot-prefixed directories, walking into the timestamped directory would
// visit every file a second time and every entry would come back
// "duplicate".
func TestLoadIdentity_SkipsKubernetesConfigMapInternals(t *testing.T) {
	dir := t.TempDir()
	backing := filepath.Join(dir, "..2024_01_01_00_00_00.000000000")
	if err := os.Mkdir(backing, 0o755); err != nil {
		t.Fatalf("mkdir backing: %v", err)
	}
	usersYAML := `
apiVersion: declarativeauth.io/v1
kind: UserList
users:
  - username: jsmith
    enabled: true
`
	if err := os.WriteFile(filepath.Join(backing, "users.yaml"), []byte(usersYAML), 0o644); err != nil {
		t.Fatalf("write backing users.yaml: %v", err)
	}
	dataLink := filepath.Join(dir, "..data")
	if err := os.Symlink(backing, dataLink); err != nil {
		t.Skipf("symlinks unavailable in this environment: %v", err)
	}
	if err := os.Symlink(filepath.Join("..data", "users.yaml"), filepath.Join(dir, "users.yaml")); err != nil {
		t.Fatalf("symlink users.yaml: %v", err)
	}

	snap, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snap.Users) != 1 {
		t.Fatalf("expected exactly 1 user (no duplicate via ..data traversal), got %d: %+v", len(snap.Users), snap.Users)
	}
}
