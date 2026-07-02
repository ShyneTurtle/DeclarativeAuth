//go:build integration

package integration

import (
	"context"
	"net"
	"sort"
	"testing"
	"time"

	"declarativeauth/internal/config"
	"declarativeauth/internal/ldapserver"

	goldap "github.com/go-ldap/ldap/v3"
)

const testPepper = "integration-test-pepper"

func startLDAPServer(t *testing.T, identityFixture string) (addr string, holder *config.SnapshotHolder) {
	t.Helper()
	pool := setupPool(t)

	holder = &config.SnapshotHolder{}
	snap, err := config.LoadIdentity(fixturePath(identityFixture))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	holder.Set(snap)

	authenticator := buildAuthenticator(pool, holder, testPepper, defaultLockoutParams())

	// Seed jsmith's password directly via the same credential store the
	// server reads from.
	encoded, err := authenticator.Hasher.Hash("Secret123!")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := authenticator.Credentials.Upsert(context.Background(), "jsmith", encoded); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	handler := &ldapserver.Handler{
		Config:        ldapserver.Config{BaseDN: "dc=example,dc=com", AllowAnonymousBind: false},
		Snapshot:      holder.Get,
		Authenticator: authenticator,
	}
	srv := &ldapserver.Server{Handler: handler}

	addr = freePort(t)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx, ln)
	time.Sleep(50 * time.Millisecond) // let the accept loop start
	return addr, holder
}

func fixturePath(name string) string {
	return "../fixtures/" + name
}

func TestLDAP_BindSuccess(t *testing.T) {
	addr, _ := startLDAPServer(t, "valid")
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()

	if err := l.Bind("uid=jsmith,ou=users,dc=example,dc=com", "Secret123!"); err != nil {
		t.Fatalf("expected bind to succeed, got %v", err)
	}
}

func TestLDAP_BindFailure_WrongPassword(t *testing.T) {
	addr, _ := startLDAPServer(t, "valid")
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()

	err = l.Bind("uid=jsmith,ou=users,dc=example,dc=com", "wrong-password")
	if err == nil {
		t.Fatal("expected bind to fail")
	}
	if !goldap.IsErrorWithCode(err, goldap.LDAPResultInvalidCredentials) {
		t.Fatalf("expected invalid credentials error, got %v", err)
	}
}

func TestLDAP_BindFailure_DisabledUser(t *testing.T) {
	addr, _ := startLDAPServer(t, "valid")
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()

	// contractor1 is enabled: false in the fixture; it has no credential row
	// at all, so bind must fail regardless of the (nonexistent) password.
	err = l.Bind("uid=contractor1,ou=users,dc=example,dc=com", "anything")
	if err == nil {
		t.Fatal("expected bind to fail for disabled user")
	}
}

func TestLDAP_Search_FlattenedMemberOf_Diamond(t *testing.T) {
	addr, _ := startLDAPServer(t, "valid")
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()

	if err := l.Bind("uid=jsmith,ou=users,dc=example,dc=com", "Secret123!"); err != nil {
		t.Fatalf("bind: %v", err)
	}

	// contractor1 (disabled) is also transitively in engineering via
	// platform-team, so both users are expected to match this filter --
	// LDAP search intentionally does not consider the enabled flag (only
	// bind does); narrow to jsmith specifically via AND.
	req := goldap.NewSearchRequest(
		"ou=users,dc=example,dc=com",
		goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 0, 0, false,
		"(&(uid=jsmith)(memberOf=cn=engineering,ou=groups,dc=example,dc=com))",
		[]string{"uid", "memberOf"},
		nil,
	)
	res, err := l.Search(req)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("expected 1 entry (jsmith, via oncall diamond into engineering), got %d", len(res.Entries))
	}
	got := res.Entries[0].GetAttributeValues("uid")
	if len(got) != 1 || got[0] != "jsmith" {
		t.Fatalf("expected jsmith, got %v", got)
	}

	memberOf := res.Entries[0].GetAttributeValues("memberOf")
	sort.Strings(memberOf)
	want := []string{
		"cn=backend-team,ou=groups,dc=example,dc=com",
		"cn=engineering,ou=groups,dc=example,dc=com",
		"cn=oncall,ou=groups,dc=example,dc=com",
		"cn=platform-team,ou=groups,dc=example,dc=com",
	}
	if len(memberOf) != len(want) {
		t.Fatalf("got memberOf %v, want %v", memberOf, want)
	}
	for i := range want {
		if memberOf[i] != want[i] {
			t.Fatalf("got memberOf %v, want %v", memberOf, want)
		}
	}
}

func TestLDAP_Search_RequiresBindFirst(t *testing.T) {
	addr, _ := startLDAPServer(t, "valid")
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()

	req := goldap.NewSearchRequest(
		"ou=users,dc=example,dc=com",
		goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 0, 0, false,
		"(uid=jsmith)", []string{"uid"}, nil,
	)
	_, err = l.Search(req)
	if err == nil {
		t.Fatal("expected search without prior bind to fail")
	}
}

func TestLDAP_CycleFixtureRejectedAtLoad(t *testing.T) {
	_, err := config.LoadIdentity(fixturePath("cycle"))
	if err == nil {
		t.Fatal("expected cycle fixture to fail to load")
	}
}
