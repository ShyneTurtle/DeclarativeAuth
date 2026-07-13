//go:build integration

package integration

import (
	"context"
	"net"
	"testing"
	"time"

	"declarativeauth/internal/config"
	"declarativeauth/internal/ldapserver"

	goldap "github.com/go-ldap/ldap/v3"
)

// startLDAPServerNoSeeding is like startLDAPServer but deliberately seeds no
// Postgres credential for anyone -- proving that a declaratively-hashed
// user (passwordHash/passwordHashFile) can log in purely from the identity
// snapshot, with zero imperative bootstrap step (the whole point of this
// feature: no init container running `admin set-password` needed).
func startLDAPServerNoSeeding(t *testing.T, identityFixture string) (addr string, holder *config.SnapshotHolder) {
	t.Helper()
	pool := setupPool(t)

	holder = &config.SnapshotHolder{}
	snap, err := config.LoadIdentity(fixturePath(identityFixture))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	holder.Set(snap)

	authenticator := buildAuthenticator(pool, holder, defaultLockoutParams())

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
	time.Sleep(50 * time.Millisecond)
	return addr, holder
}

func TestLDAP_BindSuccess_DeclarativePasswordHashFile(t *testing.T) {
	addr, _ := startLDAPServerNoSeeding(t, "password-hash")
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()

	if err := l.Bind("uid=svc-ldap,ou=users,dc=example,dc=com", "Secret123!"); err != nil {
		t.Fatalf("expected bind to succeed purely from passwordHashFile (no Postgres credential seeded), got %v", err)
	}
}

func TestLDAP_BindSuccess_DeclarativePasswordHashInline(t *testing.T) {
	addr, _ := startLDAPServerNoSeeding(t, "password-hash")
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()

	if err := l.Bind("uid=svc-inline,ou=users,dc=example,dc=com", "Secret123!"); err != nil {
		t.Fatalf("expected bind to succeed purely from inline passwordHash, got %v", err)
	}
}

func TestLDAP_BindFailure_DeclarativePasswordHashWrongPassword(t *testing.T) {
	addr, _ := startLDAPServerNoSeeding(t, "password-hash")
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()

	err = l.Bind("uid=svc-ldap,ou=users,dc=example,dc=com", "wrong-password")
	if err == nil {
		t.Fatal("expected bind to fail for wrong password against a declarative hash")
	}
	if !goldap.IsErrorWithCode(err, goldap.LDAPResultInvalidCredentials) {
		t.Fatalf("expected invalid credentials error, got %v", err)
	}
}

func TestLDAP_BindFailure_NoDeclarativeHashAndNoPostgresCredential(t *testing.T) {
	addr, _ := startLDAPServerNoSeeding(t, "password-hash")
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()

	// normaluser has no declarative passwordHash and (in this test) no
	// Postgres credential either -- must fail the same way it always did,
	// confirming the fallback path still works unmodified.
	err = l.Bind("uid=normaluser,ou=users,dc=example,dc=com", "anything")
	if err == nil {
		t.Fatal("expected bind to fail for a user with neither a declarative hash nor a Postgres credential")
	}
}
