//go:build integration

package integration

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"sort"
	"testing"
	"time"

	"declarativeauth/internal/auth"
	"declarativeauth/internal/config"
	"declarativeauth/internal/ldapserver"
	"declarativeauth/internal/store"
	dtls "declarativeauth/internal/tls"

	goldap "github.com/go-ldap/ldap/v3"
)

func startLDAPServer(t *testing.T, identityFixture string, opts ...func(*ldapserver.Config)) (addr string, holder *config.SnapshotHolder) {
	t.Helper()
	pool := setupPool(t)

	holder = &config.SnapshotHolder{}
	snap, err := config.LoadIdentity(fixturePath(identityFixture))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	holder.Set(snap)

	authenticator := buildAuthenticator(pool, holder, defaultLockoutParams())

	// Seed jsmith's password directly via the same credential store the
	// server reads from.
	encoded, err := authenticator.Hasher.Hash("Secret123!")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := authenticator.Credentials.Upsert(context.Background(), "jsmith", encoded, auth.NTHash("Secret123!")); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	cfg := ldapserver.Config{BaseDN: "dc=example,dc=com", AllowAnonymousBind: false}
	for _, opt := range opts {
		opt(&cfg)
	}
	handler := &ldapserver.Handler{
		Config:        cfg,
		Snapshot:      holder.Get,
		Authenticator: authenticator,
		// Wired up unconditionally -- harmless for the tests in this file,
		// none of which set Config.SambaReadersGroup, but required by any
		// test (e.g. samba-privileged search tests) that does.
		Credentials: authenticator.Credentials,
		SambaGroups: &store.SambaGroupStore{Pool: pool},
	}
	tlsSrc, err := dtls.NewSelfSignedSource()
	if err != nil {
		t.Fatalf("self-signed source: %v", err)
	}
	// TLSConfig here mirrors what run.go wires up for the plaintext LDAP
	// listener in production: it's what StartTLS offers mid-connection.
	// The listener itself stays plain TCP -- StartTLS is opt-in per
	// connection, so this doesn't change anything about plaintext bind
	// working exactly as it did before.
	srv := &ldapserver.Server{Handler: handler, TLSConfig: tlsSrc.Config(0)}

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

func TestLDAP_BindSuccess_CaseInsensitiveDN(t *testing.T) {
	addr, _ := startLDAPServer(t, "valid")
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()

	// Attribute types and the "ou=users"/base DN path are case-insensitive
	// per RFC 4514; only the username value itself stays exact-case.
	if err := l.Bind("UID=jsmith,OU=Users,DC=EXAMPLE,DC=COM", "Secret123!"); err != nil {
		t.Fatalf("expected case-insensitive bind DN to succeed, got %v", err)
	}
}

func TestLDAP_StartTLS_PlaintextListenerStillWorks(t *testing.T) {
	addr, _ := startLDAPServer(t, "valid")

	// Plain bind, no StartTLS at all -- the plaintext listener must keep
	// working exactly as before now that StartTLS is also available on it.
	plain, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer plain.Close()
	if err := plain.Bind("uid=jsmith,ou=users,dc=example,dc=com", "Secret123!"); err != nil {
		t.Fatalf("expected plaintext bind to keep working, got %v", err)
	}
}

func TestLDAP_StartTLS_UpgradesConnection(t *testing.T) {
	addr, _ := startLDAPServer(t, "valid")
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()

	if err := l.StartTLS(&stdtls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("starttls: %v", err)
	}
	// RFC 4511 §4.14.1: any bind state from before StartTLS is discarded,
	// but there wasn't one here -- confirm the upgraded connection is
	// simply fully usable for a fresh bind.
	if err := l.Bind("uid=jsmith,ou=users,dc=example,dc=com", "Secret123!"); err != nil {
		t.Fatalf("expected bind over the StartTLS-upgraded connection to succeed, got %v", err)
	}
}

func TestLDAP_Search_RootDSE_NoBindRequired(t *testing.T) {
	addr, _ := startLDAPServer(t, "valid")
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()

	req := goldap.NewSearchRequest(
		"", goldap.ScopeBaseObject, goldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"namingContexts", "subschemaSubentry", "supportedExtension"}, nil,
	)
	res, err := l.Search(req)
	if err != nil {
		t.Fatalf("expected RootDSE search without a prior bind to succeed, got %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("expected exactly one RootDSE entry, got %d", len(res.Entries))
	}
	if got := res.Entries[0].GetAttributeValues("namingContexts"); len(got) != 1 || got[0] != "dc=example,dc=com" {
		t.Fatalf("expected namingContexts [dc=example,dc=com], got %v", got)
	}
	if got := res.Entries[0].GetAttributeValues("supportedExtension"); len(got) != 1 || got[0] != "1.3.6.1.4.1.1466.20037" {
		t.Fatalf("expected supportedExtension to advertise StartTLS, got %v", got)
	}
}

func TestLDAP_Search_GroupMemberAttribute(t *testing.T) {
	addr, _ := startLDAPServer(t, "valid")
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()
	if err := l.Bind("uid=jsmith,ou=users,dc=example,dc=com", "Secret123!"); err != nil {
		t.Fatalf("bind: %v", err)
	}

	// jsmith is a direct+diamond member of engineering (via backend-team
	// and oncall); contractor1 (disabled, but LDAP search doesn't consider
	// enabled) is a member via platform-team.
	req := goldap.NewSearchRequest(
		"cn=engineering,ou=groups,dc=example,dc=com",
		goldap.ScopeBaseObject, goldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=groupOfNames)", []string{"member"}, nil,
	)
	res, err := l.Search(req)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("expected exactly one group entry, got %d", len(res.Entries))
	}
	member := res.Entries[0].GetAttributeValues("member")
	sort.Strings(member)
	want := []string{
		"uid=contractor1,ou=users,dc=example,dc=com",
		"uid=jsmith,ou=users,dc=example,dc=com",
	}
	if len(member) != len(want) {
		t.Fatalf("got member %v, want %v", member, want)
	}
	for i := range want {
		if member[i] != want[i] {
			t.Fatalf("got member %v, want %v", member, want)
		}
	}
}

func TestLDAP_UnsupportedOp_DoesNotDisconnectConnection(t *testing.T) {
	addr, _ := startLDAPServer(t, "valid")
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()

	_, err = l.Compare("uid=jsmith,ou=users,dc=example,dc=com", "uid", "jsmith")
	if err == nil {
		t.Fatal("expected Compare to be rejected -- identity is read-only via LDAP")
	}
	if !goldap.IsErrorWithCode(err, goldap.LDAPResultUnwillingToPerform) {
		t.Fatalf("expected unwillingToPerform, got %v", err)
	}

	// The connection must still be usable afterwards -- an unimplemented
	// operation is a clean per-request rejection, not a dropped session.
	if err := l.Bind("uid=jsmith,ou=users,dc=example,dc=com", "Secret123!"); err != nil {
		t.Fatalf("expected connection to remain usable after an unsupported op, got %v", err)
	}
}

func TestLDAP_RequireTLS_RejectsPlaintextBind(t *testing.T) {
	addr, _ := startLDAPServer(t, "valid", func(c *ldapserver.Config) { c.RequireTLS = true })
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()

	err = l.Bind("uid=jsmith,ou=users,dc=example,dc=com", "Secret123!")
	if err == nil {
		t.Fatal("expected plaintext bind to be rejected when RequireTLS is set")
	}
	if !goldap.IsErrorWithCode(err, goldap.LDAPResultConfidentialityRequired) {
		t.Fatalf("expected confidentialityRequired, got %v", err)
	}
}

func TestLDAP_RequireTLS_RejectsPlaintextSearch(t *testing.T) {
	addr, _ := startLDAPServer(t, "valid", func(c *ldapserver.Config) { c.RequireTLS = true; c.AllowAnonymousBind = true })
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()

	req := goldap.NewSearchRequest(
		"ou=users,dc=example,dc=com", goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 0, 0, false,
		"(uid=jsmith)", []string{"uid"}, nil,
	)
	_, err = l.Search(req)
	if err == nil {
		t.Fatal("expected plaintext search to be rejected when RequireTLS is set")
	}
	if !goldap.IsErrorWithCode(err, goldap.LDAPResultConfidentialityRequired) {
		t.Fatalf("expected confidentialityRequired, got %v", err)
	}
}

func TestLDAP_RequireTLS_RootDSEStillReadablePlaintext(t *testing.T) {
	addr, _ := startLDAPServer(t, "valid", func(c *ldapserver.Config) { c.RequireTLS = true })
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()

	// The RootDSE probe must stay reachable pre-TLS -- it's how a client
	// discovers StartTLS support in the first place; RequireTLS would
	// otherwise be a chicken-and-egg lockout.
	req := goldap.NewSearchRequest(
		"", goldap.ScopeBaseObject, goldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"supportedExtension"}, nil,
	)
	if _, err := l.Search(req); err != nil {
		t.Fatalf("expected RootDSE search to stay readable under RequireTLS, got %v", err)
	}
}

func TestLDAP_RequireTLS_AllowsBindAfterStartTLS(t *testing.T) {
	addr, _ := startLDAPServer(t, "valid", func(c *ldapserver.Config) { c.RequireTLS = true })
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()

	if err := l.StartTLS(&stdtls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("starttls: %v", err)
	}
	// RequireTLS is satisfied by a StartTLS-upgraded connection without
	// needing the separate secure listener at all.
	if err := l.Bind("uid=jsmith,ou=users,dc=example,dc=com", "Secret123!"); err != nil {
		t.Fatalf("expected bind after StartTLS to satisfy RequireTLS, got %v", err)
	}
}

func TestLDAP_Search_AttributeSelection_ExcludesUnrequested(t *testing.T) {
	addr, _ := startLDAPServer(t, "valid")
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()
	if err := l.Bind("uid=jsmith,ou=users,dc=example,dc=com", "Secret123!"); err != nil {
		t.Fatalf("bind: %v", err)
	}

	req := goldap.NewSearchRequest(
		"uid=jsmith,ou=users,dc=example,dc=com", goldap.ScopeBaseObject, goldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"uid"}, nil,
	)
	res, err := l.Search(req)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("expected exactly one entry, got %d", len(res.Entries))
	}
	entry := res.Entries[0]
	if got := entry.GetAttributeValues("uid"); len(got) != 1 || got[0] != "jsmith" {
		t.Fatalf("expected uid [jsmith], got %v", got)
	}
	if len(entry.Attributes) != 1 {
		t.Fatalf("expected only the requested 'uid' attribute, got %d attributes: %v", len(entry.Attributes), entry.Attributes)
	}
	if got := entry.GetAttributeValues("mail"); len(got) != 0 {
		t.Fatalf("expected 'mail' to be excluded from the unrequested response, got %v", got)
	}
}

func TestLDAP_Search_TypesOnly(t *testing.T) {
	addr, _ := startLDAPServer(t, "valid")
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()
	if err := l.Bind("uid=jsmith,ou=users,dc=example,dc=com", "Secret123!"); err != nil {
		t.Fatalf("bind: %v", err)
	}

	req := goldap.NewSearchRequest(
		"uid=jsmith,ou=users,dc=example,dc=com", goldap.ScopeBaseObject, goldap.NeverDerefAliases, 0, 0,
		true, // typesOnly
		"(objectClass=*)", []string{"uid", "mail"}, nil,
	)
	res, err := l.Search(req)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("expected exactly one entry, got %d", len(res.Entries))
	}
	entry := res.Entries[0]
	foundUID := false
	for _, a := range entry.Attributes {
		if a.Name == "uid" {
			foundUID = true
			if len(a.Values) != 0 {
				t.Fatalf("expected typesOnly to return no values for 'uid', got %v", a.Values)
			}
		}
	}
	if !foundUID {
		t.Fatalf("expected the 'uid' attribute name to still be present under typesOnly, got %v", entry.Attributes)
	}
}

func TestLDAP_Search_PagedResults(t *testing.T) {
	addr, _ := startLDAPServer(t, "valid")
	l, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer l.Close()
	if err := l.Bind("uid=jsmith,ou=users,dc=example,dc=com", "Secret123!"); err != nil {
		t.Fatalf("bind: %v", err)
	}

	newReq := func(controls []goldap.Control) *goldap.SearchRequest {
		return goldap.NewSearchRequest(
			"ou=users,dc=example,dc=com", goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)", []string{"1.1"}, controls,
		)
	}

	full, err := l.Search(newReq(nil))
	if err != nil {
		t.Fatalf("unpaged search: %v", err)
	}
	total := len(full.Entries)
	if total < 3 {
		t.Fatalf("fixture too small to exercise paging: got only %d entries", total)
	}

	paging := goldap.NewControlPaging(1)
	collected := 0
	for page := 0; page <= total; page++ {
		res, err := l.Search(newReq([]goldap.Control{paging}))
		if err != nil {
			t.Fatalf("paged search (page %d): %v", page, err)
		}
		if len(res.Entries) > 1 {
			t.Fatalf("expected at most 1 entry per page, got %d", len(res.Entries))
		}
		collected += len(res.Entries)

		ctrl := goldap.FindControl(res.Controls, goldap.ControlTypePaging)
		if ctrl == nil {
			t.Fatal("expected a paged-results response control")
		}
		respPaging, ok := ctrl.(*goldap.ControlPaging)
		if !ok {
			t.Fatalf("expected *ControlPaging, got %T", ctrl)
		}
		if len(respPaging.Cookie) == 0 {
			break
		}
		paging.SetCookie(respPaging.Cookie)
	}

	if collected != total {
		t.Fatalf("paged collection returned %d entries total, want %d", collected, total)
	}
}
