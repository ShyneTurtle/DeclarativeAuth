package ldapserver

import "testing"

func TestUserDN(t *testing.T) {
	got := UserDN("dc=example,dc=com", "jsmith")
	want := "uid=jsmith,ou=users,dc=example,dc=com"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestUsernameFromBindDN_FullDN(t *testing.T) {
	got, ok := UsernameFromBindDN("dc=example,dc=com", "uid=jsmith,ou=users,dc=example,dc=com")
	if !ok || got != "jsmith" {
		t.Fatalf("got (%q, %v), want (jsmith, true)", got, ok)
	}
}

func TestUsernameFromBindDN_BareUsername(t *testing.T) {
	got, ok := UsernameFromBindDN("dc=example,dc=com", "jsmith")
	if !ok || got != "jsmith" {
		t.Fatalf("got (%q, %v), want (jsmith, true)", got, ok)
	}
}

func TestUsernameFromBindDN_WrongBaseDN(t *testing.T) {
	_, ok := UsernameFromBindDN("dc=example,dc=com", "uid=jsmith,ou=users,dc=other,dc=com")
	if ok {
		t.Fatal("expected rejection for mismatched baseDN")
	}
}

func TestGroupNameFromDN(t *testing.T) {
	got, ok := GroupNameFromDN("dc=example,dc=com", "cn=engineering,ou=groups,dc=example,dc=com")
	if !ok || got != "engineering" {
		t.Fatalf("got (%q, %v), want (engineering, true)", got, ok)
	}
}

func TestUsernameFromBindDN_CaseInsensitiveStructure(t *testing.T) {
	// Attribute types and the fixed "ou=users"/baseDN path are
	// case-insensitive per RFC 4514; only the identity-bearing value
	// (the username itself) stays exact-case.
	got, ok := UsernameFromBindDN("dc=example,dc=com", "UID=jsmith,OU=Users,DC=Example,DC=Com")
	if !ok || got != "jsmith" {
		t.Fatalf("got (%q, %v), want (jsmith, true)", got, ok)
	}
}

func TestUsernameFromBindDN_WhitespaceInsensitive(t *testing.T) {
	got, ok := UsernameFromBindDN("dc=example,dc=com", "uid=jsmith, ou=users, dc=example, dc=com")
	if !ok || got != "jsmith" {
		t.Fatalf("got (%q, %v), want (jsmith, true)", got, ok)
	}
}

func TestUsernameFromBindDN_ValueCasePreserved(t *testing.T) {
	// The username value itself must NOT be folded -- identity lookups
	// elsewhere are exact-case map lookups.
	got, ok := UsernameFromBindDN("dc=example,dc=com", "uid=JSmith,ou=users,dc=example,dc=com")
	if !ok || got != "JSmith" {
		t.Fatalf("got (%q, %v), want (JSmith, true)", got, ok)
	}
}

func TestGroupNameFromDN_CaseInsensitiveStructure(t *testing.T) {
	got, ok := GroupNameFromDN("dc=example,dc=com", "CN=engineering,OU=Groups,DC=EXAMPLE,DC=COM")
	if !ok || got != "engineering" {
		t.Fatalf("got (%q, %v), want (engineering, true)", got, ok)
	}
}

func TestDNEqualFold(t *testing.T) {
	if !dnEqualFold("DC=Example,DC=Com", "dc=example, dc=com") {
		t.Fatal("expected case/whitespace-insensitive DN equality")
	}
	if dnEqualFold("dc=example,dc=com", "dc=other,dc=com") {
		t.Fatal("expected mismatched DNs to be unequal")
	}
}
