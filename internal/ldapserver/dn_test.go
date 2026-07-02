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
