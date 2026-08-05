package ldapserver

import (
	"testing"

	"declarativeauth/internal/identity"
)

func TestGroupEntry_MemberAttribute(t *testing.T) {
	attrs := GroupEntry("dc=example,dc=com", identity.Group{Name: "engineering"}, []string{"asmith", "jsmith"})

	member := attrValues(attrs, "member")
	want := []string{"uid=asmith,ou=users,dc=example,dc=com", "uid=jsmith,ou=users,dc=example,dc=com"}
	if len(member) != len(want) {
		t.Fatalf("got member %v, want %v", member, want)
	}
	for i := range want {
		if member[i] != want[i] {
			t.Fatalf("got member %v, want %v", member, want)
		}
	}

	objectClass := attrValues(attrs, "objectClass")
	if len(objectClass) != 1 || objectClass[0] != "groupOfNames" {
		t.Fatalf("expected objectClass [groupOfNames], got %v", objectClass)
	}
}

func TestGroupEntry_EmptyGroupHasNoMemberValues(t *testing.T) {
	attrs := GroupEntry("dc=example,dc=com", identity.Group{Name: "empty"}, nil)
	if got := attrValues(attrs, "member"); len(got) != 0 {
		t.Fatalf("expected no member values for an empty group, got %v", got)
	}
}

func TestRootDSEEntry_AdvertisesStartTLSOnlyWhenAvailable(t *testing.T) {
	withTLS := RootDSEEntry("dc=example,dc=com", true)
	if got := attrValues(withTLS, "supportedExtension"); len(got) != 1 || got[0] != oidStartTLS {
		t.Fatalf("expected supportedExtension to advertise StartTLS, got %v", got)
	}

	withoutTLS := RootDSEEntry("dc=example,dc=com", false)
	if got := attrValues(withoutTLS, "supportedExtension"); len(got) != 0 {
		t.Fatalf("expected no supportedExtension when StartTLS unavailable, got %v", got)
	}

	if got := attrValues(withTLS, "namingContexts"); len(got) != 1 || got[0] != "dc=example,dc=com" {
		t.Fatalf("expected namingContexts [dc=example,dc=com], got %v", got)
	}
	if got := attrValues(withTLS, "subschemaSubentry"); len(got) != 1 || got[0] != SubschemaDN {
		t.Fatalf("expected subschemaSubentry [%s], got %v", SubschemaDN, got)
	}
}

func TestBaseEntry_DerivesDCAndO(t *testing.T) {
	attrs := BaseEntry("dc=example,dc=com")
	if got := attrValues(attrs, "dc"); len(got) != 1 || got[0] != "example" {
		t.Fatalf("expected dc [example], got %v", got)
	}
	if got := attrValues(attrs, "o"); len(got) != 1 || got[0] != "example" {
		t.Fatalf("expected o [example], got %v", got)
	}
}

func TestOUEntry(t *testing.T) {
	attrs := OUEntry("users")
	if got := attrValues(attrs, "ou"); len(got) != 1 || got[0] != "users" {
		t.Fatalf("expected ou [users], got %v", got)
	}
}
