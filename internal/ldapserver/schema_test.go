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

func TestUserEntry_NoSambaAttrsWhenNil(t *testing.T) {
	attrs := UserEntry("dc=example,dc=com", identity.User{Username: "jsmith"}, nil, nil)
	if got := attrValues(attrs, "sambaSID"); len(got) != 0 {
		t.Fatalf("expected no sambaSID when samba is nil, got %v", got)
	}
	objectClass := attrValues(attrs, "objectClass")
	for _, oc := range objectClass {
		if oc == "sambaSamAccount" {
			t.Fatalf("expected no sambaSamAccount objectClass when samba is nil, got %v", objectClass)
		}
	}
}

func TestUserEntry_SambaAttrsPresentAndMarkedSensitive(t *testing.T) {
	samba := &SambaUserAttrs{SID: "S-1-5-21-1-2-3-1000", NTHash: "8846F7EAEE8FB117AD06BDD830B7586C", Enabled: true}
	attrs := UserEntry("dc=example,dc=com", identity.User{Username: "jsmith"}, nil, samba)

	objectClass := attrValues(attrs, "objectClass")
	found := false
	for _, oc := range objectClass {
		if oc == "sambaSamAccount" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected sambaSamAccount objectClass, got %v", objectClass)
	}
	if got := attrValues(attrs, "sambaSID"); len(got) != 1 || got[0] != samba.SID {
		t.Fatalf("expected sambaSID [%s], got %v", samba.SID, got)
	}
	if got := attrValues(attrs, "sambaNTPassword"); len(got) != 1 || got[0] != samba.NTHash {
		t.Fatalf("expected sambaNTPassword [%s], got %v", samba.NTHash, got)
	}
	for _, a := range attrs {
		if a.Name == "sambaSID" || a.Name == "sambaNTPassword" || a.Name == "sambaAcctFlags" {
			if !a.Sensitive {
				t.Fatalf("expected %s to be marked Sensitive", a.Name)
			}
		}
	}
}

func TestUserEntry_NoNTPasswordAttrWhenHashNotYetComputed(t *testing.T) {
	samba := &SambaUserAttrs{SID: "S-1-5-21-1-2-3-1000", NTHash: "", Enabled: true}
	attrs := UserEntry("dc=example,dc=com", identity.User{Username: "jsmith"}, nil, samba)
	if got := attrValues(attrs, "sambaNTPassword"); len(got) != 0 {
		t.Fatalf("expected no sambaNTPassword attribute when NTHash hasn't been computed yet, got %v", got)
	}
}

func TestSambaAcctFlags(t *testing.T) {
	if got := sambaAcctFlags(true); got != "[U          ]" {
		t.Fatalf("expected enabled flags %q, got %q", "[U          ]", got)
	}
	if got := sambaAcctFlags(false); got != "[UD         ]" {
		t.Fatalf("expected disabled flags %q, got %q", "[UD         ]", got)
	}
	for _, enabled := range []bool{true, false} {
		got := sambaAcctFlags(enabled)
		if len(got) != 13 { // "[" + 11 + "]"
			t.Fatalf("expected fixed-width 13-char flags string, got %d chars: %q", len(got), got)
		}
	}
}

func TestSambaDomainEntry(t *testing.T) {
	attrs := SambaDomainEntry("WORKGROUP", "S-1-5-21-1-2-3")
	if got := attrValues(attrs, "sambaDomainName"); len(got) != 1 || got[0] != "WORKGROUP" {
		t.Fatalf("expected sambaDomainName [WORKGROUP], got %v", got)
	}
	if got := attrValues(attrs, "sambaSID"); len(got) != 1 || got[0] != "S-1-5-21-1-2-3" {
		t.Fatalf("expected sambaSID [S-1-5-21-1-2-3], got %v", got)
	}
	if got := attrValues(attrs, "objectClass"); len(got) != 1 || got[0] != "sambaDomain" {
		t.Fatalf("expected objectClass [sambaDomain], got %v", got)
	}
}
