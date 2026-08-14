package ldapserver

import (
	"strings"
	"testing"

	"declarativeauth/internal/identity"
	"declarativeauth/internal/store"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func testSnapshot() *identity.Snapshot {
	users := map[string]identity.User{
		"jsmith": {Username: "jsmith", Email: "jsmith@example.com"},
	}
	groups := map[string]identity.Group{
		"engineering": {Name: "engineering"},
	}
	flattenedMemberOf := map[string][]string{"jsmith": {"engineering"}}
	return &identity.Snapshot{
		Users:             users,
		Groups:            groups,
		FlattenedMemberOf: flattenedMemberOf,
		FlattenedMembers:  identity.ResolveFlattenedMembers(flattenedMemberOf),
	}
}

func testHandler() *Handler {
	return &Handler{Config: Config{BaseDN: "dc=example,dc=com"}}
}

func TestEntriesFor_RootDSE(t *testing.T) {
	h := testHandler()
	entries := h.entriesFor(testSnapshot(), "", scopeBaseObject, true, sambaContext{})
	if len(entries) != 1 || entries[0].dn != "" {
		t.Fatalf("expected a single unnamed RootDSE entry, got %v", entries)
	}
	if !entries[0].forceAllAttrs {
		t.Fatal("expected RootDSE entry to force all attributes")
	}
}

func TestEntriesFor_Subschema(t *testing.T) {
	h := testHandler()
	entries := h.entriesFor(testSnapshot(), SubschemaDN, scopeBaseObject, true, sambaContext{})
	if len(entries) != 1 || entries[0].dn != SubschemaDN {
		t.Fatalf("expected the subschema entry, got %v", entries)
	}
}

func TestEntriesFor_BaseScope_ReturnsBaseEntryOnly(t *testing.T) {
	h := testHandler()
	entries := h.entriesFor(testSnapshot(), "dc=example,dc=com", scopeBaseObject, true, sambaContext{})
	if len(entries) != 1 || entries[0].dn != "dc=example,dc=com" {
		t.Fatalf("expected only the base entry, got %v", entries)
	}
}

func TestEntriesFor_SingleLevel_ReturnsOUsOnly(t *testing.T) {
	h := testHandler()
	entries := h.entriesFor(testSnapshot(), "dc=example,dc=com", scopeSingleLevel, true, sambaContext{})
	if len(entries) != 2 {
		t.Fatalf("expected exactly the two OU containers, got %v", entries)
	}
	for _, e := range entries {
		if e.dn != "ou=users,dc=example,dc=com" && e.dn != "ou=groups,dc=example,dc=com" {
			t.Fatalf("unexpected entry in single-level results: %v", e)
		}
	}
}

func TestEntriesFor_WholeSubtree_ReturnsEverything(t *testing.T) {
	h := testHandler()
	entries := h.entriesFor(testSnapshot(), "dc=example,dc=com", scopeWholeSubtree, true, sambaContext{})
	// base + ou=users + jsmith + ou=groups + engineering
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries in the whole subtree, got %d: %v", len(entries), entries)
	}
}

func TestEntriesFor_LeafUser_SingleLevelHasNoChildren(t *testing.T) {
	h := testHandler()
	entries := h.entriesFor(testSnapshot(), "uid=jsmith,ou=users,dc=example,dc=com", scopeSingleLevel, true, sambaContext{})
	if len(entries) != 0 {
		t.Fatalf("a leaf user entry has no children, got %v", entries)
	}
}

func TestEntriesFor_LeafUser_BaseScope(t *testing.T) {
	h := testHandler()
	entries := h.entriesFor(testSnapshot(), "uid=jsmith,ou=users,dc=example,dc=com", scopeBaseObject, true, sambaContext{})
	if len(entries) != 1 || entries[0].dn != "uid=jsmith,ou=users,dc=example,dc=com" {
		t.Fatalf("expected jsmith's entry, got %v", entries)
	}
}

func TestEntriesFor_UnknownBase_ReturnsNothing(t *testing.T) {
	h := testHandler()
	entries := h.entriesFor(testSnapshot(), "dc=nowhere,dc=com", scopeWholeSubtree, true, sambaContext{})
	if len(entries) != 0 {
		t.Fatalf("expected no entries for an unrelated base, got %v", entries)
	}
}

func TestAttrSelection_DefaultIsAll(t *testing.T) {
	sel := parseAttrSelection(nil)
	if !sel.includes("uid") || !sel.includes("anythingAtAll") {
		t.Fatal("expected an empty/nil selection to include every attribute")
	}
}

func TestAttrSelection_NoAttrs(t *testing.T) {
	sel := attrSelection{none: true}
	if sel.includes("uid") {
		t.Fatal("expected the 1.1 (no attributes) selection to exclude everything")
	}
}

func TestAttrSelection_NamedIsCaseInsensitive(t *testing.T) {
	sel := attrSelection{names: map[string]bool{"uid": true}}
	if !sel.includes("UID") {
		t.Fatal("expected attribute-name matching to be case-insensitive")
	}
	if sel.includes("mail") {
		t.Fatal("expected an attribute not in the selection to be excluded")
	}
}

func TestAttrSelection_IncludesExplicit_WildcardDoesNotCount(t *testing.T) {
	sel := attrSelection{all: true}
	if sel.includesExplicit("sambaNTPassword") {
		t.Fatal("expected a wildcard/default selection to NOT count as an explicit request for a sensitive attribute")
	}
}

func TestAttrSelection_IncludesExplicit_NamedAttributeCounts(t *testing.T) {
	sel := attrSelection{names: map[string]bool{strings.ToLower("sambaNTPassword"): true}}
	if !sel.includesExplicit("sambaNTPassword") {
		t.Fatal("expected an explicitly-named attribute to count, case-insensitively")
	}
	if sel.includesExplicit("uid") {
		t.Fatal("expected an attribute not in the selection to be excluded")
	}
}

func TestAttrSelection_IncludesExplicit_NoneExcludesEverything(t *testing.T) {
	sel := attrSelection{none: true}
	if sel.includesExplicit("sambaNTPassword") {
		t.Fatal("expected the 1.1 (no attributes) selection to exclude even an explicitly-sensitive attribute")
	}
}

// resultEntryAttrNames extracts the attribute names actually encoded into a
// buildSearchResultEntry packet, walking the same PartialAttributeList
// structure search.go builds -- so these tests exercise the real wire
// encoding, not just the pre-encoding Attribute slice.
func resultEntryAttrNames(p *ber.Packet) []string {
	if len(p.Children) < 2 {
		return nil
	}
	var names []string
	for _, pa := range p.Children[1].Children {
		if len(pa.Children) == 0 {
			continue
		}
		if name, ok := pa.Children[0].Value.(string); ok {
			names = append(names, name)
		}
	}
	return names
}

func containsFold(names []string, want string) bool {
	for _, n := range names {
		if strings.EqualFold(n, want) {
			return true
		}
	}
	return false
}

func TestBuildSearchResultEntry_SensitiveAttrHiddenFromWildcardSelection(t *testing.T) {
	e := entry{dn: "uid=jsmith,ou=users,dc=example,dc=com", attrs: []Attribute{
		{Name: "uid", Values: []string{"jsmith"}},
		{Name: "sambaNTPassword", Values: []string{"8846F7EAEE8FB117AD06BDD830B7586C"}, Sensitive: true},
	}}
	names := resultEntryAttrNames(buildSearchResultEntry(e, attrSelection{all: true}, false))
	if containsFold(names, "sambaNTPassword") {
		t.Fatalf("expected sambaNTPassword to be excluded from a wildcard selection, got %v", names)
	}
	if !containsFold(names, "uid") {
		t.Fatalf("expected uid to still be present, got %v", names)
	}
}

func TestBuildSearchResultEntry_SensitiveAttrShownWhenExplicitlyRequested(t *testing.T) {
	e := entry{dn: "uid=jsmith,ou=users,dc=example,dc=com", attrs: []Attribute{
		{Name: "uid", Values: []string{"jsmith"}},
		{Name: "sambaNTPassword", Values: []string{"8846F7EAEE8FB117AD06BDD830B7586C"}, Sensitive: true},
	}}
	sel := attrSelection{names: map[string]bool{"sambantpassword": true}}
	names := resultEntryAttrNames(buildSearchResultEntry(e, sel, false))
	if !containsFold(names, "sambaNTPassword") {
		t.Fatalf("expected sambaNTPassword to be present when explicitly requested, got %v", names)
	}
	if containsFold(names, "uid") {
		t.Fatalf("expected uid to be excluded since it wasn't requested, got %v", names)
	}
}

func testSnapshotWithSambaReader() *identity.Snapshot {
	users := map[string]identity.User{
		"jsmith": {Username: "jsmith", Email: "jsmith@example.com", Enabled: true},
	}
	groups := map[string]identity.Group{
		"samba-readers": {Name: "samba-readers"},
	}
	flattenedMemberOf := map[string][]string{"jsmith": {"samba-readers"}}
	return &identity.Snapshot{
		Users:             users,
		Groups:            groups,
		FlattenedMemberOf: flattenedMemberOf,
		FlattenedMembers:  identity.ResolveFlattenedMembers(flattenedMemberOf),
	}
}

func testSambaHandler() *Handler {
	return &Handler{Config: Config{
		BaseDN:            "dc=example,dc=com",
		SambaReadersGroup: "samba-readers",
		SambaDomainSID:    "S-1-5-21-1-2-3",
		SambaDomainName:   "WORKGROUP",
	}}
}

func TestEntriesFor_SambaPrivileged_AddsUserSambaAttrs(t *testing.T) {
	h := testSambaHandler()
	creds := map[string]store.SambaCredential{"jsmith": {NTHash: "8846F7EAEE8FB117AD06BDD830B7586C", RID: 1000}}
	entries := h.entriesFor(testSnapshotWithSambaReader(), "uid=jsmith,ou=users,dc=example,dc=com", scopeBaseObject, true, sambaContext{privileged: true, creds: creds})
	if len(entries) != 1 {
		t.Fatalf("expected jsmith's entry, got %v", entries)
	}
	if got := attrValues(entries[0].attrs, "sambaSID"); len(got) != 1 || got[0] != "S-1-5-21-1-2-3-1000" {
		t.Fatalf("expected sambaSID [S-1-5-21-1-2-3-1000], got %v", got)
	}
	if got := attrValues(entries[0].attrs, "sambaNTPassword"); len(got) != 1 || got[0] != "8846F7EAEE8FB117AD06BDD830B7586C" {
		t.Fatalf("expected sambaNTPassword, got %v", got)
	}
}

func TestEntriesFor_NotPrivileged_NoSambaAttrsEvenIfCredsProvided(t *testing.T) {
	h := testSambaHandler()
	creds := map[string]store.SambaCredential{"jsmith": {NTHash: "8846F7EAEE8FB117AD06BDD830B7586C", RID: 1000}}
	entries := h.entriesFor(testSnapshotWithSambaReader(), "uid=jsmith,ou=users,dc=example,dc=com", scopeBaseObject, true, sambaContext{privileged: false, creds: creds})
	if got := attrValues(entries[0].attrs, "sambaSID"); len(got) != 0 {
		t.Fatalf("expected no sambaSID when the search isn't samba-privileged, got %v", got)
	}
}

func TestEntriesFor_SambaPrivileged_NoCredYetMeansNoSambaAttrs(t *testing.T) {
	h := testSambaHandler()
	entries := h.entriesFor(testSnapshotWithSambaReader(), "uid=jsmith,ou=users,dc=example,dc=com", scopeBaseObject, true, sambaContext{privileged: true, creds: map[string]store.SambaCredential{}})
	if got := attrValues(entries[0].attrs, "sambaSID"); len(got) != 0 {
		t.Fatalf("expected no sambaSID before an NT hash has been computed for this user, got %v", got)
	}
}

func TestEntriesFor_SambaPrivileged_DomainEntryAppearsUnderBaseSingleLevel(t *testing.T) {
	h := testSambaHandler()
	entries := h.entriesFor(testSnapshotWithSambaReader(), "dc=example,dc=com", scopeSingleLevel, true, sambaContext{privileged: true})
	wantDN := "sambaDomainName=WORKGROUP,dc=example,dc=com"
	found := false
	for _, e := range entries {
		if e.dn == wantDN {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the sambaDomain entry (%s) among single-level results, got %v", wantDN, entries)
	}
}

func TestEntriesFor_NotPrivileged_NoDomainEntry(t *testing.T) {
	h := testSambaHandler()
	entries := h.entriesFor(testSnapshotWithSambaReader(), "dc=example,dc=com", scopeSingleLevel, true, sambaContext{})
	for _, e := range entries {
		if e.dn == "sambaDomainName=WORKGROUP,dc=example,dc=com" {
			t.Fatalf("expected no sambaDomain entry when the search isn't samba-privileged, got %v", entries)
		}
	}
}

func TestEntriesFor_SambaPrivileged_AddsGroupSambaAttrsAndWellKnownGroup(t *testing.T) {
	h := testSambaHandler()
	groupRIDs := map[string]int64{"samba-readers": 1001}
	sc := sambaContext{privileged: true, groupRIDs: groupRIDs}
	entries := h.entriesFor(testSnapshotWithSambaReader(), "cn=samba-readers,ou=groups,dc=example,dc=com", scopeBaseObject, true, sc)
	if len(entries) != 1 {
		t.Fatalf("expected samba-readers's entry, got %v", entries)
	}
	if got := attrValues(entries[0].attrs, "sambaSID"); len(got) != 1 || got[0] != "S-1-5-21-1-2-3-1001" {
		t.Fatalf("expected sambaSID [S-1-5-21-1-2-3-1001], got %v", got)
	}

	// The whole-subtree listing must also include the synthetic "Domain
	// Users" group (RID 513, fixed) even though it's not declared anywhere
	// in the snapshot -- see SambaWellKnownGroupName.
	entries = h.entriesFor(testSnapshotWithSambaReader(), "dc=example,dc=com", scopeWholeSubtree, true, sc)
	wantDN := "cn=Domain Users,ou=groups,dc=example,dc=com"
	found := false
	for _, e := range entries {
		if e.dn == wantDN {
			found = true
			if got := attrValues(e.attrs, "sambaSID"); len(got) != 1 || got[0] != "S-1-5-21-1-2-3-513" {
				t.Fatalf("expected Domain Users sambaSID [S-1-5-21-1-2-3-513], got %v", got)
			}
		}
	}
	if !found {
		t.Fatalf("expected the synthetic Domain Users group (%s) among whole-subtree results, got %v", wantDN, entries)
	}
}

func TestEntriesFor_NotPrivileged_NoGroupSambaAttrsOrWellKnownGroup(t *testing.T) {
	h := testSambaHandler()
	entries := h.entriesFor(testSnapshotWithSambaReader(), "cn=samba-readers,ou=groups,dc=example,dc=com", scopeBaseObject, true, sambaContext{})
	if got := attrValues(entries[0].attrs, "sambaSID"); len(got) != 0 {
		t.Fatalf("expected no sambaSID when the search isn't samba-privileged, got %v", got)
	}

	entries = h.entriesFor(testSnapshotWithSambaReader(), "dc=example,dc=com", scopeWholeSubtree, true, sambaContext{})
	for _, e := range entries {
		if e.dn == "cn=Domain Users,ou=groups,dc=example,dc=com" {
			t.Fatalf("expected no synthetic Domain Users group when the search isn't samba-privileged, got %v", entries)
		}
	}
}
