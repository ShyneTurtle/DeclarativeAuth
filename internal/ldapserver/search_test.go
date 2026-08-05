package ldapserver

import (
	"testing"

	"declarativeauth/internal/identity"
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
	entries := h.entriesFor(testSnapshot(), "", scopeBaseObject, true)
	if len(entries) != 1 || entries[0].dn != "" {
		t.Fatalf("expected a single unnamed RootDSE entry, got %v", entries)
	}
	if !entries[0].forceAllAttrs {
		t.Fatal("expected RootDSE entry to force all attributes")
	}
}

func TestEntriesFor_Subschema(t *testing.T) {
	h := testHandler()
	entries := h.entriesFor(testSnapshot(), SubschemaDN, scopeBaseObject, true)
	if len(entries) != 1 || entries[0].dn != SubschemaDN {
		t.Fatalf("expected the subschema entry, got %v", entries)
	}
}

func TestEntriesFor_BaseScope_ReturnsBaseEntryOnly(t *testing.T) {
	h := testHandler()
	entries := h.entriesFor(testSnapshot(), "dc=example,dc=com", scopeBaseObject, true)
	if len(entries) != 1 || entries[0].dn != "dc=example,dc=com" {
		t.Fatalf("expected only the base entry, got %v", entries)
	}
}

func TestEntriesFor_SingleLevel_ReturnsOUsOnly(t *testing.T) {
	h := testHandler()
	entries := h.entriesFor(testSnapshot(), "dc=example,dc=com", scopeSingleLevel, true)
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
	entries := h.entriesFor(testSnapshot(), "dc=example,dc=com", scopeWholeSubtree, true)
	// base + ou=users + jsmith + ou=groups + engineering
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries in the whole subtree, got %d: %v", len(entries), entries)
	}
}

func TestEntriesFor_LeafUser_SingleLevelHasNoChildren(t *testing.T) {
	h := testHandler()
	entries := h.entriesFor(testSnapshot(), "uid=jsmith,ou=users,dc=example,dc=com", scopeSingleLevel, true)
	if len(entries) != 0 {
		t.Fatalf("a leaf user entry has no children, got %v", entries)
	}
}

func TestEntriesFor_LeafUser_BaseScope(t *testing.T) {
	h := testHandler()
	entries := h.entriesFor(testSnapshot(), "uid=jsmith,ou=users,dc=example,dc=com", scopeBaseObject, true)
	if len(entries) != 1 || entries[0].dn != "uid=jsmith,ou=users,dc=example,dc=com" {
		t.Fatalf("expected jsmith's entry, got %v", entries)
	}
}

func TestEntriesFor_UnknownBase_ReturnsNothing(t *testing.T) {
	h := testHandler()
	entries := h.entriesFor(testSnapshot(), "dc=nowhere,dc=com", scopeWholeSubtree, true)
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
