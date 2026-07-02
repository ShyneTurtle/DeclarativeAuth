package config

import (
	"testing"

	"declarativeauth/internal/identity"
)

func TestDiffSnapshots_AddedRemovedModified(t *testing.T) {
	old := &identity.Snapshot{
		Users: map[string]identity.User{
			"a": {Username: "a", Enabled: true},
			"b": {Username: "b", Enabled: true},
		},
		Groups: map[string]identity.Group{
			"g1": {Name: "g1"},
		},
	}
	updated := &identity.Snapshot{
		Users: map[string]identity.User{
			"a": {Username: "a", Enabled: false}, // modified
			"c": {Username: "c", Enabled: true},  // added
		},
		Groups: map[string]identity.Group{
			"g1": {Name: "g1"},
			"g2": {Name: "g2"}, // added
		},
	}

	d := DiffSnapshots(old, updated)
	if d.IsEmpty() {
		t.Fatal("expected non-empty diff")
	}
	assertContains(t, d.UsersAdded, "c")
	assertContains(t, d.UsersRemoved, "b")
	assertContains(t, d.UsersModified, "a")
	assertContains(t, d.GroupsAdded, "g2")
}

func TestDiffSnapshots_NoChange(t *testing.T) {
	snap := &identity.Snapshot{
		Users:  map[string]identity.User{"a": {Username: "a", Enabled: true}},
		Groups: map[string]identity.Group{"g1": {Name: "g1"}},
	}
	d := DiffSnapshots(snap, snap)
	if !d.IsEmpty() {
		t.Fatalf("expected empty diff, got %+v", d)
	}
}

func assertContains(t *testing.T, list []string, want string) {
	t.Helper()
	for _, v := range list {
		if v == want {
			return
		}
	}
	t.Fatalf("expected %q in %v", want, list)
}
