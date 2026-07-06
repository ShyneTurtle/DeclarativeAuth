package config

import (
	"path/filepath"
	"testing"
)

func fixture(name string) string {
	return filepath.Join("..", "..", "test", "fixtures", name)
}

func TestLoadIdentity_Valid(t *testing.T) {
	snap, err := LoadIdentity(fixture("valid"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snap.Users) != 3 {
		t.Fatalf("expected 3 users, got %d", len(snap.Users))
	}
	if len(snap.Groups) != 5 {
		t.Fatalf("expected 5 groups, got %d", len(snap.Groups))
	}
	// jsmith is in oncall -> backend-team + platform-team -> engineering (diamond)
	want := []string{"backend-team", "engineering", "oncall", "platform-team"}
	got := snap.FlattenedMemberOf["jsmith"]
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if snap.Users["contractor1"].Enabled {
		t.Fatal("expected contractor1 to be disabled")
	}
}

func TestLoadIdentity_Cycle(t *testing.T) {
	_, err := LoadIdentity(fixture("cycle"))
	if err == nil {
		t.Fatal("expected cycle error, got nil")
	}
}

func TestLoadIdentity_MissingDir(t *testing.T) {
	_, err := LoadIdentity(fixture("does-not-exist"))
	if err == nil {
		t.Fatal("expected error for missing directory, got nil")
	}
}

func TestLoadIdentity_MFAFields(t *testing.T) {
	snap, err := LoadIdentity(fixture("mfa"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !snap.Groups["secure-team"].RequireMFA {
		t.Fatal("expected secure-team.RequireMFA to be true")
	}
	if snap.Groups["regular-team"].RequireMFA {
		t.Fatal("expected regular-team.RequireMFA to be false")
	}
	if !snap.Users["byuserflag"].MFAEnabled {
		t.Fatal("expected byuserflag.MFAEnabled to be true")
	}
	if snap.Users["nomfa"].MFAEnabled {
		t.Fatal("expected nomfa.MFAEnabled to be false")
	}

	if !snap.MFARequiredByDeclaration("bysecuregroup") {
		t.Fatal("expected bysecuregroup to require MFA via group membership")
	}
	if !snap.MFARequiredByDeclaration("byuserflag") {
		t.Fatal("expected byuserflag to require MFA via per-user override")
	}
	if snap.MFARequiredByDeclaration("nomfa") {
		t.Fatal("expected nomfa to not require MFA")
	}
}
