package identity

import "testing"

func TestUser_DisplayNameOrDefault(t *testing.T) {
	cases := []struct {
		name string
		u    User
		want string
	}{
		{"explicit displayName wins", User{Username: "jsmith", FirstName: "Jane", Name: "Smith", DisplayName: "Jane S."}, "Jane S."},
		{"first + name combine", User{Username: "jsmith", FirstName: "Jane", Name: "Smith"}, "Jane Smith"},
		{"first name only", User{Username: "jsmith", FirstName: "Jane"}, "Jane"},
		{"name only", User{Username: "jsmith", Name: "Smith"}, "Smith"},
		{"falls back to username", User{Username: "jsmith"}, "jsmith"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.u.DisplayNameOrDefault(); got != tc.want {
				t.Errorf("DisplayNameOrDefault() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSnapshot_MFARequiredByDeclaration(t *testing.T) {
	snap := &Snapshot{
		Users: map[string]User{
			"forced":     {Username: "forced", MFAEnabled: true},
			"plain":      {Username: "plain"},
			"in-secure":  {Username: "in-secure"},
			"transitive": {Username: "transitive"},
		},
		Groups: map[string]Group{
			"secure":    {Name: "secure", RequireMFA: true},
			"parent":    {Name: "parent", RequireMFA: false},
			"unrelated": {Name: "unrelated"},
		},
		FlattenedMemberOf: map[string][]string{
			"forced":     {"unrelated"},
			"plain":      {"unrelated"},
			"in-secure":  {"secure", "unrelated"},
			"transitive": {"parent", "secure"}, // reaches "secure" transitively
		},
	}

	cases := []struct {
		username string
		want     bool
	}{
		{"forced", true},     // per-user declarative override
		{"plain", false},     // no override, no group requiring MFA
		{"in-secure", true},  // direct member of a group requiring MFA
		{"transitive", true}, // transitively reaches a group requiring MFA
		{"unknown", false},   // unknown user: no declaration applies
	}
	for _, tc := range cases {
		t.Run(tc.username, func(t *testing.T) {
			if got := snap.MFARequiredByDeclaration(tc.username); got != tc.want {
				t.Errorf("MFARequiredByDeclaration(%q) = %v, want %v", tc.username, got, tc.want)
			}
		})
	}
}
