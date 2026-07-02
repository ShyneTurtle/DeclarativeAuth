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
