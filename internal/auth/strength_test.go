package auth

import "testing"

func TestStrength(t *testing.T) {
	cases := []struct {
		password string
		want     int
	}{
		{"", 0},
		{"a", 0},
		{"bqxmzk", 1},                       // random-ish 6 lowercase letters, no sequence/repeat pattern
		{"abcdefg", 0},                      // pure ascending sequence
		{"1234", 0},                         // short sequence
		{"1234123412341234", 0},             // "1234" repeated 4x -- must not out-score a single "1234"
		{"1234123412341234123412341234", 0}, // ...or 7x: repeating a weak unit stays weak
		{"aaaaaaaaaaaaaaaa", 0},             // single character repeated
		{"password1", 2},
		{"Password1", 2},
		{"Secret123!", 3},
		{"NewSecret456!", 4},
		{"correct-horse-battery-staple-42!", 4},
	}
	for _, tc := range cases {
		if got := Strength(tc.password); got != tc.want {
			t.Errorf("Strength(%q) = %d, want %d", tc.password, got, tc.want)
		}
	}
}

func TestPasswordPolicy_Validate(t *testing.T) {
	p := PasswordPolicy{MinLength: 8, MinStrength: 2}

	if err := p.Validate("short1!"); err == nil {
		t.Error("expected error for too-short password")
	}
	if err := p.Validate("12345678"); err == nil {
		t.Error("expected error for too-weak (single character class) password")
	}
	if err := p.Validate("Secret123!"); err != nil {
		t.Errorf("expected strong-enough password to pass, got: %v", err)
	}
}

func TestPasswordPolicy_Defaults(t *testing.T) {
	var p PasswordPolicy // zero value: MinLength/MinStrength both 0

	if err := p.Validate("short1!"); err == nil {
		t.Error("expected zero-value policy to still enforce the 8-char default")
	}
	if err := p.Validate("Secret123!"); err != nil {
		t.Errorf("expected zero-value policy to accept a fair-strength password, got: %v", err)
	}
}
