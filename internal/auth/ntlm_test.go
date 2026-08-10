package auth

import "testing"

// Known-answer tests: these NT hash values are widely published (e.g. in
// hashcat/John the Ripper example hash sets), so a wrong implementation is
// caught here rather than the first time a real Samba deployment rejects a
// login.
func TestNTHash_KnownVectors(t *testing.T) {
	cases := []struct {
		password string
		want     string
	}{
		{"password", "8846F7EAEE8FB117AD06BDD830B7586C"},
		{"", "31D6CFE0D16AE931B73C59D7E0C089C0"},
	}
	for _, tc := range cases {
		if got := NTHash(tc.password); got != tc.want {
			t.Errorf("NTHash(%q) = %q, want %q", tc.password, got, tc.want)
		}
	}
}

func TestNTHash_DeterministicAndCaseSensitiveToInput(t *testing.T) {
	a := NTHash("Secret123!")
	b := NTHash("Secret123!")
	if a != b {
		t.Fatalf("expected NTHash to be deterministic (no salt), got %q then %q", a, b)
	}
	if NTHash("Secret123!") == NTHash("secret123!") {
		t.Fatal("expected differently-cased passwords to hash differently")
	}
}

func TestNTHash_AlwaysUppercaseHex(t *testing.T) {
	got := NTHash("whatever")
	for _, r := range got {
		if r >= 'a' && r <= 'z' {
			t.Fatalf("expected uppercase hex output, got %q", got)
		}
	}
	if len(got) != 32 {
		t.Fatalf("expected a 32-character hex MD4 digest, got %d chars: %q", len(got), got)
	}
}
