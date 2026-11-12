package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B vectors (SHA-1 secret, truncated to 6 digits).
func TestCode_RFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	cases := map[int64]string{
		59:         "287082",
		1111111109: "081804",
		1111111111: "050471",
		1234567890: "005924",
		2000000000: "279037",
	}
	for unix, want := range cases {
		if got := Code(secret, unix/Period); got != want {
			t.Errorf("t=%d: got %s want %s", unix, got, want)
		}
	}
}

func TestVerify_WindowAndReplay(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111109, 0)
	cur := Step(now)

	step, ok := Verify(secret, Code(secret, cur), now, 0)
	if !ok || step != cur {
		t.Fatalf("current code rejected: ok=%v step=%d", ok, step)
	}
	if _, ok := Verify(secret, Code(secret, cur-1), now, 0); !ok {
		t.Error("previous step should be accepted (clock skew)")
	}
	if _, ok := Verify(secret, Code(secret, cur+1), now, 0); !ok {
		t.Error("next step should be accepted (clock skew)")
	}
	if _, ok := Verify(secret, Code(secret, cur-2), now, 0); ok {
		t.Error("two steps back should be rejected")
	}
	if _, ok := Verify(secret, Code(secret, cur), now, cur); ok {
		t.Error("replay of an already-used step must be rejected")
	}
	if _, ok := Verify(secret, Code(secret, cur-1), now, cur); ok {
		t.Error("an older step than the last accepted one must be rejected")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := Verify(secret, bad, now, 0); ok {
			t.Errorf("malformed code %q accepted", bad)
		}
	}
}

func TestCipher_RoundTripAndBinding(t *testing.T) {
	key := make([]byte, 32)
	c, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := c.Seal([]byte("secret"), "alice")
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Open(sealed, "alice")
	if err != nil || string(got) != "secret" {
		t.Fatalf("round trip: %q %v", got, err)
	}
	if _, err := c.Open(sealed, "bob"); err == nil {
		t.Error("sealed secret must not open under another username")
	}
	if _, err := NewCipher(make([]byte, 16)); err == nil {
		t.Error("short key accepted")
	}
}

func TestParseKey(t *testing.T) {
	if _, err := ParseKey(strings.Repeat("ab", 32)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", strings.Repeat("ab", 31), strings.Repeat("zz", 32)} {
		if _, err := ParseKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestOTPAuthURI(t *testing.T) {
	uri := OTPAuthURI("Quasar Auth", "alice", []byte("12345678901234567890"))
	for _, want := range []string{"otpauth://totp/Quasar%20Auth:alice?", "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "digits=6", "period=30"} {
		if !strings.Contains(uri, want) {
			t.Errorf("uri %q missing %q", uri, want)
		}
	}
}
