package auth

import (
	"context"
	"errors"
	"testing"

	"declarativeauth/internal/identity"
)

// fakeTOTP accepts exactly one code, once, mimicking store.TOTPStore's
// single-use behavior.
type fakeTOTP struct {
	code string
	used bool
}

func (f *fakeTOTP) Verify(_ context.Context, _, code string) (bool, error) {
	if f.used || code != f.code {
		return false, nil
	}
	f.used = true
	return true, nil
}

// NewMFATestAuthenticator is shared with other packages' tests via the
// exported helper below; here it backs the table tests.
func newMFAAuthenticator(t *testing.T, fake *fakeTOTP) *Authenticator {
	t.Helper()
	hasher := &Hasher{Params: DefaultArgon2Params}
	hash, err := hasher.Hash("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	snap := &identity.Snapshot{
		Users: map[string]identity.User{
			// Declaratively-hashed users never touch Postgres.
			"secure": {Username: "secure", Enabled: true, MFAEnabled: true, PasswordHash: hash},
			"plain":  {Username: "plain", Enabled: true, PasswordHash: hash},
		},
	}
	holder := func() *identity.Snapshot { return snap }
	return &Authenticator{
		Snapshot: holder,
		Hasher:   hasher,
		MFA:      &MFAPolicy{Snapshot: holder},
		TOTP:     fake,
	}
}

func reasonOf(t *testing.T, err error) Reason {
	t.Helper()
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("expected *AuthError, got %v", err)
	}
	return ae.Reason
}

func TestAuthenticateWithCode_RequiredUser(t *testing.T) {
	ctx := context.Background()

	t.Run("password and code", func(t *testing.T) {
		a := newMFAAuthenticator(t, &fakeTOTP{code: "123456"})
		res, err := a.AuthenticateWithCode(ctx, "secure", "hunter2", "123456", "1.2.3.4")
		if err != nil || res.Username != "secure" {
			t.Fatalf("got %v %v", res, err)
		}
	})
	t.Run("password only is rejected", func(t *testing.T) {
		a := newMFAAuthenticator(t, &fakeTOTP{code: "123456"})
		_, err := a.AuthenticateWithCode(ctx, "secure", "hunter2", "", "1.2.3.4")
		if r := reasonOf(t, err); r != ReasonMFAMissing {
			t.Fatalf("reason = %s", r)
		}
	})
	t.Run("wrong code", func(t *testing.T) {
		a := newMFAAuthenticator(t, &fakeTOTP{code: "123456"})
		_, err := a.AuthenticateWithCode(ctx, "secure", "hunter2", "000000", "1.2.3.4")
		if r := reasonOf(t, err); r != ReasonBadTOTP {
			t.Fatalf("reason = %s", r)
		}
	})
	t.Run("wrong password does not consume the code", func(t *testing.T) {
		fake := &fakeTOTP{code: "123456"}
		a := newMFAAuthenticator(t, fake)
		_, err := a.AuthenticateWithCode(ctx, "secure", "wrongpw", "123456", "1.2.3.4")
		if r := reasonOf(t, err); r != ReasonBadPassword {
			t.Fatalf("reason = %s", r)
		}
		if fake.used {
			t.Fatal("code must not be checked/consumed when the password is wrong")
		}
	})
	t.Run("code is single use", func(t *testing.T) {
		a := newMFAAuthenticator(t, &fakeTOTP{code: "123456"})
		if _, err := a.AuthenticateWithCode(ctx, "secure", "hunter2", "123456", "1.2.3.4"); err != nil {
			t.Fatal(err)
		}
		if _, err := a.AuthenticateWithCode(ctx, "secure", "hunter2", "123456", "1.2.3.4"); err == nil {
			t.Fatal("replayed code accepted")
		}
	})
	t.Run("no TOTP backend fails closed", func(t *testing.T) {
		a := newMFAAuthenticator(t, nil)
		a.TOTP = nil
		_, err := a.AuthenticateWithCode(ctx, "secure", "hunter2", "123456", "1.2.3.4")
		if r := reasonOf(t, err); r != ReasonBadTOTP {
			t.Fatalf("reason = %s", r)
		}
	})
}

func TestAuthenticateWithCode_UnrestrictedUserUnchanged(t *testing.T) {
	a := newMFAAuthenticator(t, &fakeTOTP{code: "123456"})
	// No code needed, and a stray one is ignored.
	for _, code := range []string{"", "999999"} {
		if _, err := a.AuthenticateWithCode(context.Background(), "plain", "hunter2", code, "1.2.3.4"); err != nil {
			t.Fatalf("plain user rejected with code %q: %v", code, err)
		}
	}
}

func TestAuthenticate_IgnoresMFA(t *testing.T) {
	// Plain Authenticate (LDAP bind, web password step) never enforces the code.
	a := newMFAAuthenticator(t, &fakeTOTP{code: "123456"})
	if _, err := a.Authenticate(context.Background(), "secure", "hunter2", "1.2.3.4"); err != nil {
		t.Fatalf("Authenticate must not enforce MFA: %v", err)
	}
}
