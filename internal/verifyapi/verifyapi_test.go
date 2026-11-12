package verifyapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"declarativeauth/internal/auth"
	"declarativeauth/internal/identity"
)

// fakeTOTP accepts one fixed code for any user.
type fakeTOTP struct{ code string }

func (f fakeTOTP) Verify(_ context.Context, _, code string) (bool, error) {
	return code == f.code, nil
}

func newHandler(t *testing.T) *Handler {
	t.Helper()
	hasher := &auth.Hasher{Params: auth.DefaultArgon2Params}
	hash, err := hasher.Hash("pw")
	if err != nil {
		t.Fatal(err)
	}
	snap := &identity.Snapshot{
		Users: map[string]identity.User{
			"vpn-svc": {Username: "vpn-svc", Enabled: true, PasswordHash: hash},
			"rando":   {Username: "rando", Enabled: true, PasswordHash: hash},
			"alice":   {Username: "alice", Enabled: true, PasswordHash: hash},
			"bob":     {Username: "bob", Enabled: true, MFAEnabled: true, PasswordHash: hash},
		},
		FlattenedMemberOf: map[string][]string{
			"vpn-svc": {"credential-verifiers"},
			"alice":   {"vpn-users"},
			"bob":     {"vpn-users"},
		},
	}
	holder := func() *identity.Snapshot { return snap }
	return &Handler{
		Authenticator: &auth.Authenticator{
			Snapshot: holder, Hasher: hasher,
			MFA: &auth.MFAPolicy{Snapshot: holder},
		},
		Snapshot:    holder,
		CallerGroup: "credential-verifiers",
	}
}

func call(h *Handler, caller, callerPW, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(body))
	req.RemoteAddr = "10.0.0.1:1234"
	if caller != "" {
		req.SetBasicAuth(caller, callerPW)
	}
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	mux.ServeHTTP(w, req)
	return w
}

func TestVerify_CallerAuth(t *testing.T) {
	h := newHandler(t)
	body := `{"username":"alice","password":"pw","group":"vpn-users"}`

	if w := call(h, "", "", body); w.Code != http.StatusUnauthorized {
		t.Errorf("no caller creds: %d", w.Code)
	}
	if w := call(h, "vpn-svc", "wrong", body); w.Code != http.StatusUnauthorized {
		t.Errorf("bad caller password: %d", w.Code)
	}
	// A valid account that is not in the caller group must not get an oracle.
	if w := call(h, "rando", "pw", body); w.Code != http.StatusForbidden {
		t.Errorf("caller outside group: %d", w.Code)
	}
	if w := call(h, "vpn-svc", "pw", body); w.Code != http.StatusOK {
		t.Errorf("valid caller: %d %s", w.Code, w.Body)
	}
}

func TestVerify_UserOutcomes(t *testing.T) {
	h := newHandler(t)
	cases := []struct {
		name, body string
		want       int
		reason     string
	}{
		{"ok", `{"username":"alice","password":"pw","group":"vpn-users"}`, 200, ""},
		{"wrong password", `{"username":"alice","password":"nope"}`, 401, "bad_password"},
		{"unknown user", `{"username":"ghost","password":"pw"}`, 401, "unknown_user"},
		{"not in group", `{"username":"alice","password":"pw","group":"admins"}`, 403, "not_in_group"},
		{"mfa user without code", `{"username":"bob","password":"pw","group":"vpn-users"}`, 401, "mfa_code_missing"},
		{"mfa user, no TOTP backend", `{"username":"bob","password":"pw","code":"123456"}`, 401, "bad_totp"},
		{"bad json", `{`, 400, "bad_request"},
		{"missing username", `{"password":"pw"}`, 400, "bad_request"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := call(h, "vpn-svc", "pw", c.body)
			if w.Code != c.want {
				t.Fatalf("status %d want %d: %s", w.Code, c.want, w.Body)
			}
			if c.reason != "" && !strings.Contains(w.Body.String(), c.reason) {
				t.Errorf("body %s missing reason %q", w.Body, c.reason)
			}
		})
	}
}

func TestVerify_MFAUserWithValidCode(t *testing.T) {
	h := newHandler(t)
	h.Authenticator.TOTP = fakeTOTP{code: "123456"}
	w := call(h, "vpn-svc", "pw", `{"username":"bob","password":"pw","code":"123456","group":"vpn-users"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"username":"bob"`) {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
	// Valid code, wrong password: still refused.
	w = call(h, "vpn-svc", "pw", `{"username":"bob","password":"nope","code":"123456"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password accepted: %d", w.Code)
	}
}

func TestVerify_MethodNotAllowed(t *testing.T) {
	h := newHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/verify", nil)
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d", w.Code)
	}
}
