//go:build integration

package integration

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
)

// TestLogin_WrongPasswordThenCorrect_PreservesReturnTo reproduces a
// reported bug: landing on /login with a return_to (as an OIDC /authorize
// redirect would send), typing the wrong password once, then the correct
// password, must still land back at the original return_to -- not lose it
// along the way.
func TestLogin_WrongPasswordThenCorrect_PreservesReturnTo(t *testing.T) {
	issuer, _ := startFullServer(t)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// An unregistered client_id, deliberately: handleAuthorize 400s on it
	// immediately (before any further redirect), so this test only
	// exercises the /login <-> return_to round trip, not the OIDC dance.
	returnTo := "/authorize?client_id=unregistered-client&redirect_uri=http://localhost:9000/callback&state=xyz"

	loginURL := issuer + "/login?return_to=" + url.QueryEscape(returnTo)
	resp, err := client.Get(loginURL)
	if err != nil {
		t.Fatalf("get /login: %v", err)
	}
	resp.Body.Close()
	u, _ := url.Parse(issuer + "/login")
	var csrf string
	for _, c := range jar.Cookies(u) {
		if c.Name == "da_csrf" {
			csrf = c.Value
		}
	}
	if csrf == "" {
		t.Fatal("expected da_csrf cookie after GET /login")
	}

	// Attempt 1: wrong password.
	resp, err = client.PostForm(issuer+"/login", url.Values{
		"csrf_token": {csrf}, "return_to": {returnTo}, "username": {"jsmith"}, "password": {"WrongPassword1!"},
	})
	if err != nil {
		t.Fatalf("post /login (wrong password): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 (re-rendered login form) after wrong password, got %d", resp.StatusCode)
	}

	// Attempt 2: correct password, same CSRF token (never rotated since
	// the cookie was never re-issued between attempts).
	resp, err = client.PostForm(issuer+"/login", url.Values{
		"csrf_token": {csrf}, "return_to": {returnTo}, "username": {"jsmith"}, "password": {"Secret123!"},
	})
	if err != nil {
		t.Fatalf("post /login (correct password): %v", err)
	}
	resp.Body.Close()

	if got := resp.Request.URL.RequestURI(); got != returnTo {
		t.Fatalf("expected to land back at return_to %q, got %q", returnTo, got)
	}

	foundSession := false
	for _, c := range jar.Cookies(u) {
		if c.Name == "da_session" {
			foundSession = true
		}
	}
	if !foundSession {
		t.Fatal("expected a da_session cookie after successful login")
	}
}
