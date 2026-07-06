//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"declarativeauth/internal/store"
)

// waitForMFACode polls mailcatcher for the 6-digit email-MFA code most
// recently sent to toEmail (mirrors waitForResetLink's polling approach).
func waitForMFACode(t *testing.T, api, toEmail string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	codeRe := regexp.MustCompile(`verification code is: (\d{6})`)

	for time.Now().Before(deadline) {
		resp, err := http.Get(api + "/messages")
		if err == nil {
			var msgs []mcMessage
			_ = json.NewDecoder(resp.Body).Decode(&msgs)
			resp.Body.Close()
			for i := len(msgs) - 1; i >= 0; i-- {
				m := msgs[i]
				matched := false
				for _, rcpt := range m.Recipients {
					if strings.Contains(rcpt, toEmail) {
						matched = true
					}
				}
				if !matched {
					continue
				}
				bodyResp, err := http.Get(api + "/messages/" + itoa(m.ID) + ".plain")
				if err != nil {
					continue
				}
				buf := make([]byte, 8192)
				n, _ := bodyResp.Body.Read(buf)
				bodyResp.Body.Close()
				if m := codeRe.FindStringSubmatch(string(buf[:n])); m != nil {
					return m[1]
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("timed out waiting for MFA code email")
	return ""
}

func csrfFrom(jar *cookiejar.Jar, u *url.URL) string {
	for _, c := range jar.Cookies(u) {
		if c.Name == "da_csrf" {
			return c.Value
		}
	}
	return ""
}

func hasCookie(jar *cookiejar.Jar, u *url.URL, name string) bool {
	for _, c := range jar.Cookies(u) {
		if c.Name == name {
			return true
		}
	}
	return false
}

// TestMFAFlow_SelfServiceEnableRequiresCodeAtLogin verifies the full
// self-service email-MFA loop: a user with no declarative MFA requirement
// enables it from their profile page (simulated here directly against the
// store, the same way seedPassword bypasses the HTTP layer for setup),
// then their next login must pass through /login/mfa with a real emailed
// code before a session is issued -- and a wrong code doesn't grant one.
func TestMFAFlow_SelfServiceEnableRequiresCodeAtLogin(t *testing.T) {
	api := mailcatcherAPI(t)
	clearMailcatcher(t, api)

	issuer, _ := startFullServerWithSMTP(t)

	pool, err := poolFor(t, testDSN(t))
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	seedPassword(t, pool, "jsmith", "CorrectHorse123!", "reset-test-pepper")

	settings := &store.UserMFASettingsStore{Pool: pool}
	if err := settings.SetEnabled(context.Background(), "jsmith", true); err != nil {
		t.Fatalf("enable self-service mfa: %v", err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	loginURL, _ := url.Parse(issuer + "/login")
	resp, err := client.Get(issuer + "/login")
	if err != nil {
		t.Fatalf("get /login: %v", err)
	}
	resp.Body.Close()
	csrf := csrfFrom(jar, loginURL)
	if csrf == "" {
		t.Fatal("expected da_csrf cookie")
	}

	resp, err = client.PostForm(issuer+"/login", url.Values{
		"username": {"jsmith"}, "password": {"CorrectHorse123!"}, "csrf_token": {csrf},
	})
	if err != nil {
		t.Fatalf("post /login: %v", err)
	}
	resp.Body.Close()

	if resp.Request.URL.Path != "/login/mfa" {
		t.Fatalf("expected to land on /login/mfa after password check, got %s", resp.Request.URL.Path)
	}
	mfaURL, _ := url.Parse(issuer + "/login/mfa")
	if hasCookie(jar, mfaURL, "da_session") {
		t.Fatal("expected no session cookie before MFA is verified")
	}
	if !hasCookie(jar, mfaURL, "da_mfa_pending") {
		t.Fatal("expected a da_mfa_pending cookie after password check")
	}

	mfaCSRF := csrfFrom(jar, mfaURL)

	// Wrong code must not issue a session.
	resp, err = client.PostForm(issuer+"/login/mfa", url.Values{"code": {"000000"}, "csrf_token": {mfaCSRF}})
	if err != nil {
		t.Fatalf("post wrong code: %v", err)
	}
	resp.Body.Close()
	if hasCookie(jar, mfaURL, "da_session") {
		t.Fatal("expected wrong code to not issue a session")
	}

	code := waitForMFACode(t, api, "jsmith@example.com")

	resp, err = client.PostForm(issuer+"/login/mfa", url.Values{"code": {code}, "csrf_token": {mfaCSRF}})
	if err != nil {
		t.Fatalf("post correct code: %v", err)
	}
	resp.Body.Close()

	if resp.Request.URL.Path != "/" {
		t.Fatalf("expected redirect to / after correct MFA code, got %s", resp.Request.URL.Path)
	}
	if !hasCookie(jar, mfaURL, "da_session") {
		t.Fatal("expected a session to be issued after correct MFA code")
	}
}

// TestMFAFlow_NotRequiredSkipsChallenge verifies a user with no declarative
// MFA requirement and no self-service opt-in logs in normally, with no
// /login/mfa detour at all.
func TestMFAFlow_NotRequiredSkipsChallenge(t *testing.T) {
	issuer, _ := startFullServerWithSMTP(t)

	pool, err := poolFor(t, testDSN(t))
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	seedPassword(t, pool, "admin", "AdminSecret123!", "reset-test-pepper")

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	loginURL, _ := url.Parse(issuer + "/login")
	resp, err := client.Get(issuer + "/login")
	if err != nil {
		t.Fatalf("get /login: %v", err)
	}
	resp.Body.Close()
	csrf := csrfFrom(jar, loginURL)

	resp, err = client.PostForm(issuer+"/login", url.Values{
		"username": {"admin"}, "password": {"AdminSecret123!"}, "csrf_token": {csrf},
	})
	if err != nil {
		t.Fatalf("post /login: %v", err)
	}
	resp.Body.Close()

	if resp.Request.URL.Path != "/" {
		t.Fatalf("expected direct redirect to /, got %s", resp.Request.URL.Path)
	}
	if !hasCookie(jar, loginURL, "da_session") {
		t.Fatal("expected a session cookie right after password login")
	}
}
