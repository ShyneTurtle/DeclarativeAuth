//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"declarativeauth/internal/config"
	"declarativeauth/internal/metrics"
	"declarativeauth/internal/server"
)

// mailcatcherAPI is the mailcatcher HTTP API base URL, reachable from inside
// the dev container via the compose service name. Reset-flow tests are
// skipped if it's unreachable (e.g. running outside the dev-compose stack).
func mailcatcherAPI(t *testing.T) string {
	t.Helper()
	api := os.Getenv("MAILCATCHER_API")
	if api == "" {
		api = "http://mailcatcher:1080"
	}
	resp, err := http.Get(api + "/messages")
	if err != nil {
		t.Skipf("mailcatcher not reachable at %s, skipping: %v", api, err)
	}
	resp.Body.Close()
	return api
}

func clearMailcatcher(t *testing.T, api string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, api+"/messages", nil)
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

type mcMessage struct {
	ID         int      `json:"id"`
	Recipients []string `json:"recipients"`
}

func waitForResetLink(t *testing.T, api, toEmail string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	linkRe := regexp.MustCompile(`http\S*/reset/confirm\?token=\S+`)

	for time.Now().Before(deadline) {
		resp, err := http.Get(api + "/messages")
		if err == nil {
			var msgs []mcMessage
			_ = json.NewDecoder(resp.Body).Decode(&msgs)
			resp.Body.Close()
			for _, m := range msgs {
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
				if link := linkRe.FindString(string(buf[:n])); link != "" {
					return strings.TrimSpace(link)
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("timed out waiting for reset email")
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func startFullServerWithSMTP(t *testing.T) (issuer string, holder *config.SnapshotHolder) {
	t.Helper()
	pool := setupPool(t)

	oidcAddr := freePort(t)
	ldapAddr := freePort(t)

	cfg := &config.ServerConfig{
		Database: config.DatabaseConfig{DSN: testDSN(t), MaxConns: 5},
		LDAP:     config.LDAPConfig{ListenAddr: ldapAddr, BaseDN: "dc=example,dc=com"},
		OIDC: config.OIDCConfig{
			Issuer:     "http://" + oidcAddr,
			ListenAddr: oidcAddr,
		},
		SMTP: config.SMTPConfig{Host: "mailcatcher", Port: 1025, From: "DeclarativeAuth <test@example.com>"},
		RateLimit: config.RateLimitConfig{
			Threshold: 5, BackoffBase: config.Duration(time.Second),
			BackoffMax: config.Duration(15 * time.Minute), Window: config.Duration(24 * time.Hour),
		},
		AdminUI: config.AdminUIConfig{AdminGroup: "admins"},
	}

	holder = &config.SnapshotHolder{}
	snap, err := config.LoadIdentity(fixturePath("valid"))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	holder.Set(snap)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = server.Run(ctx, cfg, holder, pool, testLogger(), metrics.New()) }()
	time.Sleep(200 * time.Millisecond)

	return "http://" + oidcAddr, holder
}

func TestResetFlow_EndToEnd(t *testing.T) {
	api := mailcatcherAPI(t)
	clearMailcatcher(t, api)

	issuer, _ := startFullServerWithSMTP(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// GET /reset to obtain a CSRF token
	resp, err := client.Get(issuer + "/reset")
	if err != nil {
		t.Fatalf("get /reset: %v", err)
	}
	resp.Body.Close()
	u, _ := url.Parse(issuer + "/reset")
	var csrf string
	for _, c := range jar.Cookies(u) {
		if c.Name == "da_csrf" {
			csrf = c.Value
		}
	}
	if csrf == "" {
		t.Fatal("expected da_csrf cookie")
	}

	resp, err = client.PostForm(issuer+"/reset", url.Values{"email": {"jsmith@example.com"}, "csrf_token": {csrf}})
	if err != nil {
		t.Fatalf("post /reset: %v", err)
	}
	resp.Body.Close()

	link := waitForResetLink(t, api, "jsmith@example.com")

	// GET the confirm page (relative path against our issuer, since the
	// email link uses cfg.OIDC.Issuer as BaseURL which matches issuer here)
	confirmPath := link[strings.Index(link, "/reset/confirm"):]
	resp, err = client.Get(issuer + confirmPath)
	if err != nil {
		t.Fatalf("get confirm: %v", err)
	}
	resp.Body.Close()
	confirmURL, _ := url.Parse(issuer + confirmPath)
	var confirmCSRF string
	for _, c := range jar.Cookies(confirmURL) {
		if c.Name == "da_csrf" {
			confirmCSRF = c.Value
		}
	}
	token := confirmURL.Query().Get("token")

	resp, err = client.PostForm(issuer+"/reset/confirm", url.Values{
		"token": {token}, "password": {"NewSecret456!"}, "password_confirm": {"NewSecret456!"}, "csrf_token": {confirmCSRF},
	})
	if err != nil {
		t.Fatalf("post confirm: %v", err)
	}
	resp.Body.Close()
	// With no return_to on the original request, a successful reset now
	// auto-logs the user in (the reset token already proved control of the
	// account) and lands them on "/" rather than a bare, redundant /login.
	if resp.Request.URL.Path != "/" {
		t.Fatalf("expected redirect to / after reset, ended at %s", resp.Request.URL.Path)
	}
	foundSession := false
	for _, c := range jar.Cookies(confirmURL) {
		if c.Name == "da_session" {
			foundSession = true
		}
	}
	if !foundSession {
		t.Fatal("expected reset to auto-login (da_session cookie) after a successful reset")
	}

	// Verify the new password actually works against the credential store.
	pool, err := poolFor(t, testDSN(t))
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	authenticator := buildAuthenticator(pool, &config.SnapshotHolder{}, defaultLockoutParams())
	snap, _ := config.LoadIdentity(fixturePath("valid"))
	holderForCheck := &config.SnapshotHolder{}
	holderForCheck.Set(snap)
	authenticator.Snapshot = holderForCheck.Get

	if _, err := authenticator.Authenticate(context.Background(), "jsmith", "NewSecret456!", "203.0.113.1"); err != nil {
		t.Fatalf("expected new password to work, got %v", err)
	}
}

// TestResetFlow_RequestByUsername verifies the "forgot password" form
// accepts a username interchangeably with an email, and that the reset
// link is always mailed to the account's declared email address -- never
// to whatever the requester typed (a username isn't a mailbox).
func TestResetFlow_RequestByUsername(t *testing.T) {
	api := mailcatcherAPI(t)
	clearMailcatcher(t, api)

	issuer, _ := startFullServerWithSMTP(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	resp, err := client.Get(issuer + "/reset")
	if err != nil {
		t.Fatalf("get /reset: %v", err)
	}
	resp.Body.Close()
	u, _ := url.Parse(issuer + "/reset")
	var csrf string
	for _, c := range jar.Cookies(u) {
		if c.Name == "da_csrf" {
			csrf = c.Value
		}
	}

	resp, err = client.PostForm(issuer+"/reset", url.Values{"email": {"jsmith"}, "csrf_token": {csrf}})
	if err != nil {
		t.Fatalf("post /reset: %v", err)
	}
	resp.Body.Close()

	// Confirms the link was mailed to jsmith's declared email, not to the
	// literal string "jsmith" (which isn't a valid recipient at all).
	waitForResetLink(t, api, "jsmith@example.com")
}

// TestResetFlow_ReturnToThreadedThroughToLogin reproduces the reported bug:
// arriving at /login with a return_to (e.g. from an OIDC /authorize
// redirect), then using "forgot password", must land back at that same
// return_to once the reset completes -- not a bare, context-less /login.
func TestResetFlow_ReturnToThreadedThroughToLogin(t *testing.T) {
	api := mailcatcherAPI(t)
	clearMailcatcher(t, api)

	issuer, _ := startFullServerWithSMTP(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// Land on /login with a return_to, as an OIDC /authorize redirect would.
	resp, err := client.Get(issuer + "/login?return_to=%2Fauthorize%3Fclient_id%3Dexample")
	if err != nil {
		t.Fatalf("get /login: %v", err)
	}
	resp.Body.Close()

	// Follow the "Forgot your password?" link, which must carry return_to.
	resp, err = client.Get(issuer + "/reset?return_to=%2Fauthorize%3Fclient_id%3Dexample")
	if err != nil {
		t.Fatalf("get /reset: %v", err)
	}
	resp.Body.Close()
	u, _ := url.Parse(issuer + "/reset")
	var csrf string
	for _, c := range jar.Cookies(u) {
		if c.Name == "da_csrf" {
			csrf = c.Value
		}
	}

	resp, err = client.PostForm(issuer+"/reset", url.Values{
		"email": {"jsmith@example.com"}, "csrf_token": {csrf}, "return_to": {"/authorize?client_id=example"},
	})
	if err != nil {
		t.Fatalf("post /reset: %v", err)
	}
	resp.Body.Close()

	link := waitForResetLink(t, api, "jsmith@example.com")
	if !strings.Contains(link, "return_to=") {
		t.Fatalf("expected the emailed reset link to carry return_to, got: %s", link)
	}
	confirmPath := link[strings.Index(link, "/reset/confirm"):]

	resp, err = client.Get(issuer + confirmPath)
	if err != nil {
		t.Fatalf("get confirm: %v", err)
	}
	resp.Body.Close()
	confirmURL, _ := url.Parse(issuer + confirmPath)
	var confirmCSRF, returnTo string
	for _, c := range jar.Cookies(confirmURL) {
		if c.Name == "da_csrf" {
			confirmCSRF = c.Value
		}
	}
	q := confirmURL.Query()
	returnTo = q.Get("return_to")
	token := q.Get("token")
	if returnTo != "/authorize?client_id=example" {
		t.Fatalf("expected return_to to survive into the confirm link, got %q", returnTo)
	}

	resp, err = client.PostForm(issuer+"/reset/confirm", url.Values{
		"token": {token}, "password": {"AnotherSecret789!"}, "password_confirm": {"AnotherSecret789!"},
		"csrf_token": {confirmCSRF}, "return_to": {returnTo},
	})
	if err != nil {
		t.Fatalf("post confirm: %v", err)
	}
	resp.Body.Close()

	if got := resp.Request.URL.RequestURI(); got != "/authorize?client_id=example" {
		t.Fatalf("expected reset to land back at the original return_to, got %s", got)
	}
}
