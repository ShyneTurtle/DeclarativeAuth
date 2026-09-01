//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"declarativeauth/internal/config"
	"declarativeauth/internal/metrics"
	"declarativeauth/internal/server"

	"github.com/descope/virtualwebauthn"
)

// startFullServerWithWebAuthn is like startFullServer but additionally
// enables passkeys, scoped to the loopback address the test server binds
// to (RPID must be a bare host with no scheme/port; RPOrigins must be the
// exact scheme+host+port a real browser would send as the Origin header).
func startFullServerWithWebAuthn(t *testing.T) (issuer string, rp virtualwebauthn.RelyingParty) {
	t.Helper()
	pool := setupPool(t)

	oidcAddr := freePort(t)
	ldapAddr := freePort(t)
	host, _, err := net.SplitHostPort(oidcAddr)
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}

	cfg := &config.ServerConfig{
		Database: config.DatabaseConfig{DSN: testDSN(t), MaxConns: 5},
		LDAP:     config.LDAPConfig{ListenAddr: ldapAddr, BaseDN: "dc=example,dc=com"},
		OIDC: config.OIDCConfig{
			Issuer:              "http://" + oidcAddr,
			ListenAddr:          oidcAddr,
			SigningAlg:          "ES256",
			KeyRotationInterval: config.Duration(720 * time.Hour),
			KeyOverlap:          config.Duration(24 * time.Hour),
			RefreshTokenTTL:     config.Duration(720 * time.Hour),
		},
		RateLimit: config.RateLimitConfig{
			Threshold: 5, BackoffBase: config.Duration(time.Second),
			BackoffMax: config.Duration(15 * time.Minute), Window: config.Duration(24 * time.Hour),
		},
		WebAuthn: config.WebAuthnConfig{
			Enabled:       true,
			RPID:          host,
			RPOrigins:     []string{"http://" + oidcAddr},
			RPDisplayName: "DeclarativeAuth Test",
		},
	}

	holder := &config.SnapshotHolder{}
	snap, err := config.LoadIdentity(fixturePath("valid"))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	holder.Set(snap)

	seedPassword(t, pool, "jsmith", "Secret123!")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = server.Run(ctx, cfg, holder, pool, testLogger(), metrics.New()) }()
	waitForTCP(t, oidcAddr, 10*time.Second)

	return "http://" + oidcAddr, virtualwebauthn.RelyingParty{
		Name: cfg.WebAuthn.RPDisplayName, ID: cfg.WebAuthn.RPID, Origin: cfg.WebAuthn.RPOrigins[0],
	}
}

func loginAndGetCSRF(t *testing.T, client *http.Client, issuer string) string {
	t.Helper()
	resp, err := client.Get(issuer + "/login")
	if err != nil {
		t.Fatalf("get /login: %v", err)
	}
	resp.Body.Close()
	u, _ := url.Parse(issuer + "/login")
	csrf := cookieValue(client, u, "da_csrf")
	if csrf == "" {
		t.Fatal("expected da_csrf cookie")
	}
	resp, err = client.PostForm(issuer+"/login", url.Values{
		"csrf_token": {csrf}, "return_to": {"/"}, "username": {"jsmith"}, "password": {"Secret123!"},
	})
	if err != nil {
		t.Fatalf("post /login: %v", err)
	}
	resp.Body.Close()
	if cookieValue(client, u, "da_session") == "" {
		t.Fatal("expected da_session cookie after password login")
	}
	return csrf
}

func cookieValue(client *http.Client, u *url.URL, name string) string {
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// TestPasskeyFlow_RegisterLoginDelete exercises the full passkey lifecycle
// against the real HTTP server using a virtual (software-simulated)
// authenticator in place of a browser/hardware authenticator: register a
// passkey while logged in via password, log in again with only the
// passkey (no password, no prior session), then remove it and confirm it
// can no longer be used to log in.
func TestPasskeyFlow_RegisterLoginDelete(t *testing.T) {
	issuer, rp := startFullServerWithWebAuthn(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	csrf := loginAndGetCSRF(t, client, issuer)

	authenticator := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	// Register: start.
	req, _ := http.NewRequest(http.MethodPost, issuer+"/webauthn/register/start", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("register/start: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register/start: expected 200, got %d: %s", resp.StatusCode, body)
	}

	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(body))
	if err != nil {
		t.Fatalf("parse attestation options: %v", err)
	}
	if attestationOptions.UserName != "jsmith" {
		t.Fatalf("expected attestation options for jsmith, got %q", attestationOptions.UserName)
	}
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *attestationOptions)

	// Register: finish.
	req, _ = http.NewRequest(http.MethodPost, issuer+"/webauthn/register/finish?name=Test+Key", strings.NewReader(attestationResponse))
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("register/finish: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register/finish: expected 200, got %d: %s", resp.StatusCode, body)
	}

	authenticator.AddCredential(cred)
	authenticator.Options.UserHandle = []byte("jsmith")

	// Log in with only the passkey, from a fresh cookie jar (no prior
	// session, no password) -- this is the actual point of a passkey.
	loginJar, _ := cookiejar.New(nil)
	loginClient := &http.Client{Jar: loginJar}

	resp, err = loginClient.Post(issuer+"/webauthn/login/start", "", nil)
	if err != nil {
		t.Fatalf("login/start: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login/start: expected 200, got %d: %s", resp.StatusCode, body)
	}
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(body))
	if err != nil {
		t.Fatalf("parse assertion options: %v", err)
	}
	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, cred, *assertionOptions)

	req, _ = http.NewRequest(http.MethodPost, issuer+"/webauthn/login/finish?return_to=%2Fsomewhere", strings.NewReader(assertionResponse))
	req.Header.Set("Content-Type", "application/json")
	resp, err = loginClient.Do(req)
	if err != nil {
		t.Fatalf("login/finish: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login/finish: expected 200, got %d: %s", resp.StatusCode, body)
	}
	var result struct {
		Redirect string `json:"redirect"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode login/finish response: %v", err)
	}
	if result.Redirect != "/somewhere" {
		t.Fatalf("expected redirect to /somewhere, got %q", result.Redirect)
	}
	loginU, _ := url.Parse(issuer + "/")
	if cookieValue(loginClient, loginU, "da_session") == "" {
		t.Fatal("expected a da_session cookie after passkey login")
	}

	// Remove the passkey (using the original, password-authenticated session).
	credIDB64 := base64.RawURLEncoding.EncodeToString(cred.ID)
	resp, err = client.PostForm(issuer+"/webauthn/register/delete", url.Values{
		"csrf_token": {csrf}, "credential_id": {credIDB64},
	})
	if err != nil {
		t.Fatalf("register/delete: %v", err)
	}
	resp.Body.Close()

	// A second passkey login attempt with the now-deleted credential must fail.
	failJar, _ := cookiejar.New(nil)
	failClient := &http.Client{Jar: failJar}
	resp, err = failClient.Post(issuer+"/webauthn/login/start", "", nil)
	if err != nil {
		t.Fatalf("login/start (post-delete): %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	assertionOptions, err = virtualwebauthn.ParseAssertionOptions(string(body))
	if err != nil {
		t.Fatalf("parse assertion options (post-delete): %v", err)
	}
	assertionResponse = virtualwebauthn.CreateAssertionResponse(rp, authenticator, cred, *assertionOptions)
	req, _ = http.NewRequest(http.MethodPost, issuer+"/webauthn/login/finish", strings.NewReader(assertionResponse))
	req.Header.Set("Content-Type", "application/json")
	resp, err = failClient.Do(req)
	if err != nil {
		t.Fatalf("login/finish (post-delete): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 logging in with a deleted passkey, got %d", resp.StatusCode)
	}
}
