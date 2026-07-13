//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"declarativeauth/internal/config"
	"declarativeauth/internal/metrics"
	"declarativeauth/internal/server"

	"github.com/golang-jwt/jwt/v5"
)

func startFullServer(t *testing.T) (issuer string, holder *config.SnapshotHolder) {
	t.Helper()
	pool := setupPool(t)
	_ = pool

	oidcAddr := freePort(t)
	ldapAddr := freePort(t)

	cfg := &config.ServerConfig{
		Database: config.DatabaseConfig{DSN: testDSN(t), MaxConns: 5},
		LDAP:     config.LDAPConfig{ListenAddr: ldapAddr, BaseDN: "dc=example,dc=com"},
		OIDC: config.OIDCConfig{
			Issuer:     "http://" + oidcAddr,
			ListenAddr: oidcAddr,
		},
		RateLimit: config.RateLimitConfig{
			Threshold: 5, BackoffBase: config.Duration(time.Second),
			BackoffMax: config.Duration(15 * time.Minute), Window: config.Duration(24 * time.Hour),
		},
	}

	holder = &config.SnapshotHolder{}
	snap, err := config.LoadIdentity(fixturePath("valid"))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	holder.Set(snap)

	pgxPool, err := poolFor(t, cfg.Database.DSN)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}

	// Seed jsmith's password via the credential store directly.
	seedPassword(t, pgxPool, "jsmith", "Secret123!")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = server.Run(ctx, cfg, holder, pgxPool, testLogger(), metrics.New())
	}()
	time.Sleep(200 * time.Millisecond) // let listeners bind

	return "http://" + oidcAddr, holder
}

func TestOIDC_FullAuthorizationCodeFlowWithPKCE(t *testing.T) {
	issuer, _ := startFullServer(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	verifier := "test-code-verifier-1234567890-1234567890"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	authorizeURL := issuer + "/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"example-client"},
		"redirect_uri":          {"http://localhost:9000/callback"},
		"scope":                 {"openid profile email groups"},
		"state":                 {"xyz"},
		"nonce":                 {"nonce123"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	// Step 1: unauthenticated -> redirected to /login
	resp, err := client.Get(authorizeURL)
	if err != nil {
		t.Fatalf("get authorize: %v", err)
	}
	loc := resp.Header.Get("Location")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "/login") {
		t.Fatalf("expected redirect to /login, got %d %s", resp.StatusCode, loc)
	}

	// Step 2: GET /login to obtain CSRF cookie
	resp, err = client.Get(issuer + loc)
	if err != nil {
		t.Fatalf("get login: %v", err)
	}
	resp.Body.Close()
	loginURL, _ := url.Parse(issuer + loc)
	var csrfToken string
	for _, c := range jar.Cookies(loginURL) {
		if c.Name == "da_csrf" {
			csrfToken = c.Value
		}
	}
	if csrfToken == "" {
		t.Fatal("expected da_csrf cookie to be set")
	}
	returnTo := loginURL.Query().Get("return_to")

	// Step 3: POST /login with credentials
	form := url.Values{
		"username": {"jsmith"}, "password": {"Secret123!"},
		"csrf_token": {csrfToken}, "return_to": {returnTo},
	}
	resp, err = client.PostForm(issuer+"/login", form)
	if err != nil {
		t.Fatalf("post login: %v", err)
	}
	loc = resp.Header.Get("Location")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 after login, got %d", resp.StatusCode)
	}

	// Step 4: follow back into /authorize now that a session exists
	resp, err = client.Get(issuer + loc)
	if err != nil {
		t.Fatalf("get authorize (2nd): %v", err)
	}
	finalLoc := resp.Header.Get("Location")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(finalLoc, "http://localhost:9000/callback") {
		t.Fatalf("expected redirect to client redirect_uri, got %d %s", resp.StatusCode, finalLoc)
	}
	cbURL, _ := url.Parse(finalLoc)
	code := cbURL.Query().Get("code")
	state := cbURL.Query().Get("state")
	if code == "" || state != "xyz" {
		t.Fatalf("expected code and matching state, got code=%q state=%q", code, state)
	}

	// Step 5: exchange code for tokens
	tokenResp, err := client.PostForm(issuer+"/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {"example-client"}, "code_verifier": {verifier},
	})
	if err != nil {
		t.Fatalf("post token: %v", err)
	}
	defer tokenResp.Body.Close()
	var tokenBody map[string]any
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenBody); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	idToken, _ := tokenBody["id_token"].(string)
	accessToken, _ := tokenBody["access_token"].(string)
	if idToken == "" || accessToken == "" {
		t.Fatalf("expected id_token and access_token, got %v", tokenBody)
	}

	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(idToken, claims); err != nil {
		t.Fatalf("parse id_token: %v", err)
	}
	if claims["sub"] != "jsmith" {
		t.Fatalf("expected sub=jsmith, got %v", claims["sub"])
	}
	if claims["nonce"] != "nonce123" {
		t.Fatalf("expected nonce echoed back, got %v", claims["nonce"])
	}
	groups, _ := claims["groups"].([]any)
	if len(groups) == 0 {
		t.Fatal("expected non-empty groups claim")
	}

	// Step 6: userinfo endpoint with the access token
	req, _ := http.NewRequest(http.MethodGet, issuer+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	uiResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	defer uiResp.Body.Close()
	var uiBody map[string]any
	if err := json.NewDecoder(uiResp.Body).Decode(&uiBody); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}
	if uiBody["sub"] != "jsmith" {
		t.Fatalf("expected userinfo sub=jsmith, got %v", uiBody["sub"])
	}
}

func TestOIDC_PKCE_WrongVerifierRejected(t *testing.T) {
	issuer, _ := startFullServer(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

	sum := sha256.Sum256([]byte("correct-verifier"))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authorizeURL := issuer + "/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {"example-client"},
		"redirect_uri": {"http://localhost:9000/callback"}, "scope": {"openid"},
		"state": {"s"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode()

	resp, _ := client.Get(authorizeURL)
	loc := resp.Header.Get("Location")
	resp.Body.Close()
	resp, _ = client.Get(issuer + loc)
	resp.Body.Close()
	loginURL, _ := url.Parse(issuer + loc)
	var csrfToken string
	for _, c := range jar.Cookies(loginURL) {
		if c.Name == "da_csrf" {
			csrfToken = c.Value
		}
	}
	returnTo := loginURL.Query().Get("return_to")
	resp, _ = client.PostForm(issuer+"/login", url.Values{
		"username": {"jsmith"}, "password": {"Secret123!"}, "csrf_token": {csrfToken}, "return_to": {returnTo},
	})
	loc = resp.Header.Get("Location")
	resp.Body.Close()
	resp, _ = client.Get(issuer + loc)
	finalLoc := resp.Header.Get("Location")
	resp.Body.Close()
	cbURL, _ := url.Parse(finalLoc)
	code := cbURL.Query().Get("code")

	tokenResp, err := client.PostForm(issuer+"/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {"example-client"}, "code_verifier": {"wrong-verifier"},
	})
	if err != nil {
		t.Fatalf("post token: %v", err)
	}
	defer tokenResp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(tokenResp.Body).Decode(&body)
	if body["error"] != "invalid_grant" {
		t.Fatalf("expected invalid_grant for wrong PKCE verifier, got %v", body)
	}
}
