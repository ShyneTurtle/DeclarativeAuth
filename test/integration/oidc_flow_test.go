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
	return startFullServerWithSigningAlg(t, "ES256")
}

func startFullServerWithSigningAlg(t *testing.T, alg string) (issuer string, holder *config.SnapshotHolder) {
	t.Helper()
	pool := setupPool(t)
	_ = pool

	oidcAddr := freePort(t)
	ldapAddr := freePort(t)

	cfg := &config.ServerConfig{
		Database: config.DatabaseConfig{DSN: testDSN(t), MaxConns: 5},
		LDAP:     config.LDAPConfig{ListenAddr: ldapAddr, BaseDN: "dc=example,dc=com"},
		OIDC: config.OIDCConfig{
			Issuer:              "http://" + oidcAddr,
			ListenAddr:          oidcAddr,
			SigningAlg:          alg,
			KeyRotationInterval: config.Duration(720 * time.Hour),
			KeyOverlap:          config.Duration(24 * time.Hour),
			RefreshTokenTTL:     config.Duration(720 * time.Hour),
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
	waitForTCP(t, oidcAddr, 10*time.Second)

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
	if got := cbURL.Query().Get("iss"); got != issuer {
		t.Fatalf("expected RFC 9207 iss=%q on the authorization response, got %q", issuer, got)
	}

	// Step 5: exchange code for tokens
	tokenResp, err := client.PostForm(issuer+"/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {"example-client"}, "code_verifier": {verifier},
		"redirect_uri": {"http://localhost:9000/callback"},
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
	refreshToken, _ := tokenBody["refresh_token"].(string)
	if idToken == "" || accessToken == "" || refreshToken == "" {
		t.Fatalf("expected id_token, access_token and refresh_token, got %v", tokenBody)
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
		"redirect_uri": {"http://localhost:9000/callback"},
	})
	if err != nil {
		t.Fatalf("post token: %v", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong PKCE verifier, got %d", tokenResp.StatusCode)
	}
	var body map[string]any
	_ = json.NewDecoder(tokenResp.Body).Decode(&body)
	if body["error"] != "invalid_grant" {
		t.Fatalf("expected invalid_grant for wrong PKCE verifier, got %v", body)
	}
}

// TestOIDC_TokenErrorsUseNonSuccessStatusCodes proves the token endpoint no
// longer returns HTTP 200 for error bodies -- a strict OAuth2 client (e.g.
// Vaultwarden's openidconnect-rs) branches on status code to decide whether
// to parse the body as a TokenResponse or an ErrorResponse; a 200 status on
// an error body was being misread as a malformed success and surfaced as a
// confusing "missing field `access_token`" error instead of invalid_client.
func TestOIDC_TokenErrorsUseNonSuccessStatusCodes(t *testing.T) {
	issuer, _ := startFullServer(t)
	client := &http.Client{}

	t.Run("unsupported_grant_type", func(t *testing.T) {
		// "password" (resource owner password credentials, RFC 6749 §4.3) is
		// deliberately not implemented -- unlike client_credentials, which is
		// now a real supported grant, this one is a genuine stand-in for
		// "a grant type this server doesn't support at all".
		resp, err := client.PostForm(issuer+"/token", url.Values{"grant_type": {"password"}})
		if err != nil {
			t.Fatalf("post token: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", resp.StatusCode)
		}
	})

	t.Run("unknown client_id", func(t *testing.T) {
		resp, err := client.PostForm(issuer+"/token", url.Values{
			"grant_type": {"authorization_code"}, "code": {"whatever"}, "client_id": {"no-such-client"},
		})
		if err != nil {
			t.Fatalf("post token: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", resp.StatusCode)
		}
		if got := resp.Header.Get("WWW-Authenticate"); got == "" {
			t.Error("expected a WWW-Authenticate challenge on invalid_client")
		}
	})

	t.Run("wrong client_secret", func(t *testing.T) {
		resp, err := client.PostForm(issuer+"/token", url.Values{
			"grant_type": {"authorization_code"}, "code": {"whatever"},
			"client_id": {"confidential-client"}, "client_secret": {"wrong"},
		})
		if err != nil {
			t.Fatalf("post token: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("invalid_grant for unknown code", func(t *testing.T) {
		resp, err := client.PostForm(issuer+"/token", url.Values{
			"grant_type": {"authorization_code"}, "code": {"no-such-code"},
			"client_id": {"confidential-client"}, "client_secret": {"s3cret-value"},
			"redirect_uri": {"http://localhost:9001/callback"},
		})
		if err != nil {
			t.Fatalf("post token: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", resp.StatusCode)
		}
	})
}

// TestOIDC_TokenEndpointAcceptsHTTPBasicClientAuth proves client_secret_basic
// (RFC 6749 §2.3.1) now works, not just client_secret_post -- this is what
// Vaultwarden's openidconnect-rs client uses by default for confidential
// clients, and the server previously only checked the POST body.
func TestOIDC_TokenEndpointAcceptsHTTPBasicClientAuth(t *testing.T) {
	issuer, _ := startFullServer(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:           jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	authorizeURL := issuer + "/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {"confidential-client"},
		"redirect_uri": {"http://localhost:9001/callback"}, "scope": {"openid"}, "state": {"s"},
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
	if code == "" {
		t.Fatalf("expected an auth code, got redirect %q", finalLoc)
	}

	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"http://localhost:9001/callback"},
	}
	req, _ := http.NewRequest(http.MethodPost, issuer+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("confidential-client", "s3cret-value")

	tokenResp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatalf("post token: %v", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with HTTP Basic client auth, got %d", tokenResp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(tokenResp.Body).Decode(&body); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if body["access_token"] == "" || body["access_token"] == nil {
		t.Fatalf("expected access_token, got %v", body)
	}
}

// TestOIDC_RS256SigningAlgorithm proves DECLARATIVEAUTH_OIDC_SIGNING_ALG=RS256
// actually changes what's signed and published, not just what's configured:
// the ID token header carries alg=RS256, and its kid resolves to an RSA
// (kty=RSA) key in the JWKS.
func TestOIDC_RS256SigningAlgorithm(t *testing.T) {
	issuer, _ := startFullServerWithSigningAlg(t, "RS256")

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

	verifier := "test-code-verifier-1234567890-1234567890"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	authorizeURL := issuer + "/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {"example-client"},
		"redirect_uri": {"http://localhost:9000/callback"}, "scope": {"openid"}, "state": {"s"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode()

	resp, err := client.Get(authorizeURL)
	if err != nil {
		t.Fatalf("get authorize: %v", err)
	}
	loc := resp.Header.Get("Location")
	resp.Body.Close()
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
	returnTo := loginURL.Query().Get("return_to")
	resp, err = client.PostForm(issuer+"/login", url.Values{
		"username": {"jsmith"}, "password": {"Secret123!"}, "csrf_token": {csrfToken}, "return_to": {returnTo},
	})
	if err != nil {
		t.Fatalf("post login: %v", err)
	}
	loc = resp.Header.Get("Location")
	resp.Body.Close()
	resp, err = client.Get(issuer + loc)
	if err != nil {
		t.Fatalf("get authorize (2nd): %v", err)
	}
	finalLoc := resp.Header.Get("Location")
	resp.Body.Close()
	cbURL, _ := url.Parse(finalLoc)
	code := cbURL.Query().Get("code")
	if code == "" {
		t.Fatalf("expected an auth code, got redirect %q", finalLoc)
	}

	tokenResp, err := client.PostForm(issuer+"/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"client_id": {"example-client"}, "redirect_uri": {"http://localhost:9000/callback"},
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
	if idToken == "" {
		t.Fatalf("expected id_token, got %v", tokenBody)
	}

	parsedToken, _, err := jwt.NewParser().ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse id_token: %v", err)
	}
	if parsedToken.Method.Alg() != "RS256" {
		t.Fatalf("expected id_token signed with RS256, got %s", parsedToken.Method.Alg())
	}
	kid, _ := parsedToken.Header["kid"].(string)
	if kid == "" {
		t.Fatal("expected a kid header on the id_token")
	}

	jwksResp, err := http.Get(issuer + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("get jwks: %v", err)
	}
	defer jwksResp.Body.Close()
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(jwksResp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	var found bool
	for _, k := range jwks.Keys {
		if k["kid"] == kid {
			found = true
			if k["kty"] != "RSA" {
				t.Errorf("expected kty=RSA for the RS256 key, got %v", k["kty"])
			}
		}
	}
	if !found {
		t.Fatalf("id_token's kid %q not found in JWKS %v", kid, jwks.Keys)
	}

	discResp, err := http.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("get discovery: %v", err)
	}
	defer discResp.Body.Close()
	var disc map[string]any
	if err := json.NewDecoder(discResp.Body).Decode(&disc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	algs, _ := disc["id_token_signing_alg_values_supported"].([]any)
	var advertisesRS256 bool
	for _, a := range algs {
		if a == "RS256" {
			advertisesRS256 = true
		}
	}
	if !advertisesRS256 {
		t.Errorf("expected discovery to advertise RS256, got %v", algs)
	}
}

// obtainTokenBody runs the full login + PKCE authorization_code exchange
// against example-client and returns the decoded /token response.
func obtainTokenBody(t *testing.T, issuer string, client *http.Client) map[string]any {
	t.Helper()
	jar := client.Jar

	verifier := "obtain-tokens-verifier-1234567890"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authorizeURL := issuer + "/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {"example-client"},
		"redirect_uri": {"http://localhost:9000/callback"}, "scope": {"openid"}, "state": {"s"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode()

	resp, err := client.Get(authorizeURL)
	if err != nil {
		t.Fatalf("get authorize: %v", err)
	}
	loc := resp.Header.Get("Location")
	resp.Body.Close()
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
	returnTo := loginURL.Query().Get("return_to")
	resp, err = client.PostForm(issuer+"/login", url.Values{
		"username": {"jsmith"}, "password": {"Secret123!"}, "csrf_token": {csrfToken}, "return_to": {returnTo},
	})
	if err != nil {
		t.Fatalf("post login: %v", err)
	}
	loc = resp.Header.Get("Location")
	resp.Body.Close()
	resp, err = client.Get(issuer + loc)
	if err != nil {
		t.Fatalf("get authorize (2nd): %v", err)
	}
	finalLoc := resp.Header.Get("Location")
	resp.Body.Close()
	cbURL, _ := url.Parse(finalLoc)
	code := cbURL.Query().Get("code")
	if code == "" {
		t.Fatalf("expected an auth code, got redirect %q", finalLoc)
	}

	tokenResp, err := client.PostForm(issuer+"/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"client_id": {"example-client"}, "redirect_uri": {"http://localhost:9000/callback"},
	})
	if err != nil {
		t.Fatalf("post token: %v", err)
	}
	defer tokenResp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(tokenResp.Body).Decode(&body); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return body
}

func TestOIDC_RefreshToken_RotatesAndReissuesTokens(t *testing.T) {
	issuer, _ := startFullServer(t)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

	body := obtainTokenBody(t, issuer, client)
	firstRefresh, _ := body["refresh_token"].(string)
	if firstRefresh == "" {
		t.Fatalf("expected a refresh_token, got %v", body)
	}

	refreshResp, err := http.PostForm(issuer+"/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {firstRefresh}, "client_id": {"example-client"},
	})
	if err != nil {
		t.Fatalf("post refresh: %v", err)
	}
	defer refreshResp.Body.Close()
	if refreshResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from refresh grant, got %d", refreshResp.StatusCode)
	}
	var refreshBody map[string]any
	if err := json.NewDecoder(refreshResp.Body).Decode(&refreshBody); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}
	newAccessToken, _ := refreshBody["access_token"].(string)
	newIDToken, _ := refreshBody["id_token"].(string)
	secondRefresh, _ := refreshBody["refresh_token"].(string)
	if newAccessToken == "" || newIDToken == "" || secondRefresh == "" {
		t.Fatalf("expected a full token set from the refresh grant, got %v", refreshBody)
	}
	if secondRefresh == firstRefresh {
		t.Fatal("expected the refresh grant to rotate to a new refresh_token, not reuse the old one")
	}

	// The rotated-away first refresh token must no longer work.
	replayResp, err := http.PostForm(issuer+"/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {firstRefresh}, "client_id": {"example-client"},
	})
	if err != nil {
		t.Fatalf("post replay: %v", err)
	}
	defer replayResp.Body.Close()
	if replayResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 invalid_grant replaying a rotated-away refresh token, got %d", replayResp.StatusCode)
	}

	// Reuse detection: since the old token was replayed, the whole session
	// is revoked, so even the *current* (second) refresh token must now be
	// rejected too.
	secondUseResp, err := http.PostForm(issuer+"/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {secondRefresh}, "client_id": {"example-client"},
	})
	if err != nil {
		t.Fatalf("post second use: %v", err)
	}
	defer secondUseResp.Body.Close()
	if secondUseResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected reuse detection to have revoked the session, got %d", secondUseResp.StatusCode)
	}
}

func TestOIDC_RefreshToken_WrongClientRejected(t *testing.T) {
	issuer, _ := startFullServer(t)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

	body := obtainTokenBody(t, issuer, client)
	refreshToken, _ := body["refresh_token"].(string)

	resp, err := http.PostForm(issuer+"/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken},
		"client_id": {"confidential-client"}, "client_secret": {"s3cret-value"},
	})
	if err != nil {
		t.Fatalf("post refresh: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 using a refresh token minted for a different client, got %d", resp.StatusCode)
	}
}

func TestOIDC_ClientCredentialsGrant(t *testing.T) {
	issuer, _ := startFullServer(t)

	resp, err := http.PostForm(issuer+"/token", url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"confidential-client"},
		"client_secret": {"s3cret-value"}, "scope": {"api:read"},
	})
	if err != nil {
		t.Fatalf("post client_credentials: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	accessToken, _ := body["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("expected an access_token, got %v", body)
	}
	if _, hasIDToken := body["id_token"]; hasIDToken {
		t.Error("client_credentials must not issue an id_token (no user context)")
	}
	if _, hasRefresh := body["refresh_token"]; hasRefresh {
		t.Error("client_credentials must not issue a refresh_token (RFC 6749 §4.4.3)")
	}

	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(accessToken, claims); err != nil {
		t.Fatalf("parse access_token: %v", err)
	}
	if claims["sub"] != "confidential-client" {
		t.Fatalf("expected sub=confidential-client, got %v", claims["sub"])
	}
}

func TestOIDC_ClientCredentialsGrant_RejectsPublicClient(t *testing.T) {
	issuer, _ := startFullServer(t)

	resp, err := http.PostForm(issuer+"/token", url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"example-client"},
	})
	if err != nil {
		t.Fatalf("post client_credentials: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 rejecting a public client from client_credentials, got %d", resp.StatusCode)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "unauthorized_client" {
		t.Fatalf("expected unauthorized_client, got %v", body)
	}
}
