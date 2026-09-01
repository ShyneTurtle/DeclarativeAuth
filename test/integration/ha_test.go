//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
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
	"github.com/golang-jwt/jwt/v5"
)

// newHAInstance starts one DeclarativeAuth process ("node") bound to its
// own loopback port, simulating one replica of a multi-instance
// deployment: it shares dsn (and therefore the same Postgres-backed
// sessions/lockouts/ceremonies/MFA-challenges) with every other instance
// started this way in the same test, exactly what "clusterized deployment
// in docker & kubernetes" (see requirements.md) means in practice. Nothing
// here is instance-specific state a load balancer would need to pin a
// client to. rpID/rpOrigins are passed through unchanged so multiple
// instances can be configured identically, as they would behind a real
// load balancer sharing one public origin.
func newHAInstance(t *testing.T, dsn string, rpID string, rpOrigins []string) string {
	t.Helper()
	oidcAddr := freePort(t)
	ldapAddr := freePort(t)

	cfg := &config.ServerConfig{
		Database: config.DatabaseConfig{DSN: dsn, MaxConns: 5},
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
			Threshold: 3, BackoffBase: config.Duration(200 * time.Millisecond),
			BackoffMax: config.Duration(2 * time.Second), Window: config.Duration(time.Hour),
		},
		WebAuthn: config.WebAuthnConfig{
			Enabled: rpID != "", RPID: rpID, RPOrigins: rpOrigins, RPDisplayName: "DeclarativeAuth HA Test",
		},
	}

	holder := &config.SnapshotHolder{}
	snap, err := config.LoadIdentity(fixturePath("valid"))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	holder.Set(snap)

	pool, err := poolFor(t, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = server.Run(ctx, cfg, holder, pool, testLogger(), metrics.New()) }()
	waitForTCP(t, oidcAddr, 10*time.Second)

	return "http://" + oidcAddr
}

// doRaw issues a request to targetURL carrying exactly the given cookies
// (name -> value) and headers, independent of any cookiejar -- this is how
// a cookie obtained from instance A is deliberately replayed against
// instance B, simulating a load balancer routing consecutive requests from
// the same browser to different backend instances.
func doRaw(t *testing.T, method, targetURL string, body io.Reader, cookies, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, targetURL, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for name, value := range cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, targetURL, err)
	}
	return resp
}

// TestHA_SessionValidAcrossInstances is the core multi-replica correctness
// check: a session issued by one instance (from a password login) must be
// accepted by a completely different instance, since sessions live in the
// shared `sessions` table, not in any single process's memory.
func TestHA_SessionValidAcrossInstances(t *testing.T) {
	dsn := testDSN(t)
	setupPool(t)
	pool, err := poolFor(t, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	seedPassword(t, pool, "jsmith", "Secret123!")

	instanceA := newHAInstance(t, dsn, "", nil)
	instanceB := newHAInstance(t, dsn, "", nil)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	u, _ := url.Parse(instanceA + "/login")
	resp, err := client.Get(instanceA + "/login")
	if err != nil {
		t.Fatalf("get /login on instance A: %v", err)
	}
	resp.Body.Close()
	csrf := cookieValue(client, u, "da_csrf")

	resp, err = client.PostForm(instanceA+"/login", url.Values{
		"username": {"jsmith"}, "password": {"Secret123!"}, "csrf_token": {csrf},
	})
	if err != nil {
		t.Fatalf("post /login on instance A: %v", err)
	}
	resp.Body.Close()
	session := cookieValue(client, u, "da_session")
	if session == "" {
		t.Fatal("expected a da_session cookie after logging in via instance A")
	}

	// Replay that exact session cookie against instance B, a process that
	// never handled the login request and has no in-memory knowledge of it.
	resp = doRaw(t, http.MethodGet, instanceB+"/", nil, map[string]string{"da_session": session}, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected instance B to accept instance A's session and serve the profile page (200), got %d", resp.StatusCode)
	}
}

// TestHA_LockoutSharedAcrossInstances verifies the persisted brute-force
// backoff is a cluster-wide property, not per-instance: failing enough
// attempts against instance A must lock the account out on instance B too,
// otherwise an attacker behind a load balancer could just get routed to a
// fresh instance to reset their attempt budget.
func TestHA_LockoutSharedAcrossInstances(t *testing.T) {
	dsn := testDSN(t)
	setupPool(t)
	pool, err := poolFor(t, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	seedPassword(t, pool, "admin", "Correct123!")

	instanceA := newHAInstance(t, dsn, "", nil)
	instanceB := newHAInstance(t, dsn, "", nil)

	jarA, _ := cookiejar.New(nil)
	clientA := &http.Client{Jar: jarA}
	uA, _ := url.Parse(instanceA + "/login")

	// Exceed the configured threshold (3) of wrong-password attempts,
	// entirely against instance A.
	for i := 0; i < 4; i++ {
		resp, err := clientA.Get(instanceA + "/login")
		if err != nil {
			t.Fatalf("get /login on instance A: %v", err)
		}
		resp.Body.Close()
		csrf := cookieValue(clientA, uA, "da_csrf")
		resp, err = clientA.PostForm(instanceA+"/login", url.Values{
			"username": {"admin"}, "password": {"WrongPassword!"}, "csrf_token": {csrf},
		})
		if err != nil {
			t.Fatalf("post wrong password on instance A (attempt %d): %v", i, err)
		}
		resp.Body.Close()
	}

	// Now try the *correct* password against instance B -- if lockout state
	// weren't shared, this would succeed, since instance B never saw any of
	// the failed attempts itself.
	jarB, _ := cookiejar.New(nil)
	clientB := &http.Client{Jar: jarB}
	uB, _ := url.Parse(instanceB + "/login")
	resp, err := clientB.Get(instanceB + "/login")
	if err != nil {
		t.Fatalf("get /login on instance B: %v", err)
	}
	resp.Body.Close()
	csrfB := cookieValue(clientB, uB, "da_csrf")
	resp, err = clientB.PostForm(instanceB+"/login", url.Values{
		"username": {"admin"}, "password": {"Correct123!"}, "csrf_token": {csrfB},
	})
	if err != nil {
		t.Fatalf("post correct password on instance B: %v", err)
	}
	resp.Body.Close()

	if session := cookieValue(clientB, uB, "da_session"); session != "" {
		t.Fatal("expected the account to be locked out on instance B due to failures recorded on instance A, but login succeeded")
	}
}

// TestHA_WebAuthnCeremonyHandoffAcrossInstances verifies the trickiest
// piece of cross-instance state: a WebAuthn ceremony (registration or
// login) started on one instance must be completable on a different one,
// since the in-progress challenge lives in the shared `webauthn_ceremonies`
// table (see store.WebAuthnCeremonyStore), keyed by an opaque cookie value,
// not in either process's memory. Both instances are configured with the
// same RPID/RPOrigins, mirroring how every backend behind a real load
// balancer shares one public origin regardless of which one happens to
// serve a given request.
func TestHA_WebAuthnCeremonyHandoffAcrossInstances(t *testing.T) {
	dsn := testDSN(t)
	setupPool(t)
	pool, err := poolFor(t, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	seedPassword(t, pool, "jsmith", "Secret123!")

	// Instance A's own address doubles as the shared public RP origin both
	// instances are configured with -- exactly as a real deployment would
	// configure every replica with the load balancer's public address, not
	// each replica's own.
	oidcAddrA := freePort(t)
	host, _, err := net.SplitHostPort(oidcAddrA)
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}
	rpOrigins := []string{"http://" + oidcAddrA}

	instanceA := startHAInstanceAt(t, dsn, oidcAddrA, host, rpOrigins)
	instanceB := newHAInstance(t, dsn, host, rpOrigins)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	u, _ := url.Parse(instanceA + "/login")
	resp, err := client.Get(instanceA + "/login")
	if err != nil {
		t.Fatalf("get /login: %v", err)
	}
	resp.Body.Close()
	csrf := cookieValue(client, u, "da_csrf")
	resp, err = client.PostForm(instanceA+"/login", url.Values{
		"username": {"jsmith"}, "password": {"Secret123!"}, "csrf_token": {csrf},
	})
	if err != nil {
		t.Fatalf("post /login: %v", err)
	}
	resp.Body.Close()
	session := cookieValue(client, u, "da_session")

	rp := virtualwebauthn.RelyingParty{Name: "DeclarativeAuth HA Test", ID: host, Origin: rpOrigins[0]}
	authenticator := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	// Start registration on instance A.
	resp = doRaw(t, http.MethodPost, instanceA+"/webauthn/register/start", nil,
		map[string]string{"da_session": session, "da_csrf": csrf}, map[string]string{"X-CSRF-Token": csrf})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register/start on A: expected 200, got %d: %s", resp.StatusCode, body)
	}
	ceremonyCookie := ""
	for _, c := range resp.Cookies() {
		if c.Name == "da_webauthn_ceremony" {
			ceremonyCookie = c.Value
		}
	}
	if ceremonyCookie == "" {
		t.Fatal("expected a da_webauthn_ceremony cookie from instance A")
	}
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(body))
	if err != nil {
		t.Fatalf("parse attestation options: %v", err)
	}
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *attestationOptions)

	// Finish registration on instance B -- it never issued this ceremony,
	// so this only works if the ceremony state was read from Postgres.
	resp = doRaw(t, http.MethodPost, instanceB+"/webauthn/register/finish?name=HA+Key", strings.NewReader(attestationResponse),
		map[string]string{"da_session": session, "da_csrf": csrf, "da_webauthn_ceremony": ceremonyCookie},
		map[string]string{"X-CSRF-Token": csrf, "Content-Type": "application/json"})
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register/finish on B: expected 200, got %d: %s", resp.StatusCode, body)
	}

	authenticator.AddCredential(cred)
	authenticator.Options.UserHandle = []byte("jsmith")

	// Now the reverse direction: start the login ceremony on instance B,
	// finish it on instance A.
	resp = doRaw(t, http.MethodPost, instanceB+"/webauthn/login/start", nil, nil, nil)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login/start on B: expected 200, got %d: %s", resp.StatusCode, body)
	}
	loginCeremonyCookie := ""
	for _, c := range resp.Cookies() {
		if c.Name == "da_webauthn_ceremony" {
			loginCeremonyCookie = c.Value
		}
	}
	if loginCeremonyCookie == "" {
		t.Fatal("expected a da_webauthn_ceremony cookie from instance B")
	}
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(body))
	if err != nil {
		t.Fatalf("parse assertion options: %v", err)
	}
	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, cred, *assertionOptions)

	resp = doRaw(t, http.MethodPost, instanceA+"/webauthn/login/finish", strings.NewReader(assertionResponse),
		map[string]string{"da_webauthn_ceremony": loginCeremonyCookie},
		map[string]string{"Content-Type": "application/json"})
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login/finish on A: expected 200, got %d: %s", resp.StatusCode, body)
	}
	foundSession := false
	for _, c := range resp.Cookies() {
		if c.Name == "da_session" {
			foundSession = true
		}
	}
	if !foundSession {
		t.Fatal("expected instance A to issue a session after finishing a ceremony started on instance B")
	}
}

// startHAInstanceAt is newHAInstance but binding to a caller-chosen OIDC
// address, needed here so instance A's own address can also serve as the
// shared RP origin both instances are configured with.
func startHAInstanceAt(t *testing.T, dsn, oidcAddr, rpID string, rpOrigins []string) string {
	t.Helper()
	ldapAddr := freePort(t)
	cfg := &config.ServerConfig{
		Database: config.DatabaseConfig{DSN: dsn, MaxConns: 5},
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
			Threshold: 3, BackoffBase: config.Duration(200 * time.Millisecond),
			BackoffMax: config.Duration(2 * time.Second), Window: config.Duration(time.Hour),
		},
		WebAuthn: config.WebAuthnConfig{
			Enabled: true, RPID: rpID, RPOrigins: rpOrigins, RPDisplayName: "DeclarativeAuth HA Test",
		},
	}
	holder := &config.SnapshotHolder{}
	snap, err := config.LoadIdentity(fixturePath("valid"))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	holder.Set(snap)

	pool, err := poolFor(t, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = server.Run(ctx, cfg, holder, pool, testLogger(), metrics.New()) }()
	waitForTCP(t, oidcAddr, 10*time.Second)
	return "http://" + oidcAddr
}

// obtainOIDCCodeFrom runs the login + PKCE authorize dance against issuer
// for example-client and returns the authorization code plus the verifier
// used to request it, deliberately stopping short of calling /token --
// the whole point of the HA tests below is to redeem/rotate/revoke against
// a *different* instance than the one that issued things, so which
// instance's /token endpoint gets called is left to the caller.
func obtainOIDCCodeFrom(t *testing.T, issuer string) (code, verifier string) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

	verifier = "ha-test-verifier-1234567890-1234567890"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	authorizeURL := issuer + "/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {"example-client"},
		"redirect_uri": {"http://localhost:9000/callback"}, "scope": {"openid profile email groups"}, "state": {"s"},
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
	code = cbURL.Query().Get("code")
	if code == "" {
		t.Fatalf("expected an auth code, got redirect %q", finalLoc)
	}
	return code, verifier
}

// TestHA_OIDC_CodeAndKeysSharedAcrossInstances proves the core OIDC
// horizontal-scaling guarantee: an authorization code minted by one
// instance is redeemable on a completely different one (DB-backed
// oidc_authorization_codes, see store.OIDCCodeStore), and the resulting
// tokens -- signed with whichever key that instance happened to have
// loaded -- verify successfully against a *different* instance's
// /userinfo, proving the Postgres-backed signing key (store.OIDCKeyStore)
// is genuinely shared, not generated per-process the way the original v1
// in-memory key was.
func TestHA_OIDC_CodeAndKeysSharedAcrossInstances(t *testing.T) {
	dsn := testDSN(t)
	setupPool(t)
	pool, err := poolFor(t, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	seedPassword(t, pool, "jsmith", "Secret123!")

	instanceA := newHAInstance(t, dsn, "", nil)
	instanceB := newHAInstance(t, dsn, "", nil)

	code, verifier := obtainOIDCCodeFrom(t, instanceA)

	tokenResp, err := http.PostForm(instanceB+"/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"client_id": {"example-client"}, "redirect_uri": {"http://localhost:9000/callback"},
	})
	if err != nil {
		t.Fatalf("post token on instance B: %v", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("expected instance B to redeem a code minted by instance A, got %d", tokenResp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(tokenResp.Body).Decode(&body); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	accessToken, _ := body["access_token"].(string)
	idToken, _ := body["id_token"].(string)
	if accessToken == "" || idToken == "" {
		t.Fatalf("expected access_token and id_token, got %v", body)
	}

	// The token was signed on B; verifying it on A only works if A can see
	// the same signing key -- i.e. the key genuinely lives in Postgres, not
	// in B's process memory.
	req, _ := http.NewRequest(http.MethodGet, instanceA+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	uiResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("userinfo on instance A: %v", err)
	}
	defer uiResp.Body.Close()
	if uiResp.StatusCode != http.StatusOK {
		t.Fatalf("expected instance A to verify a token signed by instance B, got %d", uiResp.StatusCode)
	}
	var uiBody map[string]any
	if err := json.NewDecoder(uiResp.Body).Decode(&uiBody); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}
	if uiBody["sub"] != "jsmith" {
		t.Fatalf("expected sub=jsmith, got %v", uiBody["sub"])
	}

	// And both instances' JWKS documents must agree on the key actually used.
	claims := jwt.MapClaims{}
	parsedToken, _, err := jwt.NewParser().ParseUnverified(idToken, claims)
	if err != nil {
		t.Fatalf("parse id_token: %v", err)
	}
	kid, _ := parsedToken.Header["kid"].(string)
	if kid == "" {
		t.Fatal("expected a kid header on the id_token")
	}
	for _, instance := range []string{instanceA, instanceB} {
		jwksResp, err := http.Get(instance + "/.well-known/jwks.json")
		if err != nil {
			t.Fatalf("get jwks from %s: %v", instance, err)
		}
		var jwks struct {
			Keys []map[string]any `json:"keys"`
		}
		decodeErr := json.NewDecoder(jwksResp.Body).Decode(&jwks)
		jwksResp.Body.Close()
		if decodeErr != nil {
			t.Fatalf("decode jwks from %s: %v", instance, decodeErr)
		}
		found := false
		for _, k := range jwks.Keys {
			if k["kid"] == kid {
				found = true
			}
		}
		if !found {
			t.Errorf("expected kid %q (used to sign a token on instance B) to appear in %s's JWKS too", kid, instance)
		}
	}
}

// TestHA_OIDC_RefreshRotationAndRevocationAcrossInstances proves refresh
// token rotation/reuse-detection and access-token revocation are also
// cluster-wide: a refresh token minted on one instance rotates correctly
// when redeemed on another (shared `sessions` table), a replayed
// rotated-away refresh token is detected and the whole session revoked
// regardless of which instance sees the replay, and revoking an access
// token on one instance is honored immediately by a different instance's
// /userinfo (shared oidc_revoked_tokens denylist, checked on every request
// rather than cached per-process).
func TestHA_OIDC_RefreshRotationAndRevocationAcrossInstances(t *testing.T) {
	dsn := testDSN(t)
	setupPool(t)
	pool, err := poolFor(t, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	seedPassword(t, pool, "jsmith", "Secret123!")

	instanceA := newHAInstance(t, dsn, "", nil)
	instanceB := newHAInstance(t, dsn, "", nil)

	code, verifier := obtainOIDCCodeFrom(t, instanceA)
	tokenResp, err := http.PostForm(instanceA+"/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"client_id": {"example-client"}, "redirect_uri": {"http://localhost:9000/callback"},
	})
	if err != nil {
		t.Fatalf("post token on instance A: %v", err)
	}
	var body map[string]any
	decodeErr := json.NewDecoder(tokenResp.Body).Decode(&body)
	tokenResp.Body.Close()
	if decodeErr != nil {
		t.Fatalf("decode token response: %v", decodeErr)
	}
	firstRefresh, _ := body["refresh_token"].(string)
	if firstRefresh == "" {
		t.Fatalf("expected a refresh_token, got %v", body)
	}

	// Rotate on the *other* instance.
	refreshResp, err := http.PostForm(instanceB+"/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {firstRefresh}, "client_id": {"example-client"},
	})
	if err != nil {
		t.Fatalf("post refresh on instance B: %v", err)
	}
	var refreshBody map[string]any
	decodeErr = json.NewDecoder(refreshResp.Body).Decode(&refreshBody)
	refreshResp.Body.Close()
	if decodeErr != nil {
		t.Fatalf("decode refresh response: %v", decodeErr)
	}
	if refreshResp.StatusCode != http.StatusOK {
		t.Fatalf("expected instance B to rotate a refresh token minted by instance A, got %d: %v", refreshResp.StatusCode, refreshBody)
	}
	secondRefresh, _ := refreshBody["refresh_token"].(string)
	secondAccess, _ := refreshBody["access_token"].(string)
	if secondRefresh == "" || secondAccess == "" {
		t.Fatalf("expected a full token set from instance B, got %v", refreshBody)
	}

	// Replay the rotated-away first refresh token, against instance A this
	// time -- reuse detection must fire regardless of which instance
	// performed the original rotation, since it's keyed off shared state.
	replayResp, err := http.PostForm(instanceA+"/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {firstRefresh}, "client_id": {"example-client"},
	})
	if err != nil {
		t.Fatalf("post replay on instance A: %v", err)
	}
	replayResp.Body.Close()
	if replayResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 replaying a rotated-away refresh token on instance A, got %d", replayResp.StatusCode)
	}

	// The whole session is now revoked (reuse detection), so even the
	// *current* (second-generation) refresh token must be rejected too --
	// checked here on instance B, the instance that isn't the one that just
	// rejected the replay.
	secondUseResp, err := http.PostForm(instanceB+"/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {secondRefresh}, "client_id": {"example-client"},
	})
	if err != nil {
		t.Fatalf("post second use on instance B: %v", err)
	}
	secondUseResp.Body.Close()
	if secondUseResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected reuse detection to have revoked the session cluster-wide, got %d", secondUseResp.StatusCode)
	}

	// Access-token revocation: revoke the second access token via instance
	// A, confirm instance B's /userinfo rejects it immediately.
	revokeResp, err := http.PostForm(instanceA+"/revoke", url.Values{
		"token": {secondAccess}, "client_id": {"example-client"},
	})
	if err != nil {
		t.Fatalf("post revoke on instance A: %v", err)
	}
	revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from revoke, got %d", revokeResp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, instanceB+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+secondAccess)
	uiResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("userinfo on instance B: %v", err)
	}
	defer uiResp.Body.Close()
	if uiResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected instance B to honor revocation performed on instance A, got %d", uiResp.StatusCode)
	}
}
