package oidcserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"declarativeauth/internal/auth"
	"declarativeauth/internal/config"
	"declarativeauth/internal/identity"
	"declarativeauth/internal/store"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Provider is the minimal OIDC authorization-code+PKCE provider. Registered
// clients are read from Snapshot() (identity.Snapshot.OIDCClients) on every
// request rather than cached at startup, so oidc-clients.yaml edits
// hot-reload the same way users.yaml/groups.yaml already do.
type Provider struct {
	Issuer          string
	Keys            *KeyStore
	Codes           *store.OIDCCodeStore
	Sessions        *store.SessionStore
	Revocations     *store.RevokedTokenStore
	RefreshTokenTTL time.Duration
	Snapshot        func() *identity.Snapshot
	// CurrentUserWithAuthTime resolves the web session cookie on a request
	// to a username and when that session was first created (a proxy for
	// OIDC's auth_time), used to honor the authorize request's max_age.
	CurrentUserWithAuthTime func(r *http.Request) (username string, authTime time.Time, ok bool)
	Logger                  *slog.Logger
	// RateLimiter throttles /token by client_id and source IP (nil disables
	// throttling entirely). Shares the same persisted backoff mechanism as
	// login/password-reset -- see auth.RateLimiter -- so client-secret
	// guessing and authorization-code/refresh-token brute-forcing can't run
	// unthrottled the way they could before.
	RateLimiter    *auth.RateLimiter
	TrustedProxies *auth.TrustedProxies
	// Logout clears the caller's web session cookie/row (RP-Initiated
	// Logout, see handleEndSession) -- typically web.SessionManager.Clear.
	// A plain func(w, r) rather than importing the web package directly,
	// matching how CurrentUserWithAuthTime is threaded in.
	Logout func(w http.ResponseWriter, r *http.Request)
}

// NewProvider builds a Provider from server config.
func NewProvider(cfg *config.ServerConfig, keys *KeyStore, codes *store.OIDCCodeStore, sessions *store.SessionStore, revocations *store.RevokedTokenStore, snapshot func() *identity.Snapshot, currentUserWithAuthTime func(r *http.Request) (string, time.Time, bool), logout func(w http.ResponseWriter, r *http.Request), logger *slog.Logger, rateLimiter *auth.RateLimiter, trustedProxies *auth.TrustedProxies) *Provider {
	return &Provider{
		Issuer:                  cfg.OIDC.Issuer,
		Keys:                    keys,
		Codes:                   codes,
		Sessions:                sessions,
		Revocations:             revocations,
		RefreshTokenTTL:         cfg.OIDC.RefreshTokenTTL.Std(),
		Snapshot:                snapshot,
		CurrentUserWithAuthTime: currentUserWithAuthTime,
		Logout:                  logout,
		Logger:                  logger,
		RateLimiter:             rateLimiter,
		TrustedProxies:          trustedProxies,
	}
}

// clientIP resolves the request's client IP through TrustedProxies, or ""
// if that's unset/unresolvable -- RateLimiter treats an empty IP key as
// "skip the IP dimension", the same convention used elsewhere.
func (p *Provider) clientIP(r *http.Request) string {
	if p.TrustedProxies == nil {
		return ""
	}
	if ip := p.TrustedProxies.ClientIP(r); ip != nil {
		return ip.String()
	}
	return ""
}

// tokenRateLimited checks (and, if locked, responds to) the /token rate
// limit for clientID + the request's source IP. Returns true if the
// request was rejected (response already written) and processing must stop.
func (p *Provider) tokenRateLimited(w http.ResponseWriter, r *http.Request, clientID string) bool {
	if p.RateLimiter == nil {
		return false
	}
	locked, err := p.RateLimiter.IsLocked(r.Context(), clientID, p.clientIP(r))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return true
	}
	if locked {
		writeTokenError(w, http.StatusTooManyRequests, "slow_down")
		return true
	}
	return false
}

func (p *Provider) recordTokenFailure(r *http.Request, clientID string) {
	if p.RateLimiter == nil {
		return
	}
	if err := p.RateLimiter.RecordFailure(r.Context(), clientID, p.clientIP(r)); err != nil && p.Logger != nil {
		p.Logger.Error("failed to record token failure for rate limiting", "component", "oidcserver", "error", err)
	}
}

func (p *Provider) recordTokenSuccess(r *http.Request, clientID string) {
	if p.RateLimiter == nil {
		return
	}
	if err := p.RateLimiter.RecordSuccess(r.Context(), clientID, p.clientIP(r)); err != nil && p.Logger != nil {
		p.Logger.Error("failed to record token success for rate limiting", "component", "oidcserver", "error", err)
	}
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// containsToken reports whether token appears among spaceDelimited's
// space-separated values -- used for the "prompt" authorize parameter,
// which OIDC Core defines as a space-delimited list (e.g. "login consent").
func containsToken(spaceDelimited, token string) bool {
	for _, t := range strings.Fields(spaceDelimited) {
		if t == token {
			return true
		}
	}
	return false
}

// NewMux builds the http.ServeMux for the OIDC provider surface.
//
// CORS is deliberately split in two tiers: discovery/JWKS carry no secrets
// and exist specifically so an RP can bootstrap itself before it's done
// anything provider-specific, so they're open to any origin
// (Access-Control-Allow-Origin: *). /token, /userinfo, /revoke, and
// /introspect are scoped to origins matching a registered client's
// redirect_uri (see originAllowed) -- this is what makes the PKCE public-
// client flow actually usable from a browser-based SPA calling fetch()
// directly, which the server already supported at the protocol level but
// couldn't serve to a browser without this. /authorize is a full-page
// navigation/redirect, never a fetch() target, so it carries no CORS
// headers at all.
func (p *Provider) NewMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", withOpenCORS(p.handleDiscovery))
	mux.HandleFunc("/.well-known/jwks.json", withOpenCORS(p.handleJWKS))
	mux.HandleFunc("/authorize", p.handleAuthorize)
	mux.HandleFunc("/token", p.withCORS(p.handleToken))
	mux.HandleFunc("/userinfo", p.withCORS(p.handleUserinfo))
	mux.HandleFunc("/revoke", p.withCORS(p.handleRevoke))
	mux.HandleFunc("/introspect", p.withCORS(p.handleIntrospect))
	mux.HandleFunc("/endsession", p.handleEndSession)
	return mux
}

// withOpenCORS marks a response as fetchable from any origin -- for
// endpoints that are public metadata with no secrets and no per-caller
// behavior (discovery, JWKS).
func withOpenCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h(w, r)
	}
}

// originAllowed reports whether origin (scheme://host[:port]) matches a
// registered redirect_uri's origin for any client -- the same trust
// boundary /authorize already enforces (RedirectURIAllowed), reused here
// rather than a separate allowlist so there's one place that defines "an
// origin this deployment's clients actually run on".
func (p *Provider) originAllowed(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	target := u.Scheme + "://" + u.Host
	for _, c := range p.Snapshot().OIDCClients {
		for _, ru := range c.RedirectURIs {
			ruURL, err := url.Parse(ru)
			if err == nil && ruURL.Scheme+"://"+ruURL.Host == target {
				return true
			}
		}
	}
	return false
}

// withCORS allows cross-origin fetch() calls only from an origin registered
// on some client's redirect_uri (see originAllowed) -- unlike
// withOpenCORS, these endpoints can involve a bearer token or client
// credentials, so a blanket "*" would let any web page read the response.
func (p *Provider) withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowed := origin != "" && p.originAllowed(origin)
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			if allowed {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Max-Age", "600")
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h(w, r)
	}
}

func (p *Provider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                p.Issuer,
		"authorization_endpoint":                p.Issuer + "/authorize",
		"token_endpoint":                        p.Issuer + "/token",
		"userinfo_endpoint":                     p.Issuer + "/userinfo",
		"jwks_uri":                              p.Issuer + "/.well-known/jwks.json",
		"revocation_endpoint":                   p.Issuer + "/revoke",
		"introspection_endpoint":                p.Issuer + "/introspect",
		"end_session_endpoint":                  p.Issuer + "/endsession",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": p.Keys.SupportedAlgorithms(),
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
		"revocation_endpoint_auth_methods_supported":   []string{"none", "client_secret_post", "client_secret_basic"},
		"introspection_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
		"code_challenge_methods_supported":               []string{"S256"},
		"claims_supported":                               []string{"sub", "email", "name", "given_name", "family_name", "preferred_username", "groups"},
		"claims_parameter_supported":                      false,
		"request_uri_parameter_supported":                 false,
		"require_request_uri_registration":                false,
		"prompt_values_supported":                         []string{"none", "login"},
		"backchannel_logout_supported":                    false,
		"frontchannel_logout_supported":                   false,
	})
}

func (p *Provider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	keys, err := p.Keys.JWKS()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"keys": keys})
}

func (p *Provider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	scope := q.Get("scope")
	state := q.Get("state")
	nonce := q.Get("nonce")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	prompt := q.Get("prompt")
	loginHint := q.Get("login_hint")
	maxAge := q.Get("max_age")
	// acr_values is accepted (so a client sending it doesn't get an
	// unrecognized-parameter error) but not enforced: there's only one
	// authentication context here (password or passkey via the shared web
	// login), no distinct ACR tiers to select between.
	_ = q.Get("acr_values")

	// redirect_uri must be present and pre-registered before we can trust it
	// enough to redirect errors to it at all (RFC 6749 §4.1.2.1) -- an
	// empty/unregistered value can only be reported inline, never via
	// redirect, since redirecting to it is exactly the open-redirect risk
	// this check exists to prevent.
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	client, ok := p.Snapshot().OIDCClients[clientID]
	if !ok || !RedirectURIAllowed(client, redirectURI) {
		http.Error(w, "unknown client_id or redirect_uri", http.StatusBadRequest)
		return
	}
	if responseType != "code" {
		p.redirectError(w, r, redirectURI, state, "unsupported_response_type", "only response_type=code is supported")
		return
	}
	if client.Public && (codeChallenge == "" || codeChallengeMethod != "S256") {
		p.redirectError(w, r, redirectURI, state, "invalid_request", "PKCE (code_challenge with code_challenge_method=S256) is required for public clients")
		return
	}

	username, authTime, authenticated := p.CurrentUserWithAuthTime(r)

	// A grace window rather than a literal "every single time": prompt=login
	// means force fresh interactive credentials, but once the user has just
	// done that (this same round trip: /authorize -> /login -> back here),
	// authTime is only moments old and we must let them through -- otherwise
	// prompt=login would redirect to /login forever, since the query string
	// (and so prompt=login itself) round-trips via return_to.
	needsReauth := authenticated && containsToken(prompt, "login") && time.Since(authTime) > 5*time.Second
	if authenticated && !needsReauth && maxAge != "" {
		if seconds, err := strconv.Atoi(maxAge); err == nil && seconds >= 0 {
			needsReauth = time.Since(authTime) > time.Duration(seconds)*time.Second
		}
	}

	if !authenticated || needsReauth {
		if containsToken(prompt, "none") {
			// OIDC Core §3.1.2.1: prompt=none means never show UI -- if we
			// can't silently satisfy the request, fail instead of
			// redirecting to a login page the caller explicitly said not to
			// show.
			p.redirectError(w, r, redirectURI, state, "login_required", "no active session satisfies the request without user interaction")
			return
		}
		loginURL := "/login?return_to=" + url.QueryEscape(r.URL.RequestURI())
		if containsToken(prompt, "login") {
			loginURL += "&prompt=login"
		}
		if loginHint != "" {
			loginURL += "&login_hint=" + url.QueryEscape(loginHint)
		}
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}

	code, err := randomToken(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ac := store.OIDCAuthCode{
		Code: code, ClientID: clientID, Username: username, RedirectURI: redirectURI, Scope: scope,
		Nonce: nonce, CodeChallenge: codeChallenge, CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt: time.Now().Add(2 * time.Minute),
	}
	if err := p.Codes.Insert(r.Context(), ac); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	dest, _ := url.Parse(redirectURI)
	qs := dest.Query()
	qs.Set("code", code)
	qs.Set("iss", p.Issuer) // RFC 9207: lets the RP detect mix-up attacks across issuers
	if state != "" {
		qs.Set("state", state)
	}
	dest.RawQuery = qs.Encode()
	http.Redirect(w, r, dest.String(), http.StatusSeeOther)
}

func (p *Provider) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, description string) {
	dest, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, errCode, http.StatusBadRequest)
		return
	}
	qs := dest.Query()
	qs.Set("error", errCode)
	if description != "" {
		qs.Set("error_description", description)
	}
	qs.Set("iss", p.Issuer)
	if state != "" {
		qs.Set("state", state)
	}
	dest.RawQuery = qs.Encode()
	http.Redirect(w, r, dest.String(), http.StatusSeeOther)
}

func (p *Provider) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	switch r.FormValue("grant_type") {
	case "authorization_code":
		p.handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		p.handleRefreshTokenGrant(w, r)
	case "client_credentials":
		p.handleClientCredentialsGrant(w, r)
	default:
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

// authenticateClient validates client credentials the way RFC 6749 §2.3.1
// requires: HTTP Basic (client_secret_basic) takes precedence over the POST
// body (client_secret_post) when both are present, and a Basic-auth
// client_id must match the form's if both are given. Shared across every
// /token grant type. Writes the RFC 6749 §5.2 invalid_client error itself on
// failure.
func (p *Provider) authenticateClient(w http.ResponseWriter, r *http.Request) (client identity.OIDCClient, clientID string, ok bool) {
	clientID = r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	if basicID, basicSecret, hasBasic := r.BasicAuth(); hasBasic {
		if basicID != clientID && clientID != "" {
			writeTokenClientAuthError(w, "invalid_client")
			return identity.OIDCClient{}, "", false
		}
		clientID = basicID
		clientSecret = basicSecret
	}

	if p.tokenRateLimited(w, r, clientID) {
		return identity.OIDCClient{}, "", false
	}

	client, found := p.Snapshot().OIDCClients[clientID]
	if !found {
		p.recordTokenFailure(r, clientID)
		writeTokenClientAuthError(w, "invalid_client")
		return identity.OIDCClient{}, "", false
	}
	if !client.Public && subtle.ConstantTimeCompare([]byte(clientSecret), []byte(client.ClientSecret)) != 1 {
		p.recordTokenFailure(r, clientID)
		writeTokenClientAuthError(w, "invalid_client")
		return identity.OIDCClient{}, "", false
	}
	return client, clientID, true
}

func (p *Provider) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	_, clientID, ok := p.authenticateClient(w, r)
	if !ok {
		return
	}

	code := r.FormValue("code")
	verifier := r.FormValue("code_verifier")
	redirectURI := r.FormValue("redirect_uri")

	ac, err := p.Codes.Redeem(r.Context(), code)
	if err != nil || ac.ClientID != clientID {
		p.recordTokenFailure(r, clientID)
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	// RFC 6749 §4.1.3: since /authorize always requires a redirect_uri
	// (see RedirectURIAllowed), the token request's must match it exactly.
	if redirectURI != ac.RedirectURI {
		p.recordTokenFailure(r, clientID)
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if ac.CodeChallenge == "" {
		// A code_verifier with no code_challenge on file means either a
		// confused client or an attempt to slip PKCE material into a code
		// that never went through PKCE at /authorize -- reject outright
		// rather than silently ignoring it.
		if verifier != "" {
			p.recordTokenFailure(r, clientID)
			writeTokenError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
	} else {
		sum := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(sum[:])
		if computed != ac.CodeChallenge {
			p.recordTokenFailure(r, clientID)
			writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "PKCE verification failed"})
			return
		}
	}

	idToken, accessToken, err := p.issueTokens(ac.Username, clientID, ac.Scope, ac.Nonce)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	refreshToken, err := p.issueRefreshToken(r.Context(), ac.Username, clientID, ac.Scope)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	p.recordTokenSuccess(r, clientID)
	writeJSON(w, map[string]any{
		"access_token":  accessToken,
		"id_token":      idToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    900,
	})
}

func (p *Provider) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	_, clientID, ok := p.authenticateClient(w, r)
	if !ok {
		return
	}

	sessionID, secret, ok := strings.Cut(r.FormValue("refresh_token"), ".")
	if !ok {
		p.recordTokenFailure(r, clientID)
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	id, err := uuid.Parse(sessionID)
	if err != nil {
		p.recordTokenFailure(r, clientID)
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	newSecret, err := randomToken(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sess, err := p.Sessions.RotateRefreshToken(r.Context(), id, hashToken(secret), hashToken(newSecret), time.Now().Add(p.RefreshTokenTTL))
	if err != nil {
		if err == store.ErrRefreshTokenReused && p.Logger != nil {
			p.Logger.Warn("refresh token reuse detected, session revoked", "component", "oidcserver", "session_id", sessionID, "client_id", clientID)
		}
		p.recordTokenFailure(r, clientID)
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if sess.ClientID != clientID {
		p.recordTokenFailure(r, clientID)
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	idToken, accessToken, err := p.issueTokens(sess.Username, clientID, sess.Scope, "")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	p.recordTokenSuccess(r, clientID)
	writeJSON(w, map[string]any{
		"access_token":  accessToken,
		"id_token":      idToken,
		"refresh_token": id.String() + "." + newSecret,
		"token_type":    "Bearer",
		"expires_in":    900,
	})
}

// handleClientCredentialsGrant is the machine-to-machine grant (RFC 6749
// §4.4): no user context, no ID token, no refresh token -- a service client
// can just request a new access token directly using its own credentials.
// Restricted to confidential clients: a "public" client has no secret to
// authenticate with, so allowing it here would let anyone claiming a known
// public client_id mint tokens with no proof of identity at all.
func (p *Provider) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	client, clientID, ok := p.authenticateClient(w, r)
	if !ok {
		return
	}
	if client.Public {
		p.recordTokenFailure(r, clientID)
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client")
		return
	}

	scope := r.FormValue("scope")
	jti, err := randomToken(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	accessToken, err := p.sign(jwt.MapClaims{
		"iss": p.Issuer, "sub": clientID, "aud": clientID, "scope": scope, "jti": jti,
		"exp": now.Add(15 * time.Minute).Unix(), "iat": now.Unix(),
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	p.recordTokenSuccess(r, clientID)
	writeJSON(w, map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   900,
		"scope":        scope,
	})
}

// issueTokens signs a fresh ID token + access token pair for username/scope.
// Each gets its own random jti claim, which /revoke and /introspect use to
// denylist/inspect an individual token ahead of its natural expiry (see
// store.RevokedTokenStore) -- otherwise a self-contained JWT has no
// server-side revocation point at all.
//
// The access token is signed first so its at_hash (OIDC Core §3.1.3.6) can
// go in the ID token: a hash of the access token that lets the RP verify
// the two weren't mismatched/substituted in transit. Both are always
// returned from /token in the same response here (this provider has no
// implicit/hybrid flow, which is the only case at_hash is strictly
// required), but including it is cheap and some conformance suites expect
// it whenever both tokens are present.
func (p *Provider) issueTokens(username, clientID, scope, nonce string) (idToken, accessToken string, err error) {
	snap := p.Snapshot()
	now := time.Now()

	accessJTI, err := randomToken(16)
	if err != nil {
		return "", "", err
	}
	accessClaims := jwt.MapClaims{
		"iss": p.Issuer, "sub": username, "aud": clientID, "scope": scope, "jti": accessJTI,
		"exp": now.Add(15 * time.Minute).Unix(), "iat": now.Unix(),
	}
	accessToken, err = p.sign(accessClaims)
	if err != nil {
		return "", "", err
	}

	idJTI, err := randomToken(16)
	if err != nil {
		return "", "", err
	}
	idClaims := jwt.MapClaims{
		"iss": p.Issuer, "sub": username, "aud": clientID, "jti": idJTI, "at_hash": atHash(accessToken),
		"exp": now.Add(15 * time.Minute).Unix(), "iat": now.Unix(),
	}
	if nonce != "" {
		idClaims["nonce"] = nonce
	}
	for k, v := range Claims(snap, username, scope) {
		if k != "sub" {
			idClaims[k] = v
		}
	}
	idToken, err = p.sign(idClaims)
	if err != nil {
		return "", "", err
	}
	return idToken, accessToken, nil
}

// atHash computes the OIDC Core §3.1.3.6 at_hash: the left half of
// SHA-256(access_token), base64url-encoded. Both of this provider's signing
// algorithms (ES256, RS256) specify SHA-256 (the "256" in each name), so the
// hash function doesn't need to vary by key the way the spec allows for.
func atHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// issueRefreshToken creates a new session row (the same store backing the
// web login cookie, see store.Session) and returns the opaque bearer value
// "<session id>.<secret>" -- the id names the row for lookup, the secret is
// what's hashed and compared, exactly like the web session cookie format.
func (p *Provider) issueRefreshToken(ctx context.Context, username, clientID, scope string) (string, error) {
	secret, err := randomToken(32)
	if err != nil {
		return "", err
	}
	id := uuid.New()
	if err := p.Sessions.Create(ctx, store.Session{
		ID: id, Username: username, ClientID: clientID, Scope: scope,
		RefreshTokenHash: hashToken(secret), ExpiresAt: time.Now().Add(p.RefreshTokenTTL),
	}); err != nil {
		return "", err
	}
	return id.String() + "." + secret, nil
}

// writeTokenError writes an RFC 6749 §5.2-shaped error body with the
// required non-200 status code, so client libraries branch on status
// rather than trying to parse the body as a successful token response.
func writeTokenError(w http.ResponseWriter, status int, errCode string) {
	writeJSONStatus(w, status, map[string]any{"error": errCode})
}

// writeTokenClientAuthError writes an invalid_client failure per RFC 6749
// §5.2: 401 with a WWW-Authenticate challenge.
func writeTokenClientAuthError(w http.ResponseWriter, errCode string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="oidc"`)
	writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"error": errCode})
}

func (p *Provider) sign(claims jwt.MapClaims) (string, error) {
	key := p.Keys.Current()
	token := jwt.NewWithClaims(key.SigningMethod(), claims)
	token.Header["kid"] = key.Kid
	return token.SignedString(key.Signer)
}

// parseAccessOrIDToken verifies raw as a JWT signed by this provider (any
// active key/algorithm) and, if valid and not individually revoked, returns
// its claims. Shared by /userinfo, /introspect, and /revoke.
func (p *Provider) parseAccessOrIDToken(ctx context.Context, raw string) (jwt.MapClaims, bool) {
	token, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		key, ok := p.Keys.Lookup(ctx, kid)
		if !ok {
			return nil, fmt.Errorf("unknown key id %q", kid)
		}
		return key.Signer.Public(), nil
	}, jwt.WithValidMethods([]string{"ES256", "RS256"}))
	if err != nil || !token.Valid {
		return nil, false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, false
	}
	if jti, _ := claims["jti"].(string); jti != "" && p.Revocations != nil {
		if revoked, err := p.Revocations.IsRevoked(ctx, jti); err != nil || revoked {
			return nil, false
		}
	}
	return claims, true
}

func (p *Provider) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	authz := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(authz) <= len(prefix) || authz[:len(prefix)] != prefix {
		unauthorizedUserinfo(w, "invalid_token", "missing bearer token")
		return
	}
	raw := authz[len(prefix):]

	claims, ok := p.parseAccessOrIDToken(r.Context(), raw)
	if !ok {
		unauthorizedUserinfo(w, "invalid_token", "the access token is malformed, expired, or revoked")
		return
	}
	sub, _ := claims["sub"].(string)
	scope, _ := claims["scope"].(string)

	snap := p.Snapshot()
	writeJSON(w, Claims(snap, sub, scope))
}

// unauthorizedUserinfo rejects a bearer token per RFC 6750 §3, which
// requires a WWW-Authenticate challenge on 401 responses -- both there and
// in a JSON body, so clients that only look at the body (rather than
// parsing the challenge header) still get a machine-readable reason.
func unauthorizedUserinfo(w http.ResponseWriter, errCode, description string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="`+errCode+`", error_description="`+description+`"`)
	writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"error": errCode, "error_description": description})
}

// handleIntrospect implements RFC 7662: given a token (access, ID, or
// refresh), report whether it's currently active plus a few standard
// fields. Always 200 with {"active": false} for anything invalid/expired/
// revoked/not-recognized -- per RFC 7662 §2.2, this endpoint never signals
// "invalid token" via an error status, since doing so would let a client
// distinguish "malformed" from "valid but revoked", an oracle the spec
// deliberately avoids.
func (p *Provider) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if _, _, ok := p.authenticateClient(w, r); !ok {
		return
	}

	raw := r.FormValue("token")
	if claims, ok := p.parseAccessOrIDToken(r.Context(), raw); ok {
		resp := map[string]any{
			"active": true, "token_type": "Bearer",
			"iss": claims["iss"], "sub": claims["sub"], "aud": claims["aud"],
			"exp": claims["exp"], "iat": claims["iat"], "client_id": claims["aud"],
		}
		if scope, ok := claims["scope"]; ok {
			resp["scope"] = scope
		}
		writeJSON(w, resp)
		return
	}

	if sessionID, secret, ok := strings.Cut(raw, "."); ok {
		if id, err := uuid.Parse(sessionID); err == nil {
			if sess, err := p.Sessions.GetByID(r.Context(), id); err == nil {
				valid := sess.RevokedAt == nil && time.Now().Before(sess.ExpiresAt) &&
					subtle.ConstantTimeCompare([]byte(sess.RefreshTokenHash), []byte(hashToken(secret))) == 1
				if valid {
					writeJSON(w, map[string]any{
						"active": true, "token_type": "refresh_token",
						"sub": sess.Username, "client_id": sess.ClientID, "scope": sess.Scope,
						"exp": sess.ExpiresAt.Unix(),
					})
					return
				}
			}
		}
	}

	writeJSON(w, map[string]any{"active": false})
}

// handleRevoke implements RFC 7009. Accepts either a refresh token
// ("<session id>.<secret>") or a self-contained access/ID token JWT.
// Per RFC 7009 §2.2, always responds 200 regardless of whether the token
// was found/valid/already-revoked (only a client authentication failure
// gets a different status), so the endpoint can't be used to probe which
// tokens are live.
func (p *Provider) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	_, clientID, ok := p.authenticateClient(w, r)
	if !ok {
		return
	}

	raw := r.FormValue("token")

	if sessionID, secret, cut := strings.Cut(raw, "."); cut {
		if id, err := uuid.Parse(sessionID); err == nil {
			if sess, err := p.Sessions.GetByID(r.Context(), id); err == nil &&
				sess.ClientID == clientID &&
				subtle.ConstantTimeCompare([]byte(sess.RefreshTokenHash), []byte(hashToken(secret))) == 1 {
				_ = p.Sessions.Revoke(r.Context(), id)
			}
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	if claims, ok := p.parseAccessOrIDToken(r.Context(), raw); ok && claims["aud"] == clientID {
		if jti, _ := claims["jti"].(string); jti != "" && p.Revocations != nil {
			if expFloat, ok := claims["exp"].(float64); ok {
				_ = p.Revocations.Revoke(r.Context(), jti, time.Unix(int64(expFloat), 0))
			}
		}
	}
	w.WriteHeader(http.StatusOK)
}

// handleEndSession implements RP-Initiated Logout: it clears the caller's
// web session (so /authorize won't silently treat them as still logged in),
// then either redirects to post_logout_redirect_uri -- only if it's
// pre-registered for the client, the same open-redirect guard /authorize's
// redirect_uri already gets -- or renders a plain confirmation.
//
// id_token_hint, if present and verifiable, is authoritative for which
// client's post_logout_redirect_uri list to check, overriding a client_id
// query parameter -- an attacker shouldn't be able to redirect to a URI
// registered for a *different* client just by naming it in the query string.
func (p *Provider) handleEndSession(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	idTokenHint := r.FormValue("id_token_hint")
	postLogoutURI := r.FormValue("post_logout_redirect_uri")
	state := r.FormValue("state")
	clientID := r.FormValue("client_id")

	if idTokenHint != "" {
		if claims, ok := p.parseAccessOrIDToken(r.Context(), idTokenHint); ok {
			if aud, _ := claims["aud"].(string); aud != "" {
				clientID = aud
			}
		}
	}

	if p.Logout != nil {
		p.Logout(w, r)
	}

	if postLogoutURI == "" {
		writeJSON(w, map[string]any{"status": "logged_out"})
		return
	}
	client, ok := p.Snapshot().OIDCClients[clientID]
	if !ok || !PostLogoutRedirectURIAllowed(client, postLogoutURI) {
		writeJSON(w, map[string]any{"status": "logged_out"})
		return
	}
	dest, err := url.Parse(postLogoutURI)
	if err != nil {
		writeJSON(w, map[string]any{"status": "logged_out"})
		return
	}
	if state != "" {
		qs := dest.Query()
		qs.Set("state", state)
		dest.RawQuery = qs.Encode()
	}
	http.Redirect(w, r, dest.String(), http.StatusSeeOther)
}

func writeJSON(w http.ResponseWriter, v any) {
	writeJSONStatus(w, http.StatusOK, v)
}

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
