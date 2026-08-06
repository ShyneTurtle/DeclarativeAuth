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
	"strings"
	"time"

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
	CurrentUser     func(r *http.Request) (string, bool)
	Logger          *slog.Logger
}

// NewProvider builds a Provider from server config.
func NewProvider(cfg *config.ServerConfig, keys *KeyStore, codes *store.OIDCCodeStore, sessions *store.SessionStore, revocations *store.RevokedTokenStore, snapshot func() *identity.Snapshot, currentUser func(r *http.Request) (string, bool), logger *slog.Logger) *Provider {
	return &Provider{
		Issuer:          cfg.OIDC.Issuer,
		Keys:            keys,
		Codes:           codes,
		Sessions:        sessions,
		Revocations:     revocations,
		RefreshTokenTTL: cfg.OIDC.RefreshTokenTTL.Std(),
		Snapshot:        snapshot,
		CurrentUser:     currentUser,
		Logger:          logger,
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

// NewMux builds the http.ServeMux for the OIDC provider surface.
func (p *Provider) NewMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.handleDiscovery)
	mux.HandleFunc("/.well-known/jwks.json", p.handleJWKS)
	mux.HandleFunc("/authorize", p.handleAuthorize)
	mux.HandleFunc("/token", p.handleToken)
	mux.HandleFunc("/userinfo", p.handleUserinfo)
	mux.HandleFunc("/revoke", p.handleRevoke)
	mux.HandleFunc("/introspect", p.handleIntrospect)
	return mux
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
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": p.Keys.SupportedAlgorithms(),
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported":                      []string{"sub", "email", "name", "preferred_username", "groups"},
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

	client, ok := p.Snapshot().OIDCClients[clientID]
	if !ok || !RedirectURIAllowed(client, redirectURI) {
		http.Error(w, "unknown client_id or redirect_uri", http.StatusBadRequest)
		return
	}
	if responseType != "code" {
		p.redirectError(w, r, redirectURI, state, "unsupported_response_type")
		return
	}
	if client.Public && (codeChallenge == "" || codeChallengeMethod != "S256") {
		p.redirectError(w, r, redirectURI, state, "invalid_request")
		return
	}

	username, ok := p.CurrentUser(r)
	if !ok {
		loginURL := "/login?return_to=" + url.QueryEscape(r.URL.RequestURI())
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

func (p *Provider) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode string) {
	dest, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, errCode, http.StatusBadRequest)
		return
	}
	qs := dest.Query()
	qs.Set("error", errCode)
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

	client, found := p.Snapshot().OIDCClients[clientID]
	if !found {
		writeTokenClientAuthError(w, "invalid_client")
		return identity.OIDCClient{}, "", false
	}
	if !client.Public && subtle.ConstantTimeCompare([]byte(clientSecret), []byte(client.ClientSecret)) != 1 {
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
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	// RFC 6749 §4.1.3: since /authorize always requires a redirect_uri
	// (see RedirectURIAllowed), the token request's must match it exactly.
	if redirectURI != ac.RedirectURI {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if ac.CodeChallenge != "" {
		sum := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(sum[:])
		if computed != ac.CodeChallenge {
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
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	id, err := uuid.Parse(sessionID)
	if err != nil {
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
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if sess.ClientID != clientID {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	idToken, accessToken, err := p.issueTokens(sess.Username, clientID, sess.Scope, "")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

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

	writeJSON(w, map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   900,
		"scope":        scope,
	})
}

// issueTokens signs a fresh ID token + access token pair for username/scope.
// Each gets its own random jti claim, the handle /revoke and /introspect use
// to denylist/inspect an individual token ahead of its natural expiry (see
// store.RevokedTokenStore) -- otherwise a self-contained JWT has no
// server-side revocation point at all.
func (p *Provider) issueTokens(username, clientID, scope, nonce string) (idToken, accessToken string, err error) {
	snap := p.Snapshot()
	now := time.Now()
	idJTI, err := randomToken(16)
	if err != nil {
		return "", "", err
	}
	idClaims := jwt.MapClaims{
		"iss": p.Issuer, "sub": username, "aud": clientID, "jti": idJTI,
		"exp": now.Add(15 * time.Minute).Unix(), "iat": now.Unix(),
	}
	if nonce != "" {
		idClaims["nonce"] = nonce
	}
	for k, v := range Claims(snap, username) {
		if k != "sub" {
			idClaims[k] = v
		}
	}
	idToken, err = p.sign(idClaims)
	if err != nil {
		return "", "", err
	}

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
	return idToken, accessToken, nil
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
		unauthorizedUserinfo(w, "invalid_token")
		return
	}
	raw := authz[len(prefix):]

	claims, ok := p.parseAccessOrIDToken(r.Context(), raw)
	if !ok {
		unauthorizedUserinfo(w, "invalid_token")
		return
	}
	sub, _ := claims["sub"].(string)

	snap := p.Snapshot()
	writeJSON(w, Claims(snap, sub))
}

// unauthorizedUserinfo rejects a bearer token per RFC 6750 §3, which
// requires a WWW-Authenticate challenge on 401 responses.
func unauthorizedUserinfo(w http.ResponseWriter, errCode string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="`+errCode+`"`)
	w.WriteHeader(http.StatusUnauthorized)
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

func writeJSON(w http.ResponseWriter, v any) {
	writeJSONStatus(w, http.StatusOK, v)
}

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
