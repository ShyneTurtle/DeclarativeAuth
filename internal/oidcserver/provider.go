package oidcserver

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"declarativeauth/internal/config"
	"declarativeauth/internal/identity"

	"github.com/golang-jwt/jwt/v5"
)

// Provider is the minimal OIDC authorization-code+PKCE provider. Registered
// clients are read from Snapshot() (identity.Snapshot.OIDCClients) on every
// request rather than cached at startup, so oidc-clients.yaml edits
// hot-reload the same way users.yaml/groups.yaml already do.
type Provider struct {
	Issuer      string
	Keys        *KeySet
	Codes       *CodeStore
	Snapshot    func() *identity.Snapshot
	CurrentUser func(r *http.Request) (string, bool)
}

// NewProvider builds a Provider from server config.
func NewProvider(cfg *config.ServerConfig, keys *KeySet, snapshot func() *identity.Snapshot, currentUser func(r *http.Request) (string, bool)) *Provider {
	return &Provider{
		Issuer:      cfg.OIDC.Issuer,
		Keys:        keys,
		Codes:       NewCodeStore(),
		Snapshot:    snapshot,
		CurrentUser: currentUser,
	}
}

// NewMux builds the http.ServeMux for the OIDC provider surface.
func (p *Provider) NewMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.handleDiscovery)
	mux.HandleFunc("/.well-known/jwks.json", p.handleJWKS)
	mux.HandleFunc("/authorize", p.handleAuthorize)
	mux.HandleFunc("/token", p.handleToken)
	mux.HandleFunc("/userinfo", p.handleUserinfo)
	return mux
}

func (p *Provider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                p.Issuer,
		"authorization_endpoint":                p.Issuer + "/authorize",
		"token_endpoint":                        p.Issuer + "/token",
		"userinfo_endpoint":                     p.Issuer + "/userinfo",
		"jwks_uri":                              p.Issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported":                      []string{"sub", "email", "name", "preferred_username", "groups"},
	})
}

func (p *Provider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"keys": []any{p.Keys.JWK()}})
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
		redirectError(w, r, redirectURI, state, "unsupported_response_type")
		return
	}
	if client.Public && (codeChallenge == "" || codeChallengeMethod != "S256") {
		redirectError(w, r, redirectURI, state, "invalid_request")
		return
	}

	username, ok := p.CurrentUser(r)
	if !ok {
		loginURL := "/login?return_to=" + url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}

	code, err := p.Codes.Issue(AuthCode{
		ClientID: clientID, Username: username, RedirectURI: redirectURI, Scope: scope,
		Nonce: nonce, CodeChallenge: codeChallenge, CodeChallengeMethod: codeChallengeMethod,
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	dest, _ := url.Parse(redirectURI)
	qs := dest.Query()
	qs.Set("code", code)
	if state != "" {
		qs.Set("state", state)
	}
	dest.RawQuery = qs.Encode()
	http.Redirect(w, r, dest.String(), http.StatusSeeOther)
}

func redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode string) {
	dest, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, errCode, http.StatusBadRequest)
		return
	}
	qs := dest.Query()
	qs.Set("error", errCode)
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
	if r.FormValue("grant_type") != "authorization_code" {
		writeJSON(w, map[string]any{"error": "unsupported_grant_type"})
		return
	}

	code := r.FormValue("code")
	verifier := r.FormValue("code_verifier")
	clientID := r.FormValue("client_id")

	client, ok := p.Snapshot().OIDCClients[clientID]
	if !ok {
		writeJSON(w, map[string]any{"error": "invalid_client"})
		return
	}
	if !client.Public && subtle.ConstantTimeCompare([]byte(r.FormValue("client_secret")), []byte(client.ClientSecret)) != 1 {
		writeJSON(w, map[string]any{"error": "invalid_client"})
		return
	}

	ac := p.Codes.Redeem(code)
	if ac == nil || ac.ClientID != clientID {
		writeJSON(w, map[string]any{"error": "invalid_grant"})
		return
	}
	if ac.CodeChallenge != "" {
		sum := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(sum[:])
		if computed != ac.CodeChallenge {
			writeJSON(w, map[string]any{"error": "invalid_grant", "error_description": "PKCE verification failed"})
			return
		}
	}

	snap := p.Snapshot()
	now := time.Now()
	idClaims := jwt.MapClaims{
		"iss": p.Issuer, "sub": ac.Username, "aud": clientID,
		"exp": now.Add(15 * time.Minute).Unix(), "iat": now.Unix(),
	}
	if ac.Nonce != "" {
		idClaims["nonce"] = ac.Nonce
	}
	for k, v := range Claims(snap, ac.Username) {
		if k != "sub" {
			idClaims[k] = v
		}
	}
	idToken, err := p.sign(idClaims)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	accessClaims := jwt.MapClaims{
		"iss": p.Issuer, "sub": ac.Username, "aud": clientID, "scope": ac.Scope,
		"exp": now.Add(15 * time.Minute).Unix(), "iat": now.Unix(),
	}
	accessToken, err := p.sign(accessClaims)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{
		"access_token": accessToken,
		"id_token":     idToken,
		"token_type":   "Bearer",
		"expires_in":   900,
	})
}

func (p *Provider) sign(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = p.Keys.Kid
	return token.SignedString(p.Keys.PrivateKey)
}

func (p *Provider) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	authz := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(authz) <= len(prefix) || authz[:len(prefix)] != prefix {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	raw := authz[len(prefix):]

	token, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		return &p.Keys.PrivateKey.PublicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	claims, _ := token.Claims.(jwt.MapClaims)
	sub, _ := claims["sub"].(string)

	snap := p.Snapshot()
	writeJSON(w, Claims(snap, sub))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
