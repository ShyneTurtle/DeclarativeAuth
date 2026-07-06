package web

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"declarativeauth/internal/auth"
	"declarativeauth/internal/identity"
	"declarativeauth/internal/store"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	webauthnCeremonyCookieName = "da_webauthn_ceremony"
	webauthnCeremonyTTL        = 5 * time.Minute
)

// webauthnUser adapts a resolved account (identity.Snapshot user + their
// stored passkeys) to the go-webauthn webauthn.User interface. The user's
// WebAuthn "handle" is simply their username: usernames are this project's
// stable, immutable natural key (see identity.Snapshot), so there's no
// separate opaque user ID to maintain.
type webauthnUser struct {
	username    string
	displayName string
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte                         { return []byte(u.username) }
func (u *webauthnUser) WebAuthnName() string                       { return u.username }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// PasskeyHandlers wires the WebAuthn registration and login ceremony
// endpoints (JSON APIs, called from webauthn.js). The user-facing passkey
// list/add/remove UI lives on the home page (Handlers.handleHome,
// registered at "/"), which reads the same WebAuthnCredentialStore.
type PasskeyHandlers struct {
	WebAuthn       *webauthn.WebAuthn
	Credentials    *store.WebAuthnCredentialStore
	Ceremonies     *store.WebAuthnCeremonyStore
	Snapshot       func() *identity.Snapshot
	Sessions       *SessionManager
	TrustedProxies *auth.TrustedProxies
	Audit          *store.AuditStore

	// OnLoginResult is an optional metrics hook, mirroring Handlers.OnLoginResult
	// so passkey logins feed the same declarativeauth_login_attempts_total /
	// _duration_seconds metrics under protocol="passkey".
	OnLoginResult func(success bool, duration time.Duration)

	Logger *slog.Logger
}

// RegisterRoutes mounts the register/login ceremony endpoints on mux.
func (h *PasskeyHandlers) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/webauthn/register/start", h.handleRegisterStart)
	mux.HandleFunc("/webauthn/register/finish", h.handleRegisterFinish)
	mux.HandleFunc("/webauthn/register/delete", h.handleDelete)
	mux.HandleFunc("/webauthn/login/start", h.handleLoginStart)
	mux.HandleFunc("/webauthn/login/finish", h.handleLoginFinish)
}

func (h *PasskeyHandlers) loadUser(ctx context.Context, username string) (*webauthnUser, error) {
	snap := h.Snapshot()
	displayName := username
	if u, ok := snap.Users[username]; ok {
		switch {
		case u.DisplayName != "":
			displayName = u.DisplayName
		case u.Name != "":
			displayName = u.Name
		}
	}
	stored, err := h.Credentials.ListForUser(ctx, username)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, len(stored))
	for i, sc := range stored {
		creds[i] = sc.Credential
	}
	return &webauthnUser{username: username, displayName: displayName, credentials: creds}, nil
}

func (h *PasskeyHandlers) handleRegisterStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	username, ok := h.Sessions.CurrentUser(r)
	if !ok {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	if !validCSRFHeader(r) {
		http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	user, err := h.loadUser(ctx, username)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	creation, session, err := h.WebAuthn.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExclusions(webauthn.Credentials(user.credentials).CredentialDescriptors()),
	)
	if err != nil {
		http.Error(w, "could not start passkey registration: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.saveCeremony(ctx, w, r, session); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, creation)
}

func (h *PasskeyHandlers) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	username, ok := h.Sessions.CurrentUser(r)
	if !ok {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	if !validCSRFHeader(r) {
		http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		name = "Passkey"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	session, err := h.loadCeremony(w, r, ctx)
	if err != nil {
		http.Error(w, "passkey registration session expired, please try again", http.StatusBadRequest)
		return
	}
	user, err := h.loadUser(ctx, username)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	cred, err := h.WebAuthn.FinishRegistration(user, *session, r)
	if err != nil {
		http.Error(w, "could not verify passkey: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.Credentials.Create(ctx, username, name, *cred); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if h.Audit != nil {
		if err := h.Audit.Write(ctx, store.AuditEvent{Username: username, EventType: "passkey_registered", Detail: name, UserAgent: r.UserAgent()}); err != nil && h.Logger != nil {
			h.Logger.Error("audit write failed", "component", "web", "event_type", "passkey_registered", "error", err)
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (h *PasskeyHandlers) handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	username, ok := h.Sessions.CurrentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !ValidCSRF(r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	id, err := base64.RawURLEncoding.DecodeString(r.FormValue("credential_id"))
	if err != nil {
		http.Error(w, "invalid credential id", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := h.Credentials.Delete(ctx, username, id); err != nil {
		http.Error(w, "passkey not found", http.StatusNotFound)
		return
	}
	if h.Audit != nil {
		if err := h.Audit.Write(ctx, store.AuditEvent{Username: username, EventType: "passkey_deleted", UserAgent: r.UserAgent()}); err != nil && h.Logger != nil {
			h.Logger.Error("audit write failed", "component", "web", "event_type", "passkey_deleted", "error", err)
		}
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *PasskeyHandlers) handleLoginStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	assertion, session, err := h.WebAuthn.BeginDiscoverableLogin()
	if err != nil {
		http.Error(w, "could not start passkey login", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := h.saveCeremony(ctx, w, r, session); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, assertion)
}

func (h *PasskeyHandlers) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	returnTo := sanitizeReturnTo(r.URL.Query().Get("return_to"))

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	session, err := h.loadCeremony(w, r, ctx)
	if err != nil {
		http.Error(w, "passkey login session expired, please try again", http.StatusBadRequest)
		return
	}

	start := time.Now()
	var resolvedUsername string
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		resolvedUsername = string(userHandle)
		return h.loadUser(ctx, resolvedUsername)
	}
	authedUser, cred, err := h.WebAuthn.FinishPasskeyLogin(handler, *session, r)

	success := err == nil
	if success {
		snap := h.Snapshot()
		u, exists := snap.Users[resolvedUsername]
		if !exists || !u.Enabled {
			success = false
		}
	}
	if h.OnLoginResult != nil {
		h.OnLoginResult(success, time.Since(start))
	}
	if !success {
		if h.Audit != nil {
			if err := h.Audit.Write(ctx, store.AuditEvent{Username: resolvedUsername, EventType: "passkey_login_failure", UserAgent: r.UserAgent()}); err != nil && h.Logger != nil {
				h.Logger.Error("audit write failed", "component", "web", "event_type", "passkey_login_failure", "error", err)
			}
		}
		http.Error(w, "passkey login failed", http.StatusUnauthorized)
		return
	}

	wu, _ := authedUser.(*webauthnUser)
	if err := h.Credentials.UpdateCredential(ctx, *cred); err != nil {
		if h.Logger != nil {
			h.Logger.Error("failed to update passkey credential (sign count)", "component", "web", "username", wu.username, "error", err)
		}
		if h.Audit != nil {
			if err := h.Audit.Write(ctx, store.AuditEvent{Username: wu.username, EventType: "passkey_credential_update_failed", Detail: err.Error()}); err != nil && h.Logger != nil {
				h.Logger.Error("audit write failed", "component", "web", "event_type", "passkey_credential_update_failed", "error", err)
			}
		}
	}
	if h.Audit != nil {
		if err := h.Audit.Write(ctx, store.AuditEvent{Username: wu.username, EventType: "passkey_login_success", UserAgent: r.UserAgent()}); err != nil && h.Logger != nil {
			h.Logger.Error("audit write failed", "component", "web", "event_type", "passkey_login_success", "error", err)
		}
	}

	sourceIP := h.TrustedProxies.ClientIP(r).String()
	if err := h.Sessions.Issue(ctx, w, wu.username, r.UserAgent(), sourceIP); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.clearCeremonyCookie(w)
	writeJSON(w, map[string]string{"redirect": returnTo})
}

func (h *PasskeyHandlers) saveCeremony(ctx context.Context, w http.ResponseWriter, r *http.Request, session *webauthn.SessionData) error {
	id, err := randomToken(24)
	if err != nil {
		return err
	}
	if err := h.Ceremonies.Save(ctx, id, session, webauthnCeremonyTTL); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     webauthnCeremonyCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.TrustedProxies.IsForwardedHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(webauthnCeremonyTTL.Seconds()),
	})
	return nil
}

func (h *PasskeyHandlers) loadCeremony(w http.ResponseWriter, r *http.Request, ctx context.Context) (*webauthn.SessionData, error) {
	c, err := r.Cookie(webauthnCeremonyCookieName)
	if err != nil || c.Value == "" {
		return nil, store.ErrNotFound
	}
	session, err := h.Ceremonies.Consume(ctx, c.Value)
	if err != nil {
		return nil, err
	}
	h.clearCeremonyCookie(w)
	return session, nil
}

func (h *PasskeyHandlers) clearCeremonyCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: webauthnCeremonyCookieName, Value: "", Path: "/", MaxAge: -1})
}

// validCSRFHeader is the X-CSRF-Token counterpart to ValidCSRF, for
// endpoints whose request body is consumed as raw WebAuthn JSON by the
// go-webauthn library (so the token can't travel as a form field the way it
// does everywhere else in this package).
func validCSRFHeader(r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	token := r.Header.Get("X-CSRF-Token")
	if token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(token)) == 1
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
