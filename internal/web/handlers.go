package web

import (
	"context"
	"encoding/base64"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"declarativeauth/internal/auth"
	"declarativeauth/internal/identity"
	"declarativeauth/internal/mail"
	"declarativeauth/internal/store"
)

// Handlers wires the web login/logout endpoints and the user's home/profile
// page to the shared auth core.
type Handlers struct {
	Authenticator  *auth.Authenticator
	Sessions       *SessionManager
	TrustedProxies *auth.TrustedProxies
	Audit          *store.AuditStore
	StaticFS       http.Handler

	// Snapshot and AdminGroup back the home page: the user's declared
	// name/email, and whether to show a link to /admin.
	Snapshot   func() *identity.Snapshot
	AdminGroup string

	// Passkeys, if non-nil, enables the passkey-management section of the
	// home page (nil when DECLARATIVEAUTH_WEBAUTHN_ENABLED is false or
	// misconfigured -- see internal/server/run.go). The home page itself is
	// always served regardless, since it's also where a user's name/email
	// live and where post-login/reset redirects with no return_to land.
	Passkeys *store.WebAuthnCredentialStore

	// Email-based MFA. Unlike Passkeys, this is a core requirement, not a
	// conditional feature, so these are always set (see internal/server/run.go)
	// and handleLoginSubmit always consults MFAPolicy after a successful
	// password check.
	MFAPolicy     *auth.MFAPolicy
	MFAChallenges *store.EmailChallengeStore
	MFAMail       *mail.Client
	MFACodeTTL    time.Duration // defaults to 10 minutes if zero, see mfaChallengeTTL

	// OnLoginResult is an optional metrics hook, called after every login
	// attempt (mirrors ldapserver.Handler.OnBind so both protocols feed the
	// same declarativeauth_login_attempts_total / _duration_seconds metrics
	// without this package importing internal/metrics directly).
	OnLoginResult func(success bool, duration time.Duration)

	Logger *slog.Logger
}

// NewMux builds the http.ServeMux for the public web surface ("/", /login,
// /logout, /static/*). Password reset and passkey routes are added in
// ResetHandlers.RegisterRoutes and PasskeyHandlers.RegisterRoutes.
func (h *Handlers) NewMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleHome)
	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc("/logout", h.handleLogout)
	mux.Handle("/static/", http.FileServer(http.FS(assetsFS)))
	return mux
}

type passkeyView struct {
	Name       string
	IDBase64   string
	CreatedAt  string
	LastUsedAt string
}

type homePageData struct {
	Title           string
	Username        string
	DisplayName     string
	Email           string
	IsAdmin         bool
	CSRFToken       string
	PasskeysEnabled bool
	Passkeys        []passkeyView
	MFARequired     bool // declaratively required: the toggle below is hidden, not just disabled
	MFASelfEnabled  bool
	Error           string
}

// handleHome serves the user's profile page: name/email, an admin-panel
// link (if applicable), and passkey management. This is "/", the default
// landing page after login and the default return_to (see
// sanitizeReturnTo).
func (h *Handlers) handleHome(w http.ResponseWriter, r *http.Request) {
	// mux.HandleFunc("/", ...) is a catch-all; only serve the profile page
	// for the exact root path and 404 everything else that fell through.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	username, ok := h.Sessions.CurrentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	secure := h.TrustedProxies.IsForwardedHTTPS(r)
	csrf := IssueCSRFToken(w, r, secure)

	var views []passkeyView
	if h.Passkeys != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		stored, err := h.Passkeys.ListForUser(ctx, username)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		views = make([]passkeyView, len(stored))
		for i, sc := range stored {
			views[i] = passkeyView{
				Name:       sc.Name,
				IDBase64:   base64.RawURLEncoding.EncodeToString(sc.Credential.ID),
				CreatedAt:  sc.CreatedAt.Format("2006-01-02 15:04"),
				LastUsedAt: "never",
			}
			if sc.LastUsedAt != nil {
				views[i].LastUsedAt = sc.LastUsedAt.Format("2006-01-02 15:04")
			}
		}
	}

	snap := h.Snapshot()
	u := snap.Users[username]

	mfaRequired := snap.MFARequiredByDeclaration(username)
	mfaSelfEnabled := false
	if h.MFAPolicy != nil && h.MFAPolicy.Settings != nil {
		var err error
		mfaSelfEnabled, err = h.MFAPolicy.Settings.IsEnabled(r.Context(), username)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	render(w, homeTmpl, homePageData{
		Title:           "My account",
		Username:        username,
		DisplayName:     u.DisplayNameOrDefault(),
		Email:           u.Email,
		IsAdmin:         h.AdminGroup != "" && snap.IsMemberOf(username, h.AdminGroup),
		CSRFToken:       csrf,
		PasskeysEnabled: h.Passkeys != nil,
		Passkeys:        views,
		MFARequired:     mfaRequired,
		MFASelfEnabled:  mfaSelfEnabled,
	})
}

type loginPageData struct {
	Title     string
	Error     string
	CSRFToken string
	ReturnTo  string
	// Username pre-fills the username field -- set from the OIDC
	// authorize request's login_hint, when /authorize redirected here.
	Username string
}

func (h *Handlers) handleLogin(w http.ResponseWriter, r *http.Request) {
	secure := h.TrustedProxies.IsForwardedHTTPS(r)
	returnTo := sanitizeReturnTo(r.URL.Query().Get("return_to"))

	// forceReauth is set when an OIDC authorize request carried
	// prompt=login: the RP explicitly asked for fresh interactive
	// credentials even if a session cookie is already live, so skip the
	// usual "already logged in" shortcut below just this once. Without
	// this, prompt=login could never actually show the form -- the
	// shortcut would immediately bounce back to return_to before the user
	// typed anything.
	forceReauth := strings.Contains(r.URL.Query().Get("prompt"), "login")

	// Covers the multi-tab case: another tab may have just logged this
	// browser in (e.g. by completing a password reset) via the same
	// shared session cookie, making this tab's still-open login form
	// stale. Rather than let it fail confusingly, notice the now-valid
	// session and finish the redirect it was already trying to do.
	if !forceReauth {
		if _, ok := h.Sessions.CurrentUser(r); ok {
			http.Redirect(w, r, returnTo, http.StatusSeeOther)
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		token := IssueCSRFToken(w, r, secure)
		render(w, loginTmpl, loginPageData{
			Title: "Log in", CSRFToken: token, ReturnTo: returnTo,
			Username: r.URL.Query().Get("login_hint"),
		})
		return
	case http.MethodPost:
		h.handleLoginSubmit(w, r, secure)
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		render(w, errorTmpl, errorPageData{Title: "Error", Message: "Method not allowed."})
	}
}

type errorPageData struct {
	Title   string
	Message string
}

func (h *Handlers) handleLoginSubmit(w http.ResponseWriter, r *http.Request, secure bool) {
	returnTo := sanitizeReturnTo(r.FormValue("return_to"))
	if !ValidCSRF(r) {
		render(w, loginTmpl, loginPageData{Title: "Log in", Error: "Your session expired, please try again.", CSRFToken: IssueCSRFToken(w, r, secure), ReturnTo: returnTo})
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	sourceIP := h.TrustedProxies.ClientIP(r).String()

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	start := time.Now()
	result, err := h.Authenticator.Authenticate(ctx, username, password, sourceIP)
	if h.OnLoginResult != nil {
		h.OnLoginResult(err == nil, time.Since(start))
	}
	eventType := "oidc_login_success"
	if err != nil {
		eventType = "oidc_login_failure"
	}
	// Audit/session identity: the canonical username Authenticate resolved
	// the identifier to when known, otherwise the raw (unresolved) input --
	// so a login via email is recorded under the same username a login via
	// the username itself would be.
	auditUsername := username
	if result != nil {
		auditUsername = result.Username
	}
	if err != nil {
		if h.Audit != nil {
			reason := ""
			var ae *auth.AuthError
			if errors.As(err, &ae) {
				reason = string(ae.Reason)
			}
			if err := h.Audit.Write(ctx, store.AuditEvent{
				Username: auditUsername, EventType: eventType, Detail: reason, UserAgent: r.UserAgent(),
			}); err != nil && h.Logger != nil {
				h.Logger.Error("audit write failed", "component", "web", "event_type", eventType, "error", err)
			}
		}
		// Generic error regardless of cause, to avoid user enumeration.
		render(w, loginTmpl, loginPageData{Title: "Log in", Error: "Invalid username or password.", CSRFToken: IssueCSRFToken(w, r, secure), ReturnTo: returnTo})
		return
	}

	if h.MFAPolicy != nil {
		mfaRequired, mfaErr := h.MFAPolicy.Required(ctx, result.Username)
		if mfaErr != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if mfaRequired {
			if h.Audit != nil {
				if err := h.Audit.Write(ctx, store.AuditEvent{Username: result.Username, EventType: "oidc_login_mfa_sent", UserAgent: r.UserAgent()}); err != nil && h.Logger != nil {
					h.Logger.Error("audit write failed", "component", "web", "event_type", "oidc_login_mfa_sent", "error", err)
				}
			}
			if err := h.startMFAChallenge(w, r, secure, result.Username, returnTo); err != nil {
				if h.Logger != nil {
					h.Logger.Error("failed to send MFA challenge email", "component", "web", "username", result.Username, "error", err)
				}
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/login/mfa", http.StatusSeeOther)
			return
		}
	}

	if h.Audit != nil {
		if err := h.Audit.Write(ctx, store.AuditEvent{Username: auditUsername, EventType: eventType, UserAgent: r.UserAgent()}); err != nil && h.Logger != nil {
			h.Logger.Error("audit write failed", "component", "web", "event_type", eventType, "error", err)
		}
	}
	if err := h.Sessions.Issue(ctx, w, result.Username, r.UserAgent(), sourceIP); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

func (h *Handlers) handleLogout(w http.ResponseWriter, r *http.Request) {
	h.Sessions.Clear(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// sanitizeReturnTo only allows same-site relative paths, guarding against
// open-redirect via a crafted return_to value.
func sanitizeReturnTo(v string) string {
	if v == "" || !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") {
		return "/"
	}
	return v
}

func render(w http.ResponseWriter, tmpl *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.ExecuteTemplate(w, "layout", data)
}
