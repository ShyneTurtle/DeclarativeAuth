package web

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"declarativeauth/internal/auth"
	"declarativeauth/internal/store"
)

// Handlers wires the web login/logout endpoints to the shared auth core.
type Handlers struct {
	Authenticator  *auth.Authenticator
	Sessions       *SessionManager
	TrustedProxies *auth.TrustedProxies
	Audit          *store.AuditStore
	StaticFS       http.Handler

	// OnLoginResult is an optional metrics hook, called after every login
	// attempt (mirrors ldapserver.Handler.OnBind so both protocols feed the
	// same declarativeauth_login_attempts_total / _duration_seconds metrics
	// without this package importing internal/metrics directly).
	OnLoginResult func(success bool, duration time.Duration)
}

// NewMux builds the http.ServeMux for the public web surface (/login,
// /logout, /static/*). Password reset routes are added in
// Handlers.RegisterResetRoutes (Section 7 reset flow).
func (h *Handlers) NewMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc("/logout", h.handleLogout)
	mux.Handle("/static/", http.FileServer(http.FS(assetsFS)))
	return mux
}

type loginPageData struct {
	Title     string
	Error     string
	CSRFToken string
	ReturnTo  string
}

func (h *Handlers) handleLogin(w http.ResponseWriter, r *http.Request) {
	secure := h.TrustedProxies.IsForwardedHTTPS(r)
	returnTo := sanitizeReturnTo(r.URL.Query().Get("return_to"))

	// Covers the multi-tab case: another tab may have just logged this
	// browser in (e.g. by completing a password reset) via the same
	// shared session cookie, making this tab's still-open login form
	// stale. Rather than let it fail confusingly, notice the now-valid
	// session and finish the redirect it was already trying to do.
	if _, ok := h.Sessions.CurrentUser(r); ok {
		http.Redirect(w, r, returnTo, http.StatusSeeOther)
		return
	}

	switch r.Method {
	case http.MethodGet:
		token := IssueCSRFToken(w, r, secure)
		render(w, loginTmpl, loginPageData{Title: "Log in", CSRFToken: token, ReturnTo: returnTo})
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
	if h.Audit != nil {
		reason := ""
		var ae *auth.AuthError
		if errors.As(err, &ae) {
			reason = string(ae.Reason)
		}
		_ = h.Audit.Write(ctx, store.AuditEvent{
			Username: auditUsername, EventType: eventType, Detail: reason, UserAgent: r.UserAgent(),
		})
	}
	if err != nil {
		// Generic error regardless of cause, to avoid user enumeration.
		render(w, loginTmpl, loginPageData{Title: "Log in", Error: "Invalid username or password.", CSRFToken: IssueCSRFToken(w, r, secure), ReturnTo: returnTo})
		return
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
