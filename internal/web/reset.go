package web

import (
	"context"
	"net/http"
	"strings"
	"time"

	"declarativeauth/internal/auth"
	"declarativeauth/internal/identity"
	"declarativeauth/internal/mail"
	"declarativeauth/internal/store"
)

// ResetHandlers wires the password reset (and first-password-setup) flow.
// The identical /reset/confirm UI is used for both cases: a user resetting
// a known password and an admin-created user setting an initial password
// for the first time, since a user with no `credentials` row is exactly the
// bootstrap state.
type ResetHandlers struct {
	Tokens   *store.ResetTokenStore
	Creds    *store.CredentialStore
	Snapshot func() *identity.Snapshot
	Mail     *mail.Client
	Hasher   *auth.Hasher
	Audit    *store.AuditStore
	TTL      time.Duration
	BaseURL  string // e.g. "https://auth.example.com", used to build the emailed link
	Policy   auth.PasswordPolicy
}

// CurrentUser resolves the requester's authenticated username from the web
// session cookie, for gating the admin-only setup-link endpoint.
type CurrentUserFunc func(r *http.Request) (string, bool)

// RegisterRoutes mounts /reset, /reset/confirm, and the admin-only
// send-setup-link endpoint on mux.
func (h *ResetHandlers) RegisterRoutes(mux *http.ServeMux, trustedProxies *auth.TrustedProxies, currentUser CurrentUserFunc, adminGroup string) {
	mux.HandleFunc("/reset", func(w http.ResponseWriter, r *http.Request) {
		h.handleReset(w, r, trustedProxies)
	})
	mux.HandleFunc("/reset/confirm", func(w http.ResponseWriter, r *http.Request) {
		h.handleResetConfirm(w, r, trustedProxies)
	})
	mux.HandleFunc("/admin/send-setup-link", func(w http.ResponseWriter, r *http.Request) {
		h.handleSendSetupLink(w, r, currentUser, adminGroup)
	})
}

// handleSendSetupLink lets an admin (any user in adminGroup, resolved via
// FlattenedMemberOf) trigger the identical reset-link email for a
// newly-declared user with no credentials row yet — the bootstrap
// first-password flow reuses the exact same token/email/confirm mechanism
// as a normal reset, so no separate "set password" code path exists and no
// password ever passes through the admin.
func (h *ResetHandlers) handleSendSetupLink(w http.ResponseWriter, r *http.Request, currentUser CurrentUserFunc, adminGroup string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	requester, ok := currentUser(r)
	snap := h.Snapshot()
	if !ok || !snap.IsMemberOf(requester, adminGroup) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !ValidCSRF(r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	username := r.FormValue("username")
	target, exists := snap.Users[username]
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	raw, _ := randomToken(32)
	if err := h.Tokens.Create(ctx, hashToken(raw), username, h.ttl()); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	link := h.BaseURL + "/reset/confirm?token=" + raw
	if err := h.Mail.SendReset(target.Email, link, humanDuration(h.ttl())); err != nil {
		http.Error(w, "failed to send email: "+err.Error(), http.StatusBadGateway)
		return
	}
	if h.Audit != nil {
		_ = h.Audit.Write(ctx, store.AuditEvent{Username: username, EventType: "password_reset_requested", Detail: "admin-triggered by " + requester})
	}
	w.WriteHeader(http.StatusOK)
}

func (h *ResetHandlers) ttl() time.Duration {
	if h.TTL == 0 {
		return 30 * time.Minute
	}
	return h.TTL
}

func (h *ResetHandlers) handleReset(w http.ResponseWriter, r *http.Request, tp *auth.TrustedProxies) {
	secure := tp.IsForwardedHTTPS(r)
	switch r.Method {
	case http.MethodGet:
		token := IssueCSRFToken(w, r, secure)
		render(w, resetRequestTmpl, map[string]any{"Title": "Reset password", "CSRFToken": token})
	case http.MethodPost:
		h.handleResetSubmit(w, r, secure)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *ResetHandlers) handleResetSubmit(w http.ResponseWriter, r *http.Request, secure bool) {
	if !ValidCSRF(r) {
		render(w, resetRequestTmpl, map[string]any{"Title": "Reset password", "Error": "Your session expired, please try again.", "CSRFToken": IssueCSRFToken(w, r, secure)})
		return
	}
	// Accepts either a username or an email, resolved the same way login
	// does (identity.Snapshot.ResolveIdentifier), so "forgot password"
	// works no matter which one the user remembers.
	identifier := r.FormValue("email")
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	snap := h.Snapshot()
	if username, ok := snap.ResolveIdentifier(identifier); ok {
		target := snap.Users[username]
		raw, _ := randomToken(32)
		tokenHash := hashToken(raw)
		if err := h.Tokens.Create(ctx, tokenHash, username, h.ttl()); err == nil {
			link := h.BaseURL + "/reset/confirm?token=" + raw
			// The link always goes to the user's declared email, never to
			// whatever the requester typed -- so typing a username still
			// sends the link to its owner's real address, not nowhere.
			_ = h.Mail.SendReset(target.Email, link, humanDuration(h.ttl()))
			if h.Audit != nil {
				_ = h.Audit.Write(ctx, store.AuditEvent{Username: username, EventType: "password_reset_requested"})
			}
		}
	}
	// Always the same response, regardless of whether the identifier
	// matched, to avoid user enumeration.
	render(w, resetSentTmpl, map[string]any{"Title": "Check your email", "ExpiresIn": humanDuration(h.ttl())})
}

func (h *ResetHandlers) handleResetConfirm(w http.ResponseWriter, r *http.Request, tp *auth.TrustedProxies) {
	secure := tp.IsForwardedHTTPS(r)
	switch r.Method {
	case http.MethodGet:
		token := r.URL.Query().Get("token")
		if token == "" || !h.Tokens.Peek(r.Context(), hashToken(token)) {
			render(w, errorTmpl, errorPageData{Title: "Invalid link", Message: "This link is invalid or has expired."})
			return
		}
		csrf := IssueCSRFToken(w, r, secure)
		render(w, resetConfirmTmpl, h.confirmPageData(token, csrf, ""))
	case http.MethodPost:
		h.handleResetConfirmSubmit(w, r, secure)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// policy resolves the effective password policy, applying the same
// zero-value defaults as auth.PasswordPolicy.Validate so the numbers shown
// to the user (minimum length, minimum strength) always match what will
// actually be enforced.
func (h *ResetHandlers) policy() auth.PasswordPolicy {
	p := h.Policy
	if p.MinLength == 0 {
		p.MinLength = 8
	}
	if p.MinStrength == 0 {
		p.MinStrength = 2
	}
	return p
}

func (h *ResetHandlers) confirmPageData(token, csrf, errMsg string) map[string]any {
	p := h.policy()
	data := map[string]any{
		"Title":       "Set your password",
		"Token":       token,
		"CSRFToken":   csrf,
		"MinLength":   p.MinLength,
		"MinStrength": p.MinStrength,
	}
	if errMsg != "" {
		data["Error"] = errMsg
	}
	return data
}

func (h *ResetHandlers) handleResetConfirmSubmit(w http.ResponseWriter, r *http.Request, secure bool) {
	token := r.FormValue("token")
	if !ValidCSRF(r) {
		render(w, errorTmpl, errorPageData{Title: "Invalid link", Message: "Your session expired, please request a new link."})
		return
	}
	password := r.FormValue("password")
	confirm := r.FormValue("password_confirm")
	if password != confirm {
		csrf := IssueCSRFToken(w, r, secure)
		render(w, resetConfirmTmpl, h.confirmPageData(token, csrf, "Passwords do not match."))
		return
	}
	if err := h.policy().Validate(password); err != nil {
		csrf := IssueCSRFToken(w, r, secure)
		render(w, resetConfirmTmpl, h.confirmPageData(token, csrf, capitalize(err.Error())+"."))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	result, err := h.Tokens.Consume(ctx, hashToken(token))
	if err != nil {
		render(w, errorTmpl, errorPageData{Title: "Invalid link", Message: "This link is invalid, expired, or has already been used."})
		return
	}

	encoded, err := h.Hasher.Hash(password)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.Creds.Upsert(ctx, result.Username, encoded); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if h.Audit != nil {
		_ = h.Audit.Write(ctx, store.AuditEvent{Username: result.Username, EventType: "password_reset_completed"})
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func humanDuration(d time.Duration) string {
	if d >= time.Hour {
		return d.Round(time.Minute).String()
	}
	return d.Round(time.Second).String()
}

// capitalize upper-cases the first rune of an idiomatic (lowercase) Go
// error string, for display in a UI sentence.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
