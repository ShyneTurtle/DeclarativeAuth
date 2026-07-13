package web

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
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
	Sessions *SessionManager // used to auto-log-in immediately after a successful reset, see handleResetConfirmSubmit
	TTL      time.Duration
	BaseURL  string // e.g. "https://auth.example.com", used to build the emailed link
	Policy   auth.PasswordPolicy
	Logger   *slog.Logger

	// RateLimiter throttles /reset submissions (a namespaced instance, see
	// auth.RateLimiter.KeyPrefix, so it doesn't share a budget with login
	// lockouts). Without this, nothing stops repeatedly POSTing the same
	// identifier to mail-bomb a user's inbox with reset links -- each
	// request is otherwise cheap (no Argon2 hashing, unlike login) and the
	// generic "check your email" response never reveals a match either
	// way, so there was no other signal an attacker would even need to
	// avoid to spam a known address. Optional: nil disables throttling.
	RateLimiter *auth.RateLimiter
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
	if target.PasswordHash != "" {
		http.Error(w, "this account's password is set declaratively (passwordHash/passwordHashFile) and can't be changed here", http.StatusConflict)
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
		if h.Logger != nil {
			h.Logger.Error("failed to send password setup email", "component", "web", "username", username, "error", err)
		}
		http.Error(w, "failed to send email: "+err.Error(), http.StatusBadGateway)
		return
	}
	if h.Audit != nil {
		if err := h.Audit.Write(ctx, store.AuditEvent{Username: username, EventType: "password_reset_requested", Detail: "admin-triggered by " + requester}); err != nil && h.Logger != nil {
			h.Logger.Error("audit write failed", "component", "web", "event_type", "password_reset_requested", "error", err)
		}
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
		returnTo := sanitizeReturnTo(r.URL.Query().Get("return_to"))
		token := IssueCSRFToken(w, r, secure)
		render(w, resetRequestTmpl, map[string]any{"Title": "Reset password", "CSRFToken": token, "ReturnTo": returnTo})
	case http.MethodPost:
		h.handleResetSubmit(w, r, secure, tp)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *ResetHandlers) handleResetSubmit(w http.ResponseWriter, r *http.Request, secure bool, tp *auth.TrustedProxies) {
	returnTo := sanitizeReturnTo(r.FormValue("return_to"))
	if !ValidCSRF(r) {
		render(w, resetRequestTmpl, map[string]any{"Title": "Reset password", "Error": "Your session expired, please try again.", "CSRFToken": IssueCSRFToken(w, r, secure), "ReturnTo": returnTo})
		return
	}
	// Accepts either a username or an email, resolved the same way login
	// does (identity.Snapshot.ResolveIdentifier), so "forgot password"
	// works no matter which one the user remembers.
	identifier := r.FormValue("email")
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	snap := h.Snapshot()
	username, resolved := snap.ResolveIdentifier(identifier)
	sourceIP := tp.ClientIP(r).String()
	// Always record the attempt (whether or not the identifier resolved)
	// and always check both dimensions before sending anything, so the
	// throttle itself can't be used to distinguish a known identifier from
	// an unknown one -- same no-enumeration property as the response body
	// below.
	locked := false
	if h.RateLimiter != nil {
		var err error
		locked, err = h.RateLimiter.IsLocked(ctx, username, sourceIP)
		if err != nil && h.Logger != nil {
			h.Logger.Error("reset rate limit check failed", "component", "web", "error", err)
		}
		if err := h.RateLimiter.RecordFailure(ctx, username, sourceIP); err != nil && h.Logger != nil {
			h.Logger.Error("reset rate limit record failed", "component", "web", "error", err)
		}
	}
	// A declaratively-hashed account (see identity.User.PasswordHash) has
	// no Postgres-stored credential to reset -- silently skip issuing a
	// token/email for it, same as an unrecognized identifier or a
	// throttled request, so the response below never reveals which case
	// applied (no user enumeration either way).
	if resolved && !locked && snap.Users[username].PasswordHash == "" {
		target := snap.Users[username]
		raw, _ := randomToken(32)
		tokenHash := hashToken(raw)
		if err := h.Tokens.Create(ctx, tokenHash, username, h.ttl()); err == nil {
			link := h.BaseURL + "/reset/confirm?token=" + raw
			// Carries the original destination through the email link, so
			// completing the reset can land the user back where they were
			// headed instead of a bare, context-less /login.
			if returnTo != "" && returnTo != "/" {
				link += "&return_to=" + url.QueryEscape(returnTo)
			}
			// The link always goes to the user's declared email, never to
			// whatever the requester typed -- so typing a username still
			// sends the link to its owner's real address, not nowhere.
			// The response to the caller never reflects send failure here
			// (always the same page, to avoid user enumeration -- see
			// below), so this is the only place such a failure surfaces.
			if err := h.Mail.SendReset(target.Email, link, humanDuration(h.ttl())); err != nil && h.Logger != nil {
				h.Logger.Error("failed to send password reset email", "component", "web", "username", username, "error", err)
			}
			if h.Audit != nil {
				if err := h.Audit.Write(ctx, store.AuditEvent{Username: username, EventType: "password_reset_requested"}); err != nil && h.Logger != nil {
					h.Logger.Error("audit write failed", "component", "web", "event_type", "password_reset_requested", "error", err)
				}
			}
		}
	}
	// Always the same response, regardless of whether the identifier
	// matched, to avoid user enumeration.
	render(w, resetSentTmpl, map[string]any{"Title": "Check your email", "ExpiresIn": humanDuration(h.ttl()), "ReturnTo": returnTo})
}

func (h *ResetHandlers) handleResetConfirm(w http.ResponseWriter, r *http.Request, tp *auth.TrustedProxies) {
	secure := tp.IsForwardedHTTPS(r)
	switch r.Method {
	case http.MethodGet:
		token := r.URL.Query().Get("token")
		username, ok := "", false
		if token != "" {
			username, ok = h.Tokens.Peek(r.Context(), hashToken(token))
		}
		if !ok {
			render(w, errorTmpl, errorPageData{Title: "Invalid link", Message: "This link is invalid or has expired."})
			return
		}
		// The account can have become declaratively managed (see
		// identity.User.PasswordHash) after this link was emailed --
		// checked here too, not just on submit, so the user finds out
		// immediately instead of after filling in the form.
		if h.Snapshot().Users[username].PasswordHash != "" {
			render(w, errorTmpl, errorPageData{Title: "Password managed by your administrator", Message: "Your password is managed by your administrator."})
			return
		}
		returnTo := sanitizeReturnTo(r.URL.Query().Get("return_to"))
		csrf := IssueCSRFToken(w, r, secure)
		render(w, resetConfirmTmpl, h.confirmPageData(token, returnTo, csrf, ""))
	case http.MethodPost:
		h.handleResetConfirmSubmit(w, r, secure, tp)
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

func (h *ResetHandlers) confirmPageData(token, returnTo, csrf, errMsg string) map[string]any {
	p := h.policy()
	data := map[string]any{
		"Title":       "Set your password",
		"Token":       token,
		"ReturnTo":    returnTo,
		"CSRFToken":   csrf,
		"MinLength":   p.MinLength,
		"MinStrength": p.MinStrength,
	}
	if errMsg != "" {
		data["Error"] = errMsg
	}
	return data
}

func (h *ResetHandlers) handleResetConfirmSubmit(w http.ResponseWriter, r *http.Request, secure bool, tp *auth.TrustedProxies) {
	token := r.FormValue("token")
	returnTo := sanitizeReturnTo(r.FormValue("return_to"))
	if !ValidCSRF(r) {
		render(w, errorTmpl, errorPageData{Title: "Invalid link", Message: "Your session expired, please request a new link."})
		return
	}
	password := r.FormValue("password")
	confirm := r.FormValue("password_confirm")
	if password != confirm {
		csrf := IssueCSRFToken(w, r, secure)
		render(w, resetConfirmTmpl, h.confirmPageData(token, returnTo, csrf, "Passwords do not match."))
		return
	}
	if err := h.policy().Validate(password); err != nil {
		csrf := IssueCSRFToken(w, r, secure)
		render(w, resetConfirmTmpl, h.confirmPageData(token, returnTo, csrf, capitalize(err.Error())+"."))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	result, err := h.Tokens.Consume(ctx, hashToken(token))
	if err != nil {
		render(w, errorTmpl, errorPageData{Title: "Invalid link", Message: "This link is invalid, expired, or has already been used."})
		return
	}
	// The identity snapshot can change between the GET check above and this
	// POST (e.g. an admin declares a passwordHash for this account while
	// the form was open) -- re-check here too rather than trusting the GET
	// check alone.
	if h.Snapshot().Users[result.Username].PasswordHash != "" {
		render(w, errorTmpl, errorPageData{Title: "Password managed by your administrator", Message: "Your password is managed by your administrator."})
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
		if err := h.Audit.Write(ctx, store.AuditEvent{Username: result.Username, EventType: "password_reset_completed"}); err != nil && h.Logger != nil {
			h.Logger.Error("audit write failed", "component", "web", "event_type", "password_reset_completed", "error", err)
		}
	}

	// Auto-login: the reset token already proved control of the account, so
	// making the user re-enter the password they just chose on a separate
	// /login page is redundant friction, and it's what previously stranded
	// people on a bare /login with the original return_to (e.g. an OIDC
	// /authorize redirect) lost. If session issuance fails for some reason,
	// fall back to /login rather than erroring -- the password change itself
	// already succeeded.
	if h.Sessions != nil {
		sourceIP := tp.ClientIP(r).String()
		if err := h.Sessions.Issue(ctx, w, result.Username, r.UserAgent(), sourceIP); err == nil {
			http.Redirect(w, r, returnTo, http.StatusSeeOther)
			return
		}
	}
	http.Redirect(w, r, "/login?return_to="+url.QueryEscape(returnTo), http.StatusSeeOther)
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
