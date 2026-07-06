package web

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"declarativeauth/internal/auth"
	"declarativeauth/internal/identity"
	"declarativeauth/internal/mail"
	"declarativeauth/internal/store"
)

const mfaPendingCookieName = "da_mfa_pending"

func mfaChallengeTTL(configured time.Duration) time.Duration {
	if configured == 0 {
		return 10 * time.Minute
	}
	return configured
}

// generateOTP returns a random, zero-padded 6-digit numeric code.
func generateOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// startMFAChallenge generates and emails a fresh one-time code, persists
// the challenge, and sets the pending-MFA cookie that ties subsequent
// /login/mfa requests back to it. Called from handleLoginSubmit right
// after a successful password check, and from MFAHandlers.handleResend.
func (h *Handlers) startMFAChallenge(w http.ResponseWriter, r *http.Request, secure bool, username, returnTo string) error {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	code, err := generateOTP()
	if err != nil {
		return err
	}
	id, err := randomToken(16)
	if err != nil {
		return err
	}
	ttl := mfaChallengeTTL(h.MFACodeTTL)
	if err := h.MFAChallenges.Create(ctx, id, username, hashToken(code), returnTo, ttl); err != nil {
		return err
	}

	target := h.Snapshot().Users[username]
	if err := h.MFAMail.SendMFACode(target.Email, code); err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     mfaPendingCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
	return nil
}

func clearMFAPendingCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: mfaPendingCookieName, Value: "", Path: "/", MaxAge: -1})
}

// MFAHandlers wires the email-MFA code-verification step of login
// (/login/mfa, /login/mfa/resend) plus the self-service enable/disable
// toggle on the home page (/account/mfa). Starting a challenge itself
// happens in Handlers.handleLoginSubmit right after a successful password
// check, since that's where the "is MFA required for this user" decision
// naturally lives; this struct only handles what comes after.
type MFAHandlers struct {
	Snapshot       func() *identity.Snapshot
	Settings       *store.UserMFASettingsStore
	Challenges     *store.EmailChallengeStore
	Mail           *mail.Client
	Sessions       *SessionManager
	TrustedProxies *auth.TrustedProxies
	Audit          *store.AuditStore
	CodeTTL        time.Duration
}

// RegisterRoutes mounts /login/mfa, /login/mfa/resend, and /account/mfa.
func (h *MFAHandlers) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/login/mfa", h.handleVerify)
	mux.HandleFunc("/login/mfa/resend", h.handleResend)
	mux.HandleFunc("/account/mfa", h.handleSettings)
}

type mfaVerifyPageData struct {
	Title     string
	CSRFToken string
	Error     string
}

func (h *MFAHandlers) handleVerify(w http.ResponseWriter, r *http.Request) {
	secure := h.TrustedProxies.IsForwardedHTTPS(r)
	switch r.Method {
	case http.MethodGet:
		if _, err := r.Cookie(mfaPendingCookieName); err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		csrf := IssueCSRFToken(w, r, secure)
		render(w, mfaVerifyTmpl, mfaVerifyPageData{Title: "Verify your identity", CSRFToken: csrf})
	case http.MethodPost:
		h.handleVerifySubmit(w, r, secure)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *MFAHandlers) handleVerifySubmit(w http.ResponseWriter, r *http.Request, secure bool) {
	cookie, err := r.Cookie(mfaPendingCookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !ValidCSRF(r) {
		render(w, mfaVerifyTmpl, mfaVerifyPageData{Title: "Verify your identity", Error: "Your session expired, please try again.", CSRFToken: IssueCSRFToken(w, r, secure)})
		return
	}

	code := r.FormValue("code")
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	ch, err := h.Challenges.Verify(ctx, cookie.Value, hashToken(code))
	if err != nil {
		if errors.Is(err, store.ErrChallengeNotFound) {
			clearMFAPendingCookie(w)
			render(w, errorTmpl, errorPageData{Title: "Expired", Message: "This verification code has expired or is no longer valid. Please log in again."})
			return
		}
		// store.ErrInvalidCode: challenge is still live, let them retry.
		if h.Audit != nil {
			_ = h.Audit.Write(ctx, store.AuditEvent{EventType: "oidc_login_mfa_failure", Detail: "invalid_code", UserAgent: r.UserAgent()})
		}
		render(w, mfaVerifyTmpl, mfaVerifyPageData{Title: "Verify your identity", Error: "Incorrect code, please try again.", CSRFToken: IssueCSRFToken(w, r, secure)})
		return
	}

	clearMFAPendingCookie(w)
	if h.Audit != nil {
		_ = h.Audit.Write(ctx, store.AuditEvent{Username: ch.Username, EventType: "oidc_login_success", Detail: "mfa_verified", UserAgent: r.UserAgent()})
	}
	sourceIP := h.TrustedProxies.ClientIP(r).String()
	if err := h.Sessions.Issue(ctx, w, ch.Username, r.UserAgent(), sourceIP); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, sanitizeReturnTo(ch.ReturnTo), http.StatusSeeOther)
}

func (h *MFAHandlers) handleResend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	secure := h.TrustedProxies.IsForwardedHTTPS(r)
	cookie, err := r.Cookie(mfaPendingCookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !ValidCSRF(r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	ch, err := h.Challenges.Peek(ctx, cookie.Value)
	if err != nil {
		clearMFAPendingCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	_ = h.Challenges.Delete(ctx, cookie.Value)

	code, err := generateOTP()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	id, err := randomToken(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ttl := mfaChallengeTTL(h.CodeTTL)
	if err := h.Challenges.Create(ctx, id, ch.Username, hashToken(code), ch.ReturnTo, ttl); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	target := h.Snapshot().Users[ch.Username]
	if err := h.Mail.SendMFACode(target.Email, code); err != nil {
		http.Error(w, "failed to send email: "+err.Error(), http.StatusBadGateway)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: mfaPendingCookieName, Value: id, Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: int(ttl.Seconds()),
	})
	http.Redirect(w, r, "/login/mfa", http.StatusSeeOther)
}

// handleSettings toggles a logged-in user's own self-service MFA
// preference from the home page. This is deliberately separate from the
// declarative MFARequiredByDeclaration check: a user can always turn MFA on
// for themselves, but this endpoint can't turn off a declaratively-required
// MFA (the toggle isn't even rendered in that case -- see home.html).
func (h *MFAHandlers) handleSettings(w http.ResponseWriter, r *http.Request) {
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
	enabled := r.FormValue("enabled") == "true"

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := h.Settings.SetEnabled(ctx, username, enabled); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if h.Audit != nil {
		detail := "disabled"
		if enabled {
			detail = "enabled"
		}
		_ = h.Audit.Write(ctx, store.AuditEvent{Username: username, EventType: "mfa_self_service_" + detail, UserAgent: r.UserAgent()})
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
