package web

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
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

// startMFAChallenge persists the pending-MFA challenge for a user who just
// passed the password check and sets the cookie tying /login/mfa requests to
// it. A user with an authenticator app enrolled is not emailed: the app is
// the default and they can ask for an emailed code on the verify page. Anyone
// else gets a fresh emailed code right away. Called from handleLoginSubmit.
func (h *Handlers) startMFAChallenge(w http.ResponseWriter, r *http.Request, secure bool, username, returnTo string) error {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	id, err := randomToken(16)
	if err != nil {
		return err
	}
	ttl := mfaChallengeTTL(h.MFACodeTTL)

	enrolled := false
	if h.TOTP != nil {
		if enrolled, err = h.TOTP.IsEnrolled(ctx, username); err != nil {
			return err
		}
	}
	if enrolled {
		// Nothing is emailed, so the stored hash must simply never match.
		never, err := randomToken(16)
		if err != nil {
			return err
		}
		if err := h.MFAChallenges.Create(ctx, id, username, hashToken(never), returnTo, store.ChallengeStageVerify, false, ttl); err != nil {
			return err
		}
	} else {
		code, err := generateOTP()
		if err != nil {
			return err
		}
		if err := h.MFAChallenges.Create(ctx, id, username, hashToken(code), returnTo, store.ChallengeStageVerify, true, ttl); err != nil {
			return err
		}
		target := h.Snapshot().Users[username]
		if err := h.MFAMail.SendMFACode(target.Email, code); err != nil {
			if h.Logger != nil {
				h.Logger.Error("failed to send MFA code email", "component", "web", "username", username, "error", err)
			}
			return err
		}
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
	Logger         *slog.Logger

	// TOTP, Policy and Issuer back the authenticator-app options: choosing it
	// at the verify step, and the forced enrolment of users subject to MFA.
	// TOTP nil disables both.
	TOTP   *store.TOTPStore
	Policy *auth.MFAPolicy
	Issuer string
}

// RegisterRoutes mounts /login/mfa, /login/mfa/resend, and /account/mfa.
func (h *MFAHandlers) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/login/mfa", h.handleVerify)
	mux.HandleFunc("/login/mfa/resend", h.handleResend)
	mux.HandleFunc("/login/mfa/enroll", h.handleEnroll)
	mux.HandleFunc("/account/mfa", h.handleSettings)
}

type mfaVerifyPageData struct {
	Title     string
	CSRFToken string
	Error     string
	// HasTOTP: the user has an authenticator app, which the page offers.
	HasTOTP bool
	// EmailSent: a code was emailed, so the page says so and offers a resend
	// rather than "email me a code".
	EmailSent bool
}

func (h *MFAHandlers) handleVerify(w http.ResponseWriter, r *http.Request) {
	secure := h.TrustedProxies.IsForwardedHTTPS(r)
	switch r.Method {
	case http.MethodGet:
		cookie, err := r.Cookie(mfaPendingCookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		h.renderVerify(w, r, secure, cookie.Value, "")
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

	code := strings.TrimSpace(r.FormValue("code"))
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	ch, err := h.Challenges.Peek(ctx, cookie.Value)
	if err != nil || ch.Stage != store.ChallengeStageVerify {
		clearMFAPendingCookie(w)
		render(w, errorTmpl, errorPageData{Title: "Expired", Message: "This verification code has expired or is no longer valid. Please log in again."})
		return
	}

	// Either factor satisfies the step: the authenticator app (single-use,
	// replay-protected in TOTPStore.Verify) or the emailed code. Every miss
	// burns the challenge's shared attempt budget.
	method := ""
	if h.TOTP != nil {
		ok, err := h.TOTP.Verify(ctx, ch.Username, code)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if ok {
			method = "totp"
			if err := h.Challenges.Consume(ctx, cookie.Value); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}
	}
	if method == "" {
		if _, err := h.Challenges.Verify(ctx, cookie.Value, hashToken(code)); err != nil {
			if errors.Is(err, store.ErrChallengeNotFound) {
				clearMFAPendingCookie(w)
				render(w, errorTmpl, errorPageData{Title: "Expired", Message: "This verification code has expired or is no longer valid. Please log in again."})
				return
			}
			// store.ErrInvalidCode: challenge is still live, let them retry.
			if h.Audit != nil {
				if err := h.Audit.Write(ctx, store.AuditEvent{Username: ch.Username, EventType: "oidc_login_mfa_failure", Detail: "invalid_code", UserAgent: r.UserAgent()}); err != nil && h.Logger != nil {
					h.Logger.Error("audit write failed", "component", "web", "event_type", "oidc_login_mfa_failure", "error", err)
				}
			}
			h.renderVerify(w, r, secure, cookie.Value, "Incorrect code, please try again.")
			return
		}
		method = "email"
	}

	clearMFAPendingCookie(w)
	if h.Audit != nil {
		if err := h.Audit.Write(ctx, store.AuditEvent{Username: ch.Username, EventType: "oidc_login_success", Detail: "mfa_verified:" + method, UserAgent: r.UserAgent()}); err != nil && h.Logger != nil {
			h.Logger.Error("audit write failed", "component", "web", "event_type", "oidc_login_success", "error", err)
		}
	}
	// Users subject to MFA must have an authenticator app: if they don't yet,
	// the sign-in continues into enrolment instead of ending here. This runs
	// only after the MFA step above passed, so a stolen password alone can't
	// be used to enrol an attacker's app.
	needs, err := h.needsEnrollment(ctx, ch.Username)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if needs {
		id, err := randomToken(16)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		never, err := randomToken(16)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		ttl := 15 * time.Minute
		if err := h.Challenges.Create(ctx, id, ch.Username, hashToken(never), ch.ReturnTo, store.ChallengeStageEnroll, false, ttl); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: mfaPendingCookieName, Value: id, Path: "/",
			HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: int(ttl.Seconds()),
		})
		http.Redirect(w, r, "/login/mfa/enroll", http.StatusSeeOther)
		return
	}
	h.finishLogin(w, r, ctx, ch.Username, ch.ReturnTo)
}

// needsEnrollment reports whether username is subject to MFA but has no
// authenticator app yet (always false when TOTP isn't configured).
func (h *MFAHandlers) needsEnrollment(ctx context.Context, username string) (bool, error) {
	if h.TOTP == nil || h.Policy == nil {
		return false, nil
	}
	required, err := h.Policy.Required(ctx, username)
	if err != nil || !required {
		return false, err
	}
	enrolled, err := h.TOTP.IsEnrolled(ctx, username)
	return !enrolled, err
}

func (h *MFAHandlers) finishLogin(w http.ResponseWriter, r *http.Request, ctx context.Context, username, returnTo string) {
	sourceIP := h.TrustedProxies.ClientIP(r).String()
	if err := h.Sessions.Issue(ctx, w, username, r.UserAgent(), sourceIP); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, sanitizeReturnTo(returnTo), http.StatusSeeOther)
}

// renderVerify draws the verify page for a live challenge.
func (h *MFAHandlers) renderVerify(w http.ResponseWriter, r *http.Request, secure bool, challengeID, errMsg string) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	ch, err := h.Challenges.Peek(ctx, challengeID)
	if err != nil || ch.Stage != store.ChallengeStageVerify {
		clearMFAPendingCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	hasTOTP := false
	if h.TOTP != nil {
		if hasTOTP, err = h.TOTP.IsEnrolled(ctx, ch.Username); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	render(w, mfaVerifyTmpl, mfaVerifyPageData{
		Title: "Verify your identity", CSRFToken: IssueCSRFToken(w, r, secure), Error: errMsg,
		HasTOTP: hasTOTP, EmailSent: ch.EmailSent,
	})
}

// handleEnroll is the forced-enrolment step of sign-in: shown only to a
// holder of an 'enroll' challenge, i.e. someone who already passed MFA.
func (h *MFAHandlers) handleEnroll(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(mfaPendingCookieName)
	if err != nil || cookie.Value == "" || h.TOTP == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	ch, err := h.Challenges.Peek(ctx, cookie.Value)
	if err != nil || ch.Stage != store.ChallengeStageEnroll {
		clearMFAPendingCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	errMsg := ""
	switch r.Method {
	case http.MethodGet:
	case http.MethodPost:
		if !ValidCSRF(r) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		err := h.TOTP.ConfirmEnrollment(ctx, ch.Username, strings.TrimSpace(r.FormValue("code")), time.Now())
		if err == nil {
			if err := h.Challenges.Consume(ctx, cookie.Value); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			clearMFAPendingCookie(w)
			if h.Audit != nil {
				for _, ev := range []store.AuditEvent{
					{Username: ch.Username, EventType: "totp_enrolled", Detail: "at_login", UserAgent: r.UserAgent()},
					{Username: ch.Username, EventType: "oidc_login_success", Detail: "mfa_enrolled", UserAgent: r.UserAgent()},
				} {
					if err := h.Audit.Write(ctx, ev); err != nil && h.Logger != nil {
						h.Logger.Error("audit write failed", "component", "web", "event_type", ev.EventType, "error", err)
					}
				}
			}
			h.finishLogin(w, r, ctx, ch.Username, ch.ReturnTo)
			return
		}
		if !errors.Is(err, store.ErrInvalidTOTPCode) {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Guessing at enrolment is bounded by the challenge's attempt budget.
		_ = h.Challenges.RecordFailure(ctx, cookie.Value)
		errMsg = "Incorrect code, please try again."
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	secret, err := h.TOTP.PendingSecret(ctx, ch.Username)
	if err == nil && secret == nil {
		secret, err = h.TOTP.BeginEnrollment(ctx, ch.Username)
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	renderTOTPSetup(w, r, h.TrustedProxies, h.Issuer, ch.Username, secret, "/login/mfa/enroll", errMsg, true)
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
	if err != nil || ch.Stage != store.ChallengeStageVerify {
		clearMFAPendingCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := h.Challenges.Delete(ctx, cookie.Value); err != nil && h.Logger != nil {
		h.Logger.Warn("failed to delete superseded MFA challenge", "component", "web", "error", err)
	}

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
	if err := h.Challenges.Create(ctx, id, ch.Username, hashToken(code), ch.ReturnTo, store.ChallengeStageVerify, true, ttl); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	target := h.Snapshot().Users[ch.Username]
	if err := h.Mail.SendMFACode(target.Email, code); err != nil {
		if h.Logger != nil {
			h.Logger.Error("failed to send MFA code email", "component", "web", "username", ch.Username, "error", err)
		}
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
		if err := h.Audit.Write(ctx, store.AuditEvent{Username: username, EventType: "mfa_self_service_" + detail, UserAgent: r.UserAgent()}); err != nil && h.Logger != nil {
			h.Logger.Error("audit write failed", "component", "web", "event_type", "mfa_self_service_"+detail, "error", err)
		}
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
