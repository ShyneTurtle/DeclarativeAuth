package web

import (
	"context"
	"encoding/base64"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"declarativeauth/internal/auth"
	"declarativeauth/internal/identity"
	"declarativeauth/internal/store"
	"declarativeauth/internal/totp"

	qrcode "github.com/skip2/go-qrcode"
)

// TOTPHandlers serves authenticator-app enrolment from the account page:
// /account/totp/setup (shows a fresh secret + QR code), /account/totp/confirm
// (proves the user's app holds it by entering a code) and /account/totp/remove.
// The secret only becomes active on confirm, so abandoning setup, or
// re-running it, never breaks an already-working authenticator.
type TOTPHandlers struct {
	Store          *store.TOTPStore
	Snapshot       func() *identity.Snapshot
	Sessions       *SessionManager
	TrustedProxies *auth.TrustedProxies
	Audit          *store.AuditStore
	Issuer         string
	Logger         *slog.Logger
}

// RegisterRoutes mounts the three /account/totp/* endpoints.
func (h *TOTPHandlers) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/account/totp/setup", h.handleSetup)
	mux.HandleFunc("/account/totp/confirm", h.handleConfirm)
	mux.HandleFunc("/account/totp/remove", h.handleRemove)
}

type totpSetupPageData struct {
	Title     string
	CSRFToken string
	Error     string
	Secret    string
	QR        template.URL
	// Action is where the confirmation form posts.
	Action string
	// Required: enrolment is mandatory to finish signing in, so there is no way out.
	Required bool
}

// guard enforces POST + logged-in + CSRF, returning the username.
func (h *TOTPHandlers) guard(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return "", false
	}
	username, ok := h.Sessions.CurrentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return "", false
	}
	if !ValidCSRF(r) {
		w.WriteHeader(http.StatusForbidden)
		return "", false
	}
	return username, true
}

func (h *TOTPHandlers) audit(ctx context.Context, r *http.Request, username, event string) {
	if h.Audit == nil {
		return
	}
	if err := h.Audit.Write(ctx, store.AuditEvent{Username: username, EventType: event, UserAgent: r.UserAgent()}); err != nil && h.Logger != nil {
		h.Logger.Error("audit write failed", "component", "web", "event_type", event, "error", err)
	}
}

// renderTOTPSetup draws the QR/secret enrolment page, shared by the account
// page flow and the forced enrolment during sign-in.
func renderTOTPSetup(w http.ResponseWriter, r *http.Request, tp *auth.TrustedProxies, issuer, username string, secret []byte, action, errMsg string, required bool) {
	uri := totp.OTPAuthURI(issuer, username, secret)
	png, err := qrcode.Encode(uri, qrcode.Medium, 224)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	render(w, totpSetupTmpl, totpSetupPageData{
		Title:     "Set up your authenticator app",
		CSRFToken: IssueCSRFToken(w, r, tp.IsForwardedHTTPS(r)),
		Error:     errMsg,
		Secret:    totp.EncodeSecret(secret),
		QR:        template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)),
		Action:    action,
		Required:  required,
	})
}

func (h *TOTPHandlers) renderSetup(w http.ResponseWriter, r *http.Request, username string, secret []byte, errMsg string) {
	renderTOTPSetup(w, r, h.TrustedProxies, h.Issuer, username, secret, "/account/totp/confirm", errMsg, false)
}

func (h *TOTPHandlers) handleSetup(w http.ResponseWriter, r *http.Request) {
	username, ok := h.guard(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	secret, err := h.Store.BeginEnrollment(ctx, username)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.renderSetup(w, r, username, secret, "")
}

func (h *TOTPHandlers) handleConfirm(w http.ResponseWriter, r *http.Request) {
	username, ok := h.guard(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	err := h.Store.ConfirmEnrollment(ctx, username, r.FormValue("code"), time.Now())
	if errors.Is(err, store.ErrInvalidTOTPCode) {
		secret, perr := h.Store.PendingSecret(ctx, username)
		if perr != nil || secret == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		h.renderSetup(w, r, username, secret, "Incorrect code, please try again.")
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.audit(ctx, r, username, "totp_enrolled")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *TOTPHandlers) handleRemove(w http.ResponseWriter, r *http.Request) {
	username, ok := h.guard(w, r)
	if !ok {
		return
	}
	// Removing the only second factor of an MFA-required account would just
	// lock them out of every MFA-enforcing client; they can re-run setup to
	// replace it instead.
	if h.Snapshot().MFARequiredByDeclaration(username) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := h.Store.Remove(ctx, username); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.audit(ctx, r, username, "totp_removed")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
