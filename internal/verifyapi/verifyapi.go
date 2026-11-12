// Package verifyapi is the credential-verification endpoint for trusted
// internal services that have to check a user's login themselves but can't
// speak OIDC or carry email MFA -- chiefly a VPN. It runs the same
// Authenticator as LDAP bind and web login, plus the authenticator-app second
// factor for users subject to MFA, so lockout and MFA policy stay in one place.
package verifyapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"declarativeauth/internal/auth"
	"declarativeauth/internal/identity"
	"declarativeauth/internal/store"
)

const maxBody = 4 << 10

// Handler serves POST /v1/verify.
type Handler struct {
	Authenticator *auth.Authenticator
	Snapshot      func() *identity.Snapshot
	// CallerGroup is the group the calling service's own account must be in.
	CallerGroup string
	Audit       *store.AuditStore
	Logger      *slog.Logger
}

// RegisterRoutes mounts the endpoint.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/verify", h.handleVerify)
}

type request struct {
	Username string `json:"username"`
	Password string `json:"password"`
	// Code is the authenticator-app code; only consulted for users subject
	// to MFA.
	Code string `json:"code"`
	// Group, if set, additionally requires the user to belong to it.
	Group string `json:"group"`
}

type response struct {
	OK       bool   `json:"ok"`
	Username string `json:"username,omitempty"`
	// Reason is for the calling service's logs, not for end users.
	Reason string `json:"reason,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v response) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *Handler) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	sourceIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	// The caller authenticates as its own account, so a leaked credential is
	// scoped to this API and the lockout applies to it like any login.
	callerName, callerPass, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="verify"`)
		writeJSON(w, http.StatusUnauthorized, response{Reason: "caller_auth_required"})
		return
	}
	caller, err := h.Authenticator.Authenticate(ctx, callerName, callerPass, sourceIP)
	if err != nil {
		var ae *auth.AuthError
		if errors.As(err, &ae) {
			writeJSON(w, http.StatusUnauthorized, response{Reason: "caller_auth_failed"})
			return
		}
		h.internalError(w, err)
		return
	}
	if h.CallerGroup == "" || !h.Snapshot().IsMemberOf(caller.Username, h.CallerGroup) {
		writeJSON(w, http.StatusForbidden, response{Reason: "caller_not_allowed"})
		return
	}

	var req request
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	if err := dec.Decode(&req); err != nil || req.Username == "" {
		writeJSON(w, http.StatusBadRequest, response{Reason: "bad_request"})
		return
	}

	res, err := h.Authenticator.AuthenticateWithCode(ctx, req.Username, req.Password, req.Code, sourceIP)
	if err != nil {
		var ae *auth.AuthError
		if errors.As(err, &ae) {
			h.audit(ctx, req.Username, false, sourceIP, string(ae.Reason))
			writeJSON(w, http.StatusUnauthorized, response{Reason: string(ae.Reason)})
			return
		}
		h.internalError(w, err)
		return
	}
	if req.Group != "" && !h.Snapshot().IsMemberOf(res.Username, req.Group) {
		h.audit(ctx, res.Username, false, sourceIP, "not_in_group")
		writeJSON(w, http.StatusForbidden, response{Reason: "not_in_group"})
		return
	}
	h.audit(ctx, res.Username, true, sourceIP, "")
	writeJSON(w, http.StatusOK, response{OK: true, Username: res.Username})
}

func (h *Handler) audit(ctx context.Context, username string, success bool, sourceIP, reason string) {
	if h.Audit == nil {
		return
	}
	event := "verify_failure"
	if success {
		event = "verify_success"
	}
	if err := h.Audit.Write(ctx, store.AuditEvent{Username: username, EventType: event, SourceIP: net.ParseIP(sourceIP), Detail: reason}); err != nil && h.Logger != nil {
		h.Logger.Error("audit write failed", "component", "verifyapi", "event_type", event, "error", err)
	}
}

func (h *Handler) internalError(w http.ResponseWriter, err error) {
	if h.Logger != nil {
		h.Logger.Error("verify failed", "component", "verifyapi", "error", err)
	}
	writeJSON(w, http.StatusInternalServerError, response{Reason: "internal_error"})
}
