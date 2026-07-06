// Package web hosts the small, server-rendered login and password-reset UI,
// shared with the OIDC authorization endpoint via the same web session
// cookie and the same internal/auth.Authenticator used by LDAP bind.
package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"declarativeauth/internal/store"

	"github.com/google/uuid"
)

const sessionCookieName = "da_session"

// SessionManager issues and validates the web login session cookie, backed
// by the same `sessions` table OIDC refresh tokens use (Section 7: shared
// revocation/audit infrastructure).
type SessionManager struct {
	Sessions *store.SessionStore
	Secure   bool // set the cookie's Secure flag (true when serving over HTTPS, incl. reverse-proxy-TLS mode)
	TTL      time.Duration
	Logger   *slog.Logger
}

// Issue creates a new session row and sets the session cookie on w.
func (m *SessionManager) Issue(ctx context.Context, w http.ResponseWriter, username, userAgent, ip string) error {
	raw, err := randomToken(32)
	if err != nil {
		return err
	}
	id := uuid.New()
	ttl := m.TTL
	if ttl == 0 {
		ttl = 12 * time.Hour
	}
	if err := m.Sessions.Create(ctx, store.Session{
		ID:               id,
		Username:         username,
		RefreshTokenHash: hashToken(raw),
		ClientID:         "web-ui",
		ExpiresAt:        time.Now().Add(ttl),
		UserAgent:        userAgent,
	}); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id.String() + "." + raw,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.Secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(ttl),
	})
	return nil
}

// CurrentUser returns the authenticated username for the session cookie on
// r, if any valid, unrevoked, unexpired session exists.
func (m *SessionManager) CurrentUser(r *http.Request) (string, bool) {
	sess, _, ok := m.lookup(r)
	if !ok {
		return "", false
	}
	return sess.Username, true
}

// Clear revokes the session and expires the cookie ("log out").
func (m *SessionManager) Clear(w http.ResponseWriter, r *http.Request) {
	if sess, _, ok := m.lookup(r); ok {
		if err := m.Sessions.Revoke(r.Context(), sess.ID); err != nil && m.Logger != nil {
			m.Logger.Error("failed to revoke session on logout", "component", "web", "error", err)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1,
	})
}

func (m *SessionManager) lookup(r *http.Request) (*store.Session, string, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return nil, "", false
	}
	id, raw, ok := strings.Cut(c.Value, ".")
	if !ok {
		return nil, "", false
	}
	sessionID, err := uuid.Parse(id)
	if err != nil {
		return nil, "", false
	}
	sess, err := m.Sessions.GetByID(r.Context(), sessionID)
	if err != nil || sess == nil {
		return nil, "", false
	}
	if sess.RevokedAt != nil || time.Now().After(sess.ExpiresAt) {
		return nil, "", false
	}
	if subtle.ConstantTimeCompare([]byte(hashToken(raw)), []byte(sess.RefreshTokenHash)) != 1 {
		return nil, "", false
	}
	return sess, raw, true
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
