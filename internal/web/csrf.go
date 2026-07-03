package web

import (
	"crypto/subtle"
	"net/http"
)

const csrfCookieName = "da_csrf"

// IssueCSRFToken sets a random CSRF cookie (double-submit pattern) if one
// isn't already present, and returns the token to embed in the form.
//
// SameSite=Lax, not Strict: this cookie must still be present on the GET
// that follows a top-level navigation from *outside* the site -- most
// notably, clicking the password-reset link in an email client, which the
// browser treats as a cross-site navigation. Strict would silently drop
// the cookie on that request, forcing a fresh one to be minted and
// desyncing it from any other tab that already has the old token embedded
// in a rendered form (surfacing later as a confusing "session expired").
// Lax still blocks the cross-site POST an actual CSRF attack would need.
func IssueCSRFToken(w http.ResponseWriter, r *http.Request, secure bool) string {
	if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	token, _ := randomToken(24)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false, // must be readable by the form-embedding template, not by third-party JS across origins
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	return token
}

// ValidCSRF checks the submitted form token against the cookie.
func ValidCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	formToken := r.FormValue("csrf_token")
	if formToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(formToken)) == 1
}
