package ldapserver

import (
	"context"
	"io"
	"time"

	"declarativeauth/internal/auth"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// handleBind processes a BindRequest (simple bind only). Returns the
// authenticated username and true on success.
func (h *Handler) handleBind(w io.Writer, isTLS bool, sourceIP string, messageID int64, op *ber.Packet) (string, bool) {
	if len(op.Children) < 3 {
		writeResult(w, messageID, ldap.ApplicationBindResponse, ldap.LDAPResultProtocolError, "", "malformed bind request")
		return "", false
	}
	if h.Config.RequireTLS && !isTLS {
		writeResult(w, messageID, ldap.ApplicationBindResponse, ldap.LDAPResultConfidentialityRequired, "", "TLS required: use the secure listener or StartTLS")
		h.audit("", false, sourceIP, "tls_required")
		return "", false
	}

	name, _ := op.Children[1].Value.(string)
	authChoice := op.Children[2]

	// Only simple bind (context-specific primitive tag 0) is supported;
	// SASL and any other mechanism is out of scope.
	if authChoice.ClassType != ber.ClassContext || authChoice.Tag != 0 {
		writeResult(w, messageID, ldap.ApplicationBindResponse, ldap.LDAPResultAuthMethodNotSupported, "", "only simple bind is supported")
		return "", false
	}
	password := authChoice.Data.String()

	if name == "" && password == "" {
		if h.Config.AllowAnonymousBind {
			writeResult(w, messageID, ldap.ApplicationBindResponse, ldap.LDAPResultSuccess, "", "")
			return "", false
		}
		writeResult(w, messageID, ldap.ApplicationBindResponse, ldap.LDAPResultUnwillingToPerform, "", "anonymous bind not allowed")
		h.audit("", false, sourceIP, "anonymous_bind_rejected")
		return "", false
	}

	username, ok := UsernameFromBindDN(h.Config.BaseDN, name)
	if !ok {
		writeResult(w, messageID, ldap.ApplicationBindResponse, ldap.LDAPResultInvalidCredentials, "", "invalid bind DN")
		h.audit("", false, sourceIP, "invalid_bind_dn")
		return "", false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := h.Authenticator.Authenticate(ctx, username, password, sourceIP)
	if err != nil {
		reason := "error"
		if ae, ok := err.(*auth.AuthError); ok {
			reason = string(ae.Reason)
		}
		writeResult(w, messageID, ldap.ApplicationBindResponse, ldap.LDAPResultInvalidCredentials, "", "invalid credentials")
		h.audit(username, false, sourceIP, reason)
		return "", false
	}

	writeResult(w, messageID, ldap.ApplicationBindResponse, ldap.LDAPResultSuccess, "", "")
	h.audit(result.Username, true, sourceIP, "")
	return result.Username, true
}

func (h *Handler) audit(username string, success bool, sourceIP, reason string) {
	if h.OnBind != nil {
		h.OnBind(username, success, sourceIP, reason)
	}
}
