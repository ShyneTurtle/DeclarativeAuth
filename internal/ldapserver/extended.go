package ldapserver

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// handleExtended processes an ExtendedRequest (RFC 4511 §4.12). StartTLS is
// the only supported extended operation; anything else gets a clean
// protocolError response, same connection kept alive -- an unrecognized
// extended operation is routine (clients probe for optional capabilities),
// not a reason to drop the session.
//
// On a successful StartTLS, returns the TLS-upgraded net.Conn for the
// caller to swap into its read loop, and true. The caller must also reset
// any pre-StartTLS bind state: RFC 4511 §4.14.1 requires discarding
// authentication established before the channel was encrypted, since it
// wasn't confidentiality- or integrity-protected.
//
// tlsConfig is nil when StartTLS isn't available at all (e.g. no cert
// material could be resolved); a connection that's already TLS (the secure
// listener) always rejects StartTLS regardless of tlsConfig, since layering
// TLS-within-TLS is nonsensical here.
func (h *Handler) handleExtended(conn net.Conn, tlsConfig *tls.Config, messageID int64, op *ber.Packet) (upgraded net.Conn, ok bool) {
	if len(op.Children) < 1 {
		writeExtendedResponse(conn, messageID, ldap.LDAPResultProtocolError, "malformed extended request", "")
		return nil, true
	}
	// requestName is context-tagged ([0] LDAPOID), like BindRequest's
	// password field -- not a plain universal OCTET STRING like Control's
	// fields -- so it doesn't auto-decode into .Value; read the raw bytes
	// the same way bind.go reads the bind password.
	oid := op.Children[0].Data.String()
	if oid != oidStartTLS {
		writeExtendedResponse(conn, messageID, ldap.LDAPResultProtocolError, "unsupported extended operation", "")
		return nil, true
	}
	if _, alreadyTLS := conn.(*tls.Conn); alreadyTLS {
		writeExtendedResponse(conn, messageID, ldap.LDAPResultOperationsError, "TLS layer already active", oidStartTLS)
		return nil, true
	}
	if tlsConfig == nil {
		writeExtendedResponse(conn, messageID, ldap.LDAPResultUnavailable, "StartTLS not available", oidStartTLS)
		return nil, true
	}
	if err := writeExtendedResponse(conn, messageID, ldap.LDAPResultSuccess, "", oidStartTLS); err != nil {
		return nil, false
	}

	tlsConn := tls.Server(conn, tlsConfig)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		if h.Logger != nil {
			h.Logger.Debug("ldap starttls handshake failed", "component", "ldapserver", "error", err)
		}
		return nil, false
	}
	return tlsConn, true
}
