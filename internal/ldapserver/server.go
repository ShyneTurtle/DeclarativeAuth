package ldapserver

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"

	"declarativeauth/internal/auth"
	"declarativeauth/internal/identity"
	"declarativeauth/internal/store"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// Handler ties the LDAP server to the shared auth/identity core.
type Handler struct {
	Config        Config
	Snapshot      func() *identity.Snapshot
	Authenticator *auth.Authenticator
	TrustedProxy  *auth.TrustedProxies
	Logger        *slog.Logger

	// Credentials, when Config.SambaReadersGroup is set, is consulted by a
	// privileged search to populate sambaNTPassword/sambaSID. Unused (may
	// be nil) otherwise.
	Credentials *store.CredentialStore

	OnBind   func(username string, success bool, sourceIP string, reason string)
	OnSearch func(sourceIP string)
}

// Server accepts LDAP connections and dispatches Bind/Search requests.
type Server struct {
	Handler *Handler
	// TLSConfig, when non-nil, is the certificate source offered to a
	// StartTLS request on this Server's connections. Leave nil either for a
	// listener that already terminates TLS at accept time (offering
	// StartTLS on top of TLS is nonsensical -- handleExtended rejects it
	// regardless) or to disable StartTLS entirely on a plaintext listener.
	TLSConfig *tls.Config
}

// Serve accepts connections on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	// A closure, not a bound method value: conn is reassigned in place on a
	// successful StartTLS upgrade, and this must close whichever conn is
	// current when handleConn returns, not the original plaintext one.
	defer func() { conn.Close() }()
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	bindUsername := "" // authenticated identity for this connection, if any

	for {
		packet, err := ber.ReadPacket(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && s.Handler.Logger != nil {
				s.Handler.Logger.Debug("ldap connection read error", "component", "ldapserver", "error", err)
			}
			return
		}
		if len(packet.Children) < 2 {
			return
		}
		messageID, ok := packet.Children[0].Value.(int64)
		if !ok {
			return
		}
		op := packet.Children[1]
		var controls *ber.Packet
		if len(packet.Children) > 2 {
			controls = packet.Children[2]
		}
		_, isTLS := conn.(*tls.Conn)

		switch op.Tag {
		case ldap.ApplicationBindRequest:
			user, ok := s.Handler.handleBind(conn, isTLS, remoteIP, messageID, op)
			if ok {
				bindUsername = user
			}
		case ldap.ApplicationUnbindRequest:
			return
		case ldap.ApplicationSearchRequest:
			startTLSAvailable := s.TLSConfig != nil && !isTLS
			s.Handler.handleSearch(conn, isTLS, remoteIP, bindUsername, messageID, op, controls, startTLSAvailable)
		case ldap.ApplicationExtendedRequest:
			upgraded, ok := s.Handler.handleExtended(conn, s.TLSConfig, messageID, op)
			if !ok {
				return // handshake failed after a success response already went out; connection is unusable
			}
			if upgraded != nil {
				conn = upgraded
				// RFC 4511 §4.14.1: discard any authentication state
				// established before the channel was encrypted.
				bindUsername = ""
			}
		case ldap.ApplicationAbandonRequest:
			// RFC 4511 §4.11: no response is ever sent for Abandon.
		case ldap.ApplicationAddRequest, ldap.ApplicationModifyRequest, ldap.ApplicationDelRequest,
			ldap.ApplicationModifyDNRequest, ldap.ApplicationCompareRequest:
			// Identity is read-only via LDAP -- a clean per-operation
			// rejection, not a dropped connection: a client issuing e.g. a
			// Compare is making a legitimate request this server simply
			// doesn't implement, not committing a protocol violation.
			writeResult(conn, messageID, unsupportedResponseTag(op.Tag), ldap.LDAPResultUnwillingToPerform, "", "identity is read-only via LDAP")
		default:
			writeExtendedResult(conn, messageID, ldap.LDAPResultProtocolError, "unrecognized operation")
			return
		}
	}
}

// unsupportedResponseTag maps a request's application tag to its
// corresponding response tag, for the read-only-identity rejection above.
func unsupportedResponseTag(requestTag ber.Tag) ber.Tag {
	switch requestTag {
	case ldap.ApplicationAddRequest:
		return ldap.ApplicationAddResponse
	case ldap.ApplicationModifyRequest:
		return ldap.ApplicationModifyResponse
	case ldap.ApplicationDelRequest:
		return ldap.ApplicationDelResponse
	case ldap.ApplicationModifyDNRequest:
		return ldap.ApplicationModifyDNResponse
	case ldap.ApplicationCompareRequest:
		return ldap.ApplicationCompareResponse
	default:
		return ldap.ApplicationExtendedResponse
	}
}
