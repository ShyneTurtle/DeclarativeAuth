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

	OnBind   func(username string, success bool, sourceIP string, reason string)
	OnSearch func(sourceIP string)
}

// Server accepts LDAP connections and dispatches Bind/Search requests.
type Server struct {
	Handler   *Handler
	TLSConfig *tls.Config // nil for plaintext
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
	defer conn.Close()
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	bindUsername := "" // authenticated identity for this connection, if any

	for {
		packet, err := ber.ReadPacket(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) {
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

		switch op.Tag {
		case ldap.ApplicationBindRequest:
			user, ok := s.Handler.handleBind(conn, remoteIP, messageID, op)
			if ok {
				bindUsername = user
			}
		case ldap.ApplicationUnbindRequest:
			return
		case ldap.ApplicationSearchRequest:
			s.Handler.handleSearch(conn, remoteIP, bindUsername, messageID, op)
		default:
			// Add/Modify/Delete/ModifyDN and anything else: unsupported,
			// identity is read-only via LDAP.
			writeExtendedResult(conn, messageID, ldap.LDAPResultUnwillingToPerform, "operation not supported")
			return
		}
	}
}
