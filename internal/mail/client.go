// Package mail sends MFA/reset emails over SMTP, with STARTTLS and AUTH
// used opportunistically (only if the server advertises support), so the
// same client works against both a real mail relay and a plain local
// mailcatcher used in dev/CI. It also supports implicit TLS ("SMTPS",
// conventionally port 465) for relays that don't offer STARTTLS.
package mail

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

const defaultTimeout = 10 * time.Second

// Config holds SMTP connection settings.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// HeloDomain is the domain sent in the SMTP HELO/EHLO greeting. Some
	// servers (Stalwart's relay listener among them) validate this against
	// SPF/anti-spam rules and reject anything that isn't a real-looking
	// domain -- "localhost" (the previous hardcoded value) or a bare
	// hostname like a spambot's "User" both get rejected as invalid.
	// Defaults to "localhost" if unset, which is fine for auth-gated
	// submission listeners and local dev relays (mailcatcher) that don't
	// validate it, but should be set to a real domain you control when
	// relaying through a listener that does.
	HeloDomain string
	// ImplicitTLS wraps the connection in TLS before any SMTP dialogue
	// ("SMTPS", conventionally port 465) instead of connecting in plaintext
	// and opportunistically upgrading via STARTTLS (port 587/25). Pointing
	// an implicit-TLS relay at this client with this left false (or vice
	// versa) is a protocol mismatch each side waits on the other for --
	// Timeout is what turns that into a clean error instead of a hang.
	ImplicitTLS bool
	// Timeout bounds the entire exchange (connect, optional TLS handshake,
	// AUTH, DATA), not just the initial dial -- a dial-only timeout doesn't
	// catch a protocol-level hang after the TCP connection is already up
	// (e.g. an ImplicitTLS mismatch). Defaults to 10s if zero.
	Timeout time.Duration
	// InsecureSkipVerify disables TLS certificate verification (both for
	// ImplicitTLS and STARTTLS). Only useful against a relay with a
	// self-signed or otherwise unverifiable cert -- it makes the connection
	// vulnerable to MITM, so prefer fixing the cert/trust store instead
	// wherever that's an option.
	InsecureSkipVerify bool
}

// Client sends plain+HTML emails via SMTP.
type Client struct {
	Config Config
}

// Send connects, opportunistically STARTTLS/AUTHs, and delivers a single
// message. Opens a new connection per send (low expected volume: MFA/reset
// emails are not bulk mail).
func (c *Client) Send(to, subject, textBody, htmlBody string) error {
	addr := net.JoinHostPort(c.Config.Host, strconv.Itoa(c.Config.Port))
	timeout := c.Config.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	if c.Config.ImplicitTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, c.tlsConfig())
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	// One deadline covering everything from here on (handshake already done
	// for ImplicitTLS; Hello/STARTTLS/AUTH/DATA/Quit for both modes), so a
	// server that never responds -- rather than actively refusing -- fails
	// within Timeout instead of hanging indefinitely.
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}

	client, err := smtp.NewClient(conn, c.Config.Host)
	if err != nil {
		return fmt.Errorf("smtp handshake: %w", err)
	}
	defer client.Close()

	helo := c.Config.HeloDomain
	if helo == "" {
		helo = "localhost"
	}
	if err := client.Hello(helo); err != nil {
		return err
	}

	if !c.Config.ImplicitTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(c.tlsConfig()); err != nil {
				return fmt.Errorf("starttls: %w", err)
			}
		}
	}

	if c.Config.Username != "" {
		if ok, _ := client.Extension("AUTH"); ok {
			auth := smtp.PlainAuth("", c.Config.Username, c.Config.Password, c.Config.Host)
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("smtp auth: %w", err)
			}
		}
	}

	from := extractAddr(c.Config.From)
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return err
	}
	msg := buildMIME(c.Config.From, to, subject, textBody, htmlBody)
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func (c *Client) tlsConfig() *tls.Config {
	return &tls.Config{
		ServerName:         c.Config.Host,
		InsecureSkipVerify: c.Config.InsecureSkipVerify,
	}
}

func extractAddr(fromHeader string) string {
	if i := strings.LastIndex(fromHeader, "<"); i != -1 {
		if j := strings.Index(fromHeader[i:], ">"); j != -1 {
			return fromHeader[i+1 : i+j]
		}
	}
	return fromHeader
}

func buildMIME(from, to, subject, textBody, htmlBody string) string {
	boundary := "declarativeauth-boundary"
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)

	fmt.Fprintf(&b, "--%s\r\n", boundary)
	fmt.Fprintf(&b, "Content-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n\r\n", textBody)

	if htmlBody != "" {
		fmt.Fprintf(&b, "--%s\r\n", boundary)
		fmt.Fprintf(&b, "Content-Type: text/html; charset=utf-8\r\n\r\n%s\r\n\r\n", htmlBody)
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.String()
}
