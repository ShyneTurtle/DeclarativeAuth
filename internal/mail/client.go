// Package mail sends MFA/reset emails over SMTP, with STARTTLS and AUTH
// used opportunistically (only if the server advertises support), so the
// same client works against both a real mail relay and a plain local
// mailcatcher used in dev/CI.
package mail

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
)

// Config holds SMTP connection settings.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// Client sends plain+HTML emails via SMTP.
type Client struct {
	Config Config
}

// Send connects, opportunistically STARTTLS/AUTHs, and delivers a single
// message. Opens a new connection per send (low expected volume: MFA/reset
// emails are not bulk mail).
func (c *Client) Send(to, subject, textBody, htmlBody string) error {
	addr := fmt.Sprintf("%s:%d", c.Config.Host, c.Config.Port)
	conn, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	if err := conn.Hello("localhost"); err != nil {
		return err
	}

	if ok, _ := conn.Extension("STARTTLS"); ok {
		tlsConfig := &tls.Config{ServerName: c.Config.Host}
		if err := conn.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}

	if c.Config.Username != "" {
		if ok, _ := conn.Extension("AUTH"); ok {
			auth := smtp.PlainAuth("", c.Config.Username, c.Config.Password, c.Config.Host)
			if err := conn.Auth(auth); err != nil {
				return fmt.Errorf("smtp auth: %w", err)
			}
		}
	}

	from := extractAddr(c.Config.From)
	if err := conn.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := conn.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}

	w, err := conn.Data()
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
	return conn.Quit()
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
