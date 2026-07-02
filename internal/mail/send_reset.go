package mail

// SendReset sends a password reset/setup email containing link, which
// expires in expiresIn (a human string like "30 minutes", already formatted
// by the caller).
func (c *Client) SendReset(to, link, expiresIn string) error {
	text, html, err := RenderReset(link, expiresIn)
	if err != nil {
		return err
	}
	return c.Send(to, "Reset your DeclarativeAuth password", text, html)
}

// SendTest sends a fixed-content test email, used by the admin UI's SMTP
// test page (Section 8b) to verify SMTP configuration without needing a
// real reset flow.
func (c *Client) SendTest(to string) error {
	return c.Send(to, "DeclarativeAuth SMTP test",
		"This is a test email from DeclarativeAuth confirming your SMTP configuration works.",
		"<p>This is a test email from DeclarativeAuth confirming your SMTP configuration works.</p>")
}
