package mail

// SendMFACode emails a one-time email-MFA verification code, sent from
// web.MFAHandlers after a successful password login for any account that
// requires (or has self-enabled) email-based MFA.
func (c *Client) SendMFACode(to, code string) error {
	return c.Send(to, "Your DeclarativeAuth verification code",
		"Your verification code is: "+code,
		"<p>Your verification code is: <strong>"+code+"</strong></p>")
}
