package mail

// SendMFACode is a placeholder for the future email-OTP MFA extension; not
// wired to any live login-flow branch since MFA delivery is a natural
// extension of this same module once TOTP/MFA lands (see
// internal/store/migrations/00005_mfa_secrets.sql).
func (c *Client) SendMFACode(to, code string) error {
	return c.Send(to, "Your DeclarativeAuth verification code",
		"Your verification code is: "+code,
		"<p>Your verification code is: <strong>"+code+"</strong></p>")
}
