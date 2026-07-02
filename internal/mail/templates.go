package mail

import (
	"bytes"
	"html/template"
	textTemplate "text/template"
)

type resetData struct {
	Link      string
	ExpiresIn string
}

var resetTextTmpl = textTemplate.Must(textTemplate.New("reset_text").Parse(
	`Hello,

A password reset (or account setup) was requested for your DeclarativeAuth account.

Set your password here: {{.Link}}

This link expires in {{.ExpiresIn}} and can only be used once.

If you didn't request this, you can safely ignore this email.
`))

var resetHTMLTmpl = template.Must(template.New("reset_html").Parse(
	`<p>Hello,</p>
<p>A password reset (or account setup) was requested for your DeclarativeAuth account.</p>
<p><a href="{{.Link}}">Set your password</a></p>
<p>This link expires in {{.ExpiresIn}} and can only be used once.</p>
<p>If you didn't request this, you can safely ignore this email.</p>
`))

// RenderReset renders the plain-text and HTML bodies for a password
// reset/setup email.
func RenderReset(link, expiresIn string) (text, html string, err error) {
	d := resetData{Link: link, ExpiresIn: expiresIn}
	var tb, hb bytes.Buffer
	if err := resetTextTmpl.Execute(&tb, d); err != nil {
		return "", "", err
	}
	if err := resetHTMLTmpl.Execute(&hb, d); err != nil {
		return "", "", err
	}
	return tb.String(), hb.String(), nil
}
