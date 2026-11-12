package web

import (
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTOTPSetupPageRenders(t *testing.T) {
	w := httptest.NewRecorder()
	render(w, totpSetupTmpl, totpSetupPageData{
		Title:     "Set up your authenticator app",
		CSRFToken: "tok",
		Secret:    "ABCDEF",
		QR:        template.URL("data:image/png;base64,AAAA"),
		Error:     "Incorrect code, please try again.",
		Action:    "/account/totp/confirm",
	})
	body := w.Body.String()
	for _, want := range []string{`src="data:image/png;base64,AAAA"`, "ABCDEF", `action="/account/totp/confirm"`, `value="tok"`, "Incorrect code", `href="/">Cancel`} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q:\n%s", want, body)
		}
	}
}

func TestTOTPSetupPage_ForcedEnrolmentHasNoWayOut(t *testing.T) {
	w := httptest.NewRecorder()
	render(w, totpSetupTmpl, totpSetupPageData{
		Title: "Set up", CSRFToken: "tok", Secret: "ABCDEF", QR: template.URL("data:image/png;base64,AAAA"),
		Action: "/login/mfa/enroll", Required: true,
	})
	body := w.Body.String()
	if !strings.Contains(body, `action="/login/mfa/enroll"`) || !strings.Contains(body, "requires two-factor") {
		t.Errorf("missing forced-enrolment wording/action:\n%s", body)
	}
	if strings.Contains(body, `href="/">Cancel`) {
		t.Error("forced enrolment must not offer to skip into the account page")
	}
}

func TestMFAVerifyPage(t *testing.T) {
	cases := []struct {
		name               string
		hasTOTP, emailSent bool
		want, notWant      string
	}{
		{"app default, nothing emailed", true, false, "Email me a code instead", "Resend code"},
		{"app user who asked for email", true, true, "Resend code", "Email me a code instead"},
		{"no app, emailed", false, true, "Resend code", "authenticator app"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			render(w, mfaVerifyTmpl, mfaVerifyPageData{Title: "Verify", CSRFToken: "tok", HasTOTP: c.hasTOTP, EmailSent: c.emailSent})
			body := w.Body.String()
			if !strings.Contains(body, c.want) {
				t.Errorf("missing %q:\n%s", c.want, body)
			}
			if strings.Contains(body, c.notWant) {
				t.Errorf("unexpected %q:\n%s", c.notWant, body)
			}
		})
	}
}

func TestHomePageTOTPSection(t *testing.T) {
	cases := []struct {
		name                  string
		enabled, enrolled     bool
		required              bool
		wantSetup, wantRemove bool
	}{
		{"disabled", false, false, false, false, false},
		{"not enrolled", true, false, false, true, false},
		{"enrolled", true, true, false, true, true},
		{"enrolled but required", true, true, true, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			render(w, homeTmpl, homePageData{
				Title: "My account", Active: "account", CSRFToken: "tok",
				TOTPEnabled: c.enabled, TOTPEnrolled: c.enrolled, MFARequired: c.required,
			})
			body := w.Body.String()
			if got := strings.Contains(body, "/account/totp/setup"); got != c.wantSetup {
				t.Errorf("setup form present = %v, want %v", got, c.wantSetup)
			}
			if got := strings.Contains(body, "/account/totp/remove"); got != c.wantRemove {
				t.Errorf("remove form present = %v, want %v", got, c.wantRemove)
			}
		})
	}
}
