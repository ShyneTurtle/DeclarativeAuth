package admin

import (
	"net/http"

	"declarativeauth/internal/web"
)

type smtpTestData struct {
	pageData
	CSRFToken string
	Result    string
	Error     string
}

func (h *Handlers) handleSMTPTest(w http.ResponseWriter, r *http.Request, username string) {
	secure := h.TrustedProxies.IsForwardedHTTPS(r)
	data := smtpTestData{pageData: pageData{Title: "SMTP test", ConfigEditorEnabled: h.ConfigEditorEnabled}}

	switch r.Method {
	case http.MethodGet:
		data.CSRFToken = web.IssueCSRFToken(w, r, secure)
		render(w, smtpTestTmpl, data)
	case http.MethodPost:
		data.CSRFToken = web.IssueCSRFToken(w, r, secure)
		if !web.ValidCSRF(r) {
			data.Error = "Your session expired, please try again."
			render(w, smtpTestTmpl, data)
			return
		}
		to := r.FormValue("to")
		err := h.Mail.SendTest(to)
		success := err == nil
		if h.OnSMTPTest != nil {
			h.OnSMTPTest(success)
		}
		if err != nil {
			data.Error = "Failed to send: " + err.Error()
		} else {
			data.Result = "Test email sent to " + to + "."
		}
		render(w, smtpTestTmpl, data)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
