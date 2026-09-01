package admin

import (
	"net/http"

	"declarativeauth/internal/web"
)

// adminHomeData backs the merged "Admin" page: the email test form and the
// group graph, stacked on one page instead of two separate tab-switched
// ones -- both are small, low-traffic diagnostics, and splitting them
// across pages bought nothing but an extra click and an extra nav item.
type adminHomeData struct {
	pageData
	CSRFToken string
	Result    string
	Error     string
	graphViewData
}

// handleAdmin serves the "Admin" tab: an email-test form above the group
// inheritance graph. It's still reachable at both /admin/smtp-test (the
// email form's POST target) and /admin/graph (kept as a stable link for
// anything that already points at it) -- see NewMux.
func (h *Handlers) handleAdmin(w http.ResponseWriter, r *http.Request, username string) {
	secure := h.TrustedProxies.IsForwardedHTTPS(r)
	data := adminHomeData{
		pageData:      newPageData("Admin", "admin", h.ConfigEditorEnabled),
		graphViewData: computeGraphData(h.Snapshot()),
	}

	switch r.Method {
	case http.MethodGet:
		data.CSRFToken = web.IssueCSRFToken(w, r, secure)
		render(w, adminHomeTmpl, data)
	case http.MethodPost:
		data.CSRFToken = web.IssueCSRFToken(w, r, secure)
		if !web.ValidCSRF(r) {
			data.Error = "Your session expired, please try again."
			render(w, adminHomeTmpl, data)
			return
		}
		to := r.FormValue("to")
		err := h.Mail.SendTest(to)
		success := err == nil
		if h.OnSMTPTest != nil {
			h.OnSMTPTest(success)
		}
		if err != nil {
			if h.Logger != nil {
				h.Logger.Error("SMTP test send failed", "component", "admin", "to", to, "error", err)
			}
			data.Error = "Failed to send: " + err.Error()
		} else {
			data.Result = "Test email sent to " + to + "."
		}
		render(w, adminHomeTmpl, data)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
