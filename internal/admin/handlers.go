// Package admin is the small, separately-gated operator web UI: SMTP
// configuration test, a group-inheritance graph view, and (feature-flagged,
// single-instance deployments only) a declarative config editor. Every
// route requires the authenticated web session to be a member of the
// configured admin group.
package admin

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"

	"declarativeauth/internal/identity"
	"declarativeauth/internal/mail"
	"declarativeauth/internal/web"
)

//go:embed templates
var templatesFS embed.FS

func mustParse(page string) *template.Template {
	return template.Must(template.ParseFS(templatesFS, "templates/layout.html", "templates/"+page))
}

var (
	dashboardTmpl    = mustParse("dashboard.html")
	smtpTestTmpl     = mustParse("smtp_test.html")
	graphTmpl        = mustParse("graph.html")
	configEditorTmpl = mustParse("config_editor.html")
)

type pageData struct {
	Title               string
	ConfigEditorEnabled bool
}

// Handlers wires the /admin/* surface.
type Handlers struct {
	Snapshot            func() *identity.Snapshot
	CurrentUser         web.CurrentUserFunc
	AdminGroup          string
	Mail                *mail.Client
	IdentityPath        string
	ConfigEditorEnabled bool
	TrustedProxies      interface {
		IsForwardedHTTPS(r *http.Request) bool
	}

	OnSMTPTest func(success bool)

	Logger *slog.Logger
}

// NewMux builds the http.ServeMux for /admin/*, with every route gated
// behind admin-group membership.
func (h *Handlers) NewMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", h.gate(h.handleDashboard))
	mux.HandleFunc("/admin/smtp-test", h.gate(h.handleSMTPTest))
	mux.HandleFunc("/admin/graph", h.gate(h.handleGraph))
	if h.ConfigEditorEnabled {
		mux.HandleFunc("/admin/config/validate", h.gate(h.handleConfigValidate))
		mux.HandleFunc("/admin/config/users", h.gate(h.handleConfigEditorUsers))
		mux.HandleFunc("/admin/config/groups", h.gate(h.handleConfigEditorGroups))
		mux.HandleFunc("/admin/config/users/save", h.gate(h.handleConfigSaveUsers))
		mux.HandleFunc("/admin/config/groups/save", h.gate(h.handleConfigSaveGroups))
		mux.HandleFunc("/admin/config/users/download", h.gate(h.handleConfigDownloadUsers))
		mux.HandleFunc("/admin/config/groups/download", h.gate(h.handleConfigDownloadGroups))
	}
	return mux
}

func (h *Handlers) gate(next func(w http.ResponseWriter, r *http.Request, username string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, ok := h.CurrentUser(r)
		if !ok {
			http.Redirect(w, r, "/login?return_to="+r.URL.Path, http.StatusSeeOther)
			return
		}
		if !h.Snapshot().IsMemberOf(username, h.AdminGroup) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden: not a member of the admin group"))
			return
		}
		next(w, r, username)
	}
}

type dashboardData struct {
	pageData
	Username string
}

func (h *Handlers) handleDashboard(w http.ResponseWriter, r *http.Request, username string) {
	render(w, dashboardTmpl, dashboardData{
		pageData: pageData{Title: "Admin", ConfigEditorEnabled: h.ConfigEditorEnabled},
		Username: username,
	})
}

func render(w http.ResponseWriter, tmpl *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.ExecuteTemplate(w, "layout", data)
}
