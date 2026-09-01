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

	"declarativeauth/internal/appshell"
	"declarativeauth/internal/buildinfo"
	"declarativeauth/internal/identity"
	"declarativeauth/internal/mail"
	"declarativeauth/internal/uiicons"
	"declarativeauth/internal/web"
)

//go:embed templates
var templatesFS embed.FS

// mustParse parses page against the shared app shell (internal/appshell),
// the same one internal/web uses for the account page -- see that
// package's mustParseShell and shell.html's own doc comment.
func mustParse(page string) *template.Template {
	funcs := template.FuncMap{
		"version": func() string { return buildinfo.Version },
	}
	for k, v := range uiicons.FuncMap() {
		funcs[k] = v
	}
	tmpl := template.Must(template.New("shell.html").Funcs(funcs).ParseFS(appshell.FS, "shell.html"))
	return template.Must(tmpl.ParseFS(templatesFS, "templates/"+page))
}

var (
	adminHomeTmpl    = mustParse("admin_home.html")
	configEditorTmpl = mustParse("config_editor.html")
)

type pageData struct {
	Title               string
	ConfigEditorEnabled bool
	// Active identifies which top tab to highlight: "admin" (shared by the
	// email-test and group-graph pages, which present as tabs of one
	// section) or "config". The "My account" tab is never active from
	// within the admin package -- it always points back to the web app.
	Active string
	// IsAdmin is always true -- every /admin page is reached only via
	// Handlers.gate, which already requires admin-group membership -- but
	// shell.html (shared with the account page, where this varies per
	// viewer) reads it unconditionally, so it still needs to be set here.
	IsAdmin bool
}

// newPageData is the one place that constructs pageData, so IsAdmin can't
// be forgotten by a future handler the way a bare struct literal would
// allow.
func newPageData(title, active string, configEditorEnabled bool) pageData {
	return pageData{Title: title, ConfigEditorEnabled: configEditorEnabled, Active: active, IsAdmin: true}
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
	mux.HandleFunc("/admin", h.gate(h.handleAdmin))
	mux.HandleFunc("/admin/smtp-test", h.gate(h.handleAdmin))
	mux.HandleFunc("/admin/graph", h.gate(h.handleAdmin))
	if h.ConfigEditorEnabled {
		// File identity is a path relative to h.IdentityPath, discovered
		// dynamically (see config.ListIdentityFiles) rather than a fixed
		// users/groups/oidc-clients enum, matching how LoadIdentity itself
		// finds config -- any file name, any nesting. {file...} captures
		// the rest of the path, slashes included.
		mux.HandleFunc("/admin/config", h.gate(h.handleConfigIndex))
		mux.HandleFunc("/admin/config/validate", h.gate(h.handleConfigValidate))
		mux.HandleFunc("/admin/config/edit/{file...}", h.gate(h.handleConfigEdit))
		mux.HandleFunc("/admin/config/save/{file...}", h.gate(h.handleConfigSave))
		mux.HandleFunc("/admin/config/download/{file...}", h.gate(h.handleConfigDownload))
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

func render(w http.ResponseWriter, tmpl *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.ExecuteTemplate(w, "layout", data)
}
