package web

import (
	"embed"
	"html/template"

	"declarativeauth/internal/appshell"
	"declarativeauth/internal/buildinfo"
	"declarativeauth/internal/uiicons"
)

//go:embed templates static
var assetsFS embed.FS

func templateFuncs() template.FuncMap {
	funcs := template.FuncMap{
		"version": func() string { return buildinfo.Version },
	}
	for k, v := range uiicons.FuncMap() {
		funcs[k] = v
	}
	return funcs
}

// mustParse is for the narrow pre-login auth pages (login, reset, MFA
// verify, error), which use this package's own "layout" (see
// templates/layout.html).
func mustParse(page string) *template.Template {
	return template.Must(template.New("layout.html").Funcs(templateFuncs()).ParseFS(assetsFS, "templates/layout.html", "templates/"+page))
}

// mustParseShell is for pages that belong to the shared tabbed app shell
// (currently just the account page) -- see internal/appshell.
func mustParseShell(page string) *template.Template {
	tmpl := template.Must(template.New("shell.html").Funcs(templateFuncs()).ParseFS(appshell.FS, "shell.html"))
	return template.Must(tmpl.ParseFS(assetsFS, "templates/"+page))
}

var (
	loginTmpl        = mustParse("login.html")
	errorTmpl        = mustParse("error.html")
	resetRequestTmpl = mustParse("reset_request.html")
	resetSentTmpl    = mustParse("reset_sent.html")
	resetConfirmTmpl = mustParse("reset_confirm.html")
	homeTmpl         = mustParseShell("home.html")
	mfaVerifyTmpl    = mustParse("mfa_verify.html")
)
