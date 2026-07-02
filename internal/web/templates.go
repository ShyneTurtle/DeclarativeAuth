package web

import (
	"embed"
	"html/template"
)

//go:embed templates static
var assetsFS embed.FS

func mustParse(page string) *template.Template {
	return template.Must(template.ParseFS(assetsFS, "templates/layout.html", "templates/"+page))
}

var (
	loginTmpl        = mustParse("login.html")
	errorTmpl        = mustParse("error.html")
	resetRequestTmpl = mustParse("reset_request.html")
	resetSentTmpl    = mustParse("reset_sent.html")
	resetConfirmTmpl = mustParse("reset_confirm.html")
)
