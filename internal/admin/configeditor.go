package admin

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"

	"declarativeauth/internal/config"
	"declarativeauth/internal/web"
)

// fileNameFor maps a URL fileKey ("users"|"groups") to its on-disk file
// name under h.IdentityPath.
func fileNameFor(fileKey string) (string, bool) {
	switch fileKey {
	case "users":
		return "users.yaml", true
	case "groups":
		return "groups.yaml", true
	default:
		return "", false
	}
}

// validateEdit re-validates fileKey's proposed content against the *other*
// file currently on disk, by writing both into a scratch temp directory and
// running it through the exact same internal/config.LoadIdentity path used
// at startup/reload/CLI validate-config -- no separate/divergent validation
// logic to keep in sync.
func (h *Handlers) validateEdit(fileKey, content string) error {
	tmpDir, err := os.MkdirTemp("", "declarativeauth-edit-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	for _, key := range []string{"users", "groups"} {
		name, _ := fileNameFor(key)
		var body []byte
		if key == fileKey {
			body = []byte(content)
		} else {
			body, err = os.ReadFile(filepath.Join(h.IdentityPath, name))
			if err != nil {
				return fmt.Errorf("reading current %s: %w", name, err)
			}
		}
		if err := os.WriteFile(filepath.Join(tmpDir, name), body, 0o644); err != nil {
			return err
		}
	}

	_, err = config.LoadIdentity(tmpDir)
	return err
}

type configEditorData struct {
	pageData
	FileKey     string
	FileKeyJS   template.JS
	FileName    string
	Content     string
	CSRFToken   string
	CSRFTokenJS template.JS
	Error       string
	Success     bool
}

func (h *Handlers) handleConfigEditorUsers(w http.ResponseWriter, r *http.Request, username string) {
	h.renderEditor(w, r, "users")
}

func (h *Handlers) handleConfigEditorGroups(w http.ResponseWriter, r *http.Request, username string) {
	h.renderEditor(w, r, "groups")
}

func (h *Handlers) renderEditor(w http.ResponseWriter, r *http.Request, fileKey string) {
	name, _ := fileNameFor(fileKey)
	body, err := os.ReadFile(filepath.Join(h.IdentityPath, name))
	if err != nil {
		http.Error(w, "reading "+name+": "+err.Error(), http.StatusInternalServerError)
		return
	}
	secure := h.TrustedProxies.IsForwardedHTTPS(r)
	csrf := web.IssueCSRFToken(w, r, secure)
	render(w, configEditorTmpl, configEditorData{
		pageData:    pageData{Title: "Config editor: " + name, ConfigEditorEnabled: h.ConfigEditorEnabled},
		FileKey:     fileKey,
		FileKeyJS:   jsString(fileKey),
		FileName:    name,
		Content:     string(body),
		CSRFToken:   csrf,
		CSRFTokenJS: jsString(csrf),
	})
}

func (h *Handlers) handleConfigValidate(w http.ResponseWriter, r *http.Request, username string) {
	if r.Method != http.MethodPost || !web.ValidCSRF(r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	fileKey := r.FormValue("fileKey")
	if _, ok := fileNameFor(fileKey); !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	content := r.FormValue("content")
	err := h.validateEdit(fileKey, content)

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"valid": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"valid": true})
}

func (h *Handlers) handleConfigSaveUsers(w http.ResponseWriter, r *http.Request, username string) {
	h.handleConfigSave(w, r, "users")
}

func (h *Handlers) handleConfigSaveGroups(w http.ResponseWriter, r *http.Request, username string) {
	h.handleConfigSave(w, r, "groups")
}

func (h *Handlers) handleConfigSave(w http.ResponseWriter, r *http.Request, fileKey string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	name, _ := fileNameFor(fileKey)
	content := r.FormValue("content")
	secure := h.TrustedProxies.IsForwardedHTTPS(r)

	data := configEditorData{
		pageData: pageData{Title: "Config editor: " + name, ConfigEditorEnabled: h.ConfigEditorEnabled},
		FileKey:  fileKey, FileKeyJS: jsString(fileKey), FileName: name, Content: content,
	}
	if !web.ValidCSRF(r) {
		data.Error = "Your session expired, please try again."
		data.CSRFToken = web.IssueCSRFToken(w, r, secure)
		data.CSRFTokenJS = jsString(data.CSRFToken)
		render(w, configEditorTmpl, data)
		return
	}
	if err := h.validateEdit(fileKey, content); err != nil {
		data.Error = "Not saved -- validation failed: " + err.Error()
		data.CSRFToken = web.IssueCSRFToken(w, r, secure)
		data.CSRFTokenJS = jsString(data.CSRFToken)
		render(w, configEditorTmpl, data)
		return
	}
	// Write directly to the mounted identity file; the existing
	// fsnotify-based hot-reload watcher picks this up as a normal file
	// write, same as any external ConfigMap update.
	if err := os.WriteFile(filepath.Join(h.IdentityPath, name), []byte(content), 0o644); err != nil {
		data.Error = "Failed to write file: " + err.Error()
		data.CSRFToken = web.IssueCSRFToken(w, r, secure)
		data.CSRFTokenJS = jsString(data.CSRFToken)
		render(w, configEditorTmpl, data)
		return
	}
	data.Success = true
	data.CSRFToken = web.IssueCSRFToken(w, r, secure)
	data.CSRFTokenJS = jsString(data.CSRFToken)
	render(w, configEditorTmpl, data)
}

func (h *Handlers) handleConfigDownloadUsers(w http.ResponseWriter, r *http.Request, username string) {
	h.handleConfigDownload(w, r, "users")
}

func (h *Handlers) handleConfigDownloadGroups(w http.ResponseWriter, r *http.Request, username string) {
	h.handleConfigDownload(w, r, "groups")
}

func (h *Handlers) handleConfigDownload(w http.ResponseWriter, r *http.Request, fileKey string) {
	name, _ := fileNameFor(fileKey)
	body, err := os.ReadFile(filepath.Join(h.IdentityPath, name))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Type", "application/x-yaml")
	_, _ = w.Write(body)
}

func jsString(s string) template.JS {
	b, _ := json.Marshal(s)
	return template.JS(b)
}
