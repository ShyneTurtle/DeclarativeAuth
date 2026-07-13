package admin

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"

	"declarativeauth/internal/config"
	"declarativeauth/internal/web"
)

// fileNameFor maps a URL fileKey ("users"|"groups"|"oidc-clients") to its
// on-disk file name under h.IdentityPath.
func fileNameFor(fileKey string) (string, bool) {
	switch fileKey {
	case "users":
		return "users.yaml", true
	case "groups":
		return "groups.yaml", true
	case "oidc-clients":
		return "oidc-clients.yaml", true
	default:
		return "", false
	}
}

// validateEdit re-validates fileKey's proposed content against everything
// else currently in the identity directory, by copying the *entire* real
// identity tree into a scratch directory, overlaying fileKey's proposed
// content on top, and running it through the exact same
// internal/config.LoadIdentity path used at startup/reload/CLI
// validate-config -- no separate/divergent validation logic to keep in
// sync. Copying the whole tree (not just the file being edited) matters
// because identity content can now be split across arbitrarily many/nested
// files (see internal/config.LoadIdentity), and because a relative
// passwordHashFile reference needs the same directory layout during
// live-validation as it has for the real running server, or it would
// report a spurious "file not found".
func (h *Handlers) validateEdit(fileKey, content string) error {
	tmpDir, err := os.MkdirTemp("", "declarativeauth-edit-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	if err := copyDirTree(h.IdentityPath, tmpDir); err != nil {
		return fmt.Errorf("preparing validation scratch copy: %w", err)
	}

	name, _ := fileNameFor(fileKey)
	if err := os.WriteFile(filepath.Join(tmpDir, name), []byte(content), 0o644); err != nil {
		return err
	}

	_, err = config.LoadIdentity(tmpDir)
	return err
}

// copyDirTree copies every regular file under src into dst, preserving the
// relative directory layout.
func copyDirTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
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

func (h *Handlers) handleConfigEditorOIDCClients(w http.ResponseWriter, r *http.Request, username string) {
	h.renderEditor(w, r, "oidc-clients")
}

// oidcClientsStarter is shown when oidc-clients.yaml doesn't exist on disk
// yet (it's optional -- see internal/config.LoadIdentity), so the editor
// has something valid to start from instead of a 500.
const oidcClientsStarter = `apiVersion: declarativeauth.io/v1
kind: OIDCClientList
clients: []
`

func (h *Handlers) renderEditor(w http.ResponseWriter, r *http.Request, fileKey string) {
	name, _ := fileNameFor(fileKey)
	body, err := os.ReadFile(filepath.Join(h.IdentityPath, name))
	if err != nil {
		if fileKey == "oidc-clients" && os.IsNotExist(err) {
			body = []byte(oidcClientsStarter)
		} else {
			http.Error(w, "reading "+name+": "+err.Error(), http.StatusInternalServerError)
			return
		}
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

func (h *Handlers) handleConfigSaveOIDCClients(w http.ResponseWriter, r *http.Request, username string) {
	h.handleConfigSave(w, r, "oidc-clients")
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

func (h *Handlers) handleConfigDownloadOIDCClients(w http.ResponseWriter, r *http.Request, username string) {
	h.handleConfigDownload(w, r, "oidc-clients")
}

func (h *Handlers) handleConfigDownload(w http.ResponseWriter, r *http.Request, fileKey string) {
	name, _ := fileNameFor(fileKey)
	body, err := os.ReadFile(filepath.Join(h.IdentityPath, name))
	if err != nil {
		if fileKey == "oidc-clients" && os.IsNotExist(err) {
			body = []byte(oidcClientsStarter)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Type", "application/x-yaml")
	_, _ = w.Write(body)
}

func jsString(s string) template.JS {
	b, _ := json.Marshal(s)
	return template.JS(b)
}
