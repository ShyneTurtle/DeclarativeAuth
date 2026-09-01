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

// validateEdit re-validates relPath's proposed content against everything
// else currently in the identity directory, by copying the *entire* real
// identity tree into a scratch directory, overlaying relPath's proposed
// content on top, and running it through the exact same
// internal/config.LoadIdentity path used at startup/reload/CLI
// validate-config -- no separate/divergent validation logic to keep in
// sync. Copying the whole tree (not just the file being edited) matters
// because identity content can now be split across arbitrarily many/nested
// files (see internal/config.LoadIdentity), and because a relative
// passwordHashFile reference needs the same directory layout during
// live-validation as it has for the real running server, or it would
// report a spurious "file not found".
func (h *Handlers) validateEdit(relPath, content string) error {
	tmpDir, err := os.MkdirTemp("", "declarativeauth-edit-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	if err := copyDirTree(h.IdentityPath, tmpDir); err != nil {
		return fmt.Errorf("preparing validation scratch copy: %w", err)
	}

	target, err := config.ResolveIdentityFile(tmpDir, relPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
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
	Files       []config.IdentityFile
	FilePath    string
	FilePathJS  template.JS
	Content     string
	CSRFToken   string
	CSRFTokenJS template.JS
	Error       string
	Success     bool
}

// knownFile reports whether relPath is one of the files ListIdentityFiles
// actually discovered -- i.e. the operator is editing/saving/downloading a
// real declarative config file, not an arbitrary path that merely resolves
// somewhere inside the identity directory.
func knownFile(files []config.IdentityFile, relPath string) bool {
	for _, f := range files {
		if f.Path == relPath {
			return true
		}
	}
	return false
}

// handleConfigIndex serves /admin/config: it has no file of its own to
// show, so it redirects to whichever declarative config file sorts first
// -- there's no more fixed "users.yaml" to default to now that files are
// discovered dynamically (see config.ListIdentityFiles), same as
// LoadIdentity itself no longer assumes any particular file name exists.
func (h *Handlers) handleConfigIndex(w http.ResponseWriter, r *http.Request, username string) {
	files, err := config.ListIdentityFiles(h.IdentityPath)
	if err != nil {
		http.Error(w, "listing config files: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if len(files) == 0 {
		h.renderEditor(w, r, "", files, "", "", false)
		return
	}
	http.Redirect(w, r, "/admin/config/edit/"+files[0].Path, http.StatusSeeOther)
}

func (h *Handlers) handleConfigEdit(w http.ResponseWriter, r *http.Request, username string) {
	relPath := r.PathValue("file")
	files, err := config.ListIdentityFiles(h.IdentityPath)
	if err != nil {
		http.Error(w, "listing config files: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !knownFile(files, relPath) {
		http.NotFound(w, r)
		return
	}
	target, err := config.ResolveIdentityFile(h.IdentityPath, relPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	body, err := os.ReadFile(target)
	if err != nil {
		http.Error(w, "reading "+relPath+": "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.renderEditor(w, r, relPath, files, string(body), "", false)
}

func (h *Handlers) renderEditor(w http.ResponseWriter, r *http.Request, relPath string, files []config.IdentityFile, content, errMsg string, success bool) {
	secure := h.TrustedProxies.IsForwardedHTTPS(r)
	csrf := web.IssueCSRFToken(w, r, secure)
	title := "Config editor"
	if relPath != "" {
		title = "Config editor: " + relPath
	}
	render(w, configEditorTmpl, configEditorData{
		pageData:    newPageData(title, "config", h.ConfigEditorEnabled),
		Files:       files,
		FilePath:    relPath,
		FilePathJS:  jsString(relPath),
		Content:     content,
		CSRFToken:   csrf,
		CSRFTokenJS: jsString(csrf),
		Error:       errMsg,
		Success:     success,
	})
}

func (h *Handlers) handleConfigValidate(w http.ResponseWriter, r *http.Request, username string) {
	if r.Method != http.MethodPost || !web.ValidCSRF(r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	relPath := r.FormValue("file")
	files, err := config.ListIdentityFiles(h.IdentityPath)
	if err != nil || !knownFile(files, relPath) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	content := r.FormValue("content")
	err = h.validateEdit(relPath, content)

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"valid": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"valid": true})
}

func (h *Handlers) handleConfigSave(w http.ResponseWriter, r *http.Request, username string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	relPath := r.PathValue("file")
	content := r.FormValue("content")

	files, err := config.ListIdentityFiles(h.IdentityPath)
	if err != nil {
		http.Error(w, "listing config files: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !knownFile(files, relPath) {
		http.NotFound(w, r)
		return
	}

	if !web.ValidCSRF(r) {
		h.renderEditor(w, r, relPath, files, content, "Your session expired, please try again.", false)
		return
	}
	if err := h.validateEdit(relPath, content); err != nil {
		h.renderEditor(w, r, relPath, files, content, "Not saved -- validation failed: "+err.Error(), false)
		return
	}
	target, err := config.ResolveIdentityFile(h.IdentityPath, relPath)
	if err != nil {
		h.renderEditor(w, r, relPath, files, content, "Invalid file path: "+err.Error(), false)
		return
	}
	// Write directly to the mounted identity file; the existing
	// fsnotify-based hot-reload watcher picks this up as a normal file
	// write, same as any external ConfigMap update.
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		h.renderEditor(w, r, relPath, files, content, "Failed to write file: "+err.Error(), false)
		return
	}
	h.renderEditor(w, r, relPath, files, content, "", true)
}

func (h *Handlers) handleConfigDownload(w http.ResponseWriter, r *http.Request, username string) {
	relPath := r.PathValue("file")
	files, err := config.ListIdentityFiles(h.IdentityPath)
	if err != nil {
		http.Error(w, "listing config files: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !knownFile(files, relPath) {
		http.NotFound(w, r)
		return
	}
	target, err := config.ResolveIdentityFile(h.IdentityPath, relPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	body, err := os.ReadFile(target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+filepath.Base(relPath)+`"`)
	w.Header().Set("Content-Type", "application/x-yaml")
	_, _ = w.Write(body)
}

func jsString(s string) template.JS {
	b, _ := json.Marshal(s)
	return template.JS(b)
}
