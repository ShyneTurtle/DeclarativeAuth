//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"declarativeauth/internal/auth"
	"declarativeauth/internal/config"
	"declarativeauth/internal/metrics"
	"declarativeauth/internal/server"
)

func startAdminServer(t *testing.T, configEditorEnabled bool) (issuer string, identityDir string) {
	t.Helper()
	pool := setupPool(t)

	// Copy the "valid" fixture into a writable temp dir, since the config
	// editor writes to IdentityPath directly.
	identityDir = t.TempDir()
	for _, name := range []string{"users.yaml", "groups.yaml"} {
		b, err := os.ReadFile(fixturePath(filepath.Join("valid", name)))
		if err != nil {
			t.Fatalf("read fixture %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(identityDir, name), b, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	oidcAddr := freePort(t)
	ldapAddr := freePort(t)
	cfg := &config.ServerConfig{
		Database: config.DatabaseConfig{DSN: testDSN(t), MaxConns: 5},
		LDAP:     config.LDAPConfig{ListenAddr: ldapAddr, BaseDN: "dc=example,dc=com"},
		OIDC:     config.OIDCConfig{Issuer: "http://" + oidcAddr, ListenAddr: oidcAddr},
		SMTP:     config.SMTPConfig{Host: "mailcatcher", Port: 1025, From: "DeclarativeAuth <test@example.com>"},
		RateLimit: config.RateLimitConfig{
			Threshold: 5, BackoffBase: config.Duration(time.Second),
			BackoffMax: config.Duration(15 * time.Minute), Window: config.Duration(24 * time.Hour),
		},
		Identity: config.IdentityConfig{IdentityPath: identityDir},
		AdminUI: config.AdminUIConfig{
			Enabled: true, AdminGroup: "admins",
			ConfigEditor: config.ConfigEditorConfig{Enabled: configEditorEnabled},
		},
	}
	t.Setenv(auth.PepperEnvVar, "admin-test-pepper")

	holder := &config.SnapshotHolder{}
	snap, err := config.LoadIdentity(identityDir)
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	holder.Set(snap)

	seedPassword(t, pool, "admin", "AdminSecret1!", "admin-test-pepper")
	seedPassword(t, pool, "jsmith", "Secret123!", "admin-test-pepper")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = server.Run(ctx, cfg, holder, pool, testLogger(), metrics.New()) }()
	time.Sleep(200 * time.Millisecond)

	return "http://" + oidcAddr, identityDir
}

func loginAs(t *testing.T, client *http.Client, jar *cookiejar.Jar, issuer, username, password string) {
	t.Helper()
	resp, err := client.Get(issuer + "/login")
	if err != nil {
		t.Fatalf("get login: %v", err)
	}
	resp.Body.Close()
	u, _ := url.Parse(issuer + "/login")
	var csrf string
	for _, c := range jar.Cookies(u) {
		if c.Name == "da_csrf" {
			csrf = c.Value
		}
	}
	resp, err = client.PostForm(issuer+"/login", url.Values{
		"username": {username}, "password": {password}, "csrf_token": {csrf}, "return_to": {"/"},
	})
	if err != nil {
		t.Fatalf("post login: %v", err)
	}
	resp.Body.Close()
}

func TestAdmin_NonAdminForbidden(t *testing.T) {
	issuer, _ := startAdminServer(t, false)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	loginAs(t, client, jar, issuer, "jsmith", "Secret123!")

	resp, err := client.Get(issuer + "/admin")
	if err != nil {
		t.Fatalf("get /admin: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin, got %d", resp.StatusCode)
	}
}

func TestAdmin_SMTPTest(t *testing.T) {
	api := mailcatcherAPI(t)
	clearMailcatcher(t, api)

	issuer, _ := startAdminServer(t, false)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	loginAs(t, client, jar, issuer, "admin", "AdminSecret1!")

	resp, err := client.Get(issuer + "/admin/smtp-test")
	if err != nil {
		t.Fatalf("get smtp-test: %v", err)
	}
	resp.Body.Close()
	u, _ := url.Parse(issuer + "/admin/smtp-test")
	var csrf string
	for _, c := range jar.Cookies(u) {
		if c.Name == "da_csrf" {
			csrf = c.Value
		}
	}

	resp, err = client.PostForm(issuer+"/admin/smtp-test", url.Values{
		"to": {"someone@example.com"}, "csrf_token": {csrf},
	})
	if err != nil {
		t.Fatalf("post smtp-test: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	deadline := time.Now().Add(5 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		r, err := http.Get(api + "/messages")
		if err == nil {
			var msgs []mcMessage
			_ = json.NewDecoder(r.Body).Decode(&msgs)
			r.Body.Close()
			for _, m := range msgs {
				for _, rcpt := range m.Recipients {
					if strings.Contains(rcpt, "someone@example.com") {
						found = true
					}
				}
			}
		}
		if found {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !found {
		t.Fatal("expected test email to arrive at mailcatcher")
	}
}

func TestAdmin_GroupGraph(t *testing.T) {
	issuer, _ := startAdminServer(t, false)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	loginAs(t, client, jar, issuer, "admin", "AdminSecret1!")

	resp, err := client.Get(issuer + "/admin/graph")
	if err != nil {
		t.Fatalf("get graph: %v", err)
	}
	defer resp.Body.Close()
	body := make([]byte, 16384)
	n, _ := resp.Body.Read(body)
	content := string(body[:n])
	if !strings.Contains(content, "<svg") || !strings.Contains(content, "engineering") {
		t.Fatalf("expected SVG graph containing group names, got: %s", content)
	}
}

func TestAdmin_ConfigEditor_DisabledByDefault404s(t *testing.T) {
	issuer, _ := startAdminServer(t, false)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	loginAs(t, client, jar, issuer, "admin", "AdminSecret1!")

	resp, err := client.Get(issuer + "/admin/config/users")
	if err != nil {
		t.Fatalf("get config editor: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 when configEditor.enabled=false, got %d", resp.StatusCode)
	}
}

func TestAdmin_ConfigEditor_ValidateAndSaveTriggersReload(t *testing.T) {
	issuer, identityDir := startAdminServer(t, true)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	loginAs(t, client, jar, issuer, "admin", "AdminSecret1!")

	resp, err := client.Get(issuer + "/admin/config/users")
	if err != nil {
		t.Fatalf("get config editor: %v", err)
	}
	resp.Body.Close()
	u, _ := url.Parse(issuer + "/admin/config/users")
	var csrf string
	for _, c := range jar.Cookies(u) {
		if c.Name == "da_csrf" {
			csrf = c.Value
		}
	}

	invalidContent := "apiVersion: declarativeauth.io/v1\nkind: UserList\nusers:\n  - username: x\n    memberOfGroups: [nonexistent-group]\n"
	resp, err = client.PostForm(issuer+"/admin/config/validate", url.Values{
		"fileKey": {"users"}, "content": {invalidContent}, "csrf_token": {csrf},
	})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	var vr map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&vr)
	resp.Body.Close()
	if vr["valid"] != false {
		t.Fatalf("expected invalid for dangling group ref, got %v", vr)
	}

	validContent, err := os.ReadFile(filepath.Join(identityDir, "users.yaml"))
	if err != nil {
		t.Fatalf("read users.yaml: %v", err)
	}
	newContent := string(validContent) + "  - username: newuser\n    email: newuser@example.com\n    enabled: true\n    memberOfGroups: []\n"

	resp, err = client.PostForm(issuer+"/admin/config/users/save", url.Values{
		"content": {newContent}, "csrf_token": {csrf},
	})
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	resp.Body.Close()

	waitFor(t, func() bool {
		b, err := os.ReadFile(filepath.Join(identityDir, "users.yaml"))
		return err == nil && strings.Contains(string(b), "newuser")
	}, 2*time.Second)
}
