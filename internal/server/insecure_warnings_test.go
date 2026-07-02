package server

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"declarativeauth/internal/config"
)

func warningsFor(cfg *config.ServerConfig) string {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	warnInsecureConfig(cfg, logger)
	return buf.String()
}

func TestWarnInsecureConfig_FullyLockedDown(t *testing.T) {
	cfg := &config.ServerConfig{
		OIDC:           config.OIDCConfig{TLS: config.TLSListenerConfig{Enabled: true}},
		LDAP:           config.LDAPConfig{TLS: config.TLSListenerConfig{Enabled: true}},
		PasswordPolicy: config.PasswordPolicyConfig{MinLength: 8, MinStrength: 2},
	}
	if out := warningsFor(cfg); out != "" {
		t.Errorf("expected no warnings for a locked-down config, got:\n%s", out)
	}
}

func TestWarnInsecureConfig_PlaintextListeners(t *testing.T) {
	cfg := &config.ServerConfig{}
	out := warningsFor(cfg)
	if !strings.Contains(out, "oidc.tls.enabled is false") {
		t.Error("expected a warning about oidc.tls.enabled")
	}
	if !strings.Contains(out, "ldap.tls.enabled is false") {
		t.Error("expected a warning about ldap.tls.enabled")
	}
}

func TestWarnInsecureConfig_AnonymousBind(t *testing.T) {
	cfg := &config.ServerConfig{
		OIDC: config.OIDCConfig{TLS: config.TLSListenerConfig{Enabled: true}},
		LDAP: config.LDAPConfig{TLS: config.TLSListenerConfig{Enabled: true}, AllowAnonymousBind: true},
	}
	if out := warningsFor(cfg); !strings.Contains(out, "allowAnonymousBind is true") {
		t.Errorf("expected a warning about allowAnonymousBind, got:\n%s", out)
	}
}

func TestWarnInsecureConfig_WeakPasswordPolicy(t *testing.T) {
	cfg := &config.ServerConfig{
		OIDC:           config.OIDCConfig{TLS: config.TLSListenerConfig{Enabled: true}},
		LDAP:           config.LDAPConfig{TLS: config.TLSListenerConfig{Enabled: true}},
		PasswordPolicy: config.PasswordPolicyConfig{MinLength: 4, MinStrength: 1},
	}
	out := warningsFor(cfg)
	if !strings.Contains(out, "minLength is set below") {
		t.Error("expected a warning about minLength")
	}
	if !strings.Contains(out, "minStrength is set below") {
		t.Error("expected a warning about minStrength")
	}
}

func TestWarnInsecureConfig_ConfigEditorOverPlaintext(t *testing.T) {
	cfg := &config.ServerConfig{
		AdminUI: config.AdminUIConfig{Enabled: true, ConfigEditor: config.ConfigEditorConfig{Enabled: true}},
	}
	if out := warningsFor(cfg); !strings.Contains(out, "adminUI.configEditor.enabled is true") {
		t.Errorf("expected a warning about the config editor over plaintext, got:\n%s", out)
	}
}
