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
		OIDC:           config.OIDCConfig{SecureListenAddr: "0.0.0.0:8443"},
		LDAP:           config.LDAPConfig{SecureListenAddr: "0.0.0.0:636", RequireTLS: true},
		PasswordPolicy: config.PasswordPolicyConfig{MinLength: 8, MinStrength: 2},
	}
	if out := warningsFor(cfg); out != "" {
		t.Errorf("expected no warnings for a locked-down config, got:\n%s", out)
	}
}

func TestWarnInsecureConfig_PlaintextListenersAndUnrequiredTLS(t *testing.T) {
	cfg := &config.ServerConfig{
		OIDC: config.OIDCConfig{ListenAddr: "0.0.0.0:8080"},
		LDAP: config.LDAPConfig{ListenAddr: "0.0.0.0:389", RequireTLS: false},
	}
	out := warningsFor(cfg)
	if !strings.Contains(out, config.EnvOIDCListenAddr+" is set") {
		t.Error("expected a warning about " + config.EnvOIDCListenAddr)
	}
	if !strings.Contains(out, config.EnvLDAPRequireTLS+" is false") {
		t.Error("expected a warning about " + config.EnvLDAPRequireTLS)
	}
}

func TestWarnInsecureConfig_AnonymousBind(t *testing.T) {
	cfg := &config.ServerConfig{
		OIDC: config.OIDCConfig{SecureListenAddr: "0.0.0.0:8443"},
		LDAP: config.LDAPConfig{SecureListenAddr: "0.0.0.0:636", AllowAnonymousBind: true, RequireTLS: true},
	}
	if out := warningsFor(cfg); !strings.Contains(out, config.EnvLDAPAllowAnonymousBind+" is true") {
		t.Errorf("expected a warning about allowAnonymousBind, got:\n%s", out)
	}
}

func TestWarnInsecureConfig_WeakPasswordPolicy(t *testing.T) {
	cfg := &config.ServerConfig{
		OIDC:           config.OIDCConfig{SecureListenAddr: "0.0.0.0:8443"},
		LDAP:           config.LDAPConfig{SecureListenAddr: "0.0.0.0:636", RequireTLS: true},
		PasswordPolicy: config.PasswordPolicyConfig{MinLength: 4, MinStrength: 1},
	}
	out := warningsFor(cfg)
	if !strings.Contains(out, config.EnvPasswordPolicyMinLength+" is set below") {
		t.Error("expected a warning about " + config.EnvPasswordPolicyMinLength)
	}
	if !strings.Contains(out, config.EnvPasswordPolicyMinStrength+" is set below") {
		t.Error("expected a warning about " + config.EnvPasswordPolicyMinStrength)
	}
}

func TestWarnInsecureConfig_ConfigEditorOverPlaintext(t *testing.T) {
	cfg := &config.ServerConfig{
		OIDC:    config.OIDCConfig{ListenAddr: "0.0.0.0:8080"},
		AdminUI: config.AdminUIConfig{Enabled: true, ConfigEditor: config.ConfigEditorConfig{Enabled: true}},
	}
	if out := warningsFor(cfg); !strings.Contains(out, config.EnvAdminUIConfigEditorEnabled+" is true") {
		t.Errorf("expected a warning about the config editor over plaintext, got:\n%s", out)
	}
}
