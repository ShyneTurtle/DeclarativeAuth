package config

import (
	"testing"
	"time"
)

func TestLoadServerConfigFromEnv_Defaults(t *testing.T) {
	cfg, err := LoadServerConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Logging.Level != "info" || cfg.Logging.Format != "json" {
		t.Errorf("unexpected logging defaults: %+v", cfg.Logging)
	}
	if cfg.Database.MaxConns != 10 {
		t.Errorf("expected default MaxConns 10, got %d", cfg.Database.MaxConns)
	}
	if cfg.Database.ConnectTimeout.Std() != 5*time.Second {
		t.Errorf("expected default ConnectTimeout 5s, got %v", cfg.Database.ConnectTimeout.Std())
	}
	if cfg.LDAP.ListenAddr != "" || cfg.LDAP.SecureListenAddr != "" || cfg.LDAP.BaseDN != "" {
		t.Errorf("expected LDAP listeners and base DN unset by default: %+v", cfg.LDAP)
	}
	if cfg.OIDC.ListenAddr != "" || cfg.OIDC.SecureListenAddr != "" {
		t.Errorf("expected OIDC listeners unset by default: %+v", cfg.OIDC)
	}
	if cfg.Metrics.ListenAddr != "" {
		t.Errorf("expected metrics listen addr unset by default: %q", cfg.Metrics.ListenAddr)
	}
	if cfg.Identity.IdentityPath != "/etc/declarativeauth/identity" {
		t.Errorf("unexpected identity path default: %q", cfg.Identity.IdentityPath)
	}
	if cfg.Identity.ReloadDebounce.Std() != 500*time.Millisecond {
		t.Errorf("unexpected reload debounce default: %v", cfg.Identity.ReloadDebounce.Std())
	}
	if !cfg.Network.TrustsDefaultGateway() {
		t.Error("expected TrustsDefaultGateway to default true")
	}
	if cfg.RateLimit.Threshold != 5 || cfg.RateLimit.BackoffBase.Std() != time.Second ||
		cfg.RateLimit.BackoffMax.Std() != 15*time.Minute || cfg.RateLimit.Window.Std() != 24*time.Hour {
		t.Errorf("unexpected rate limit defaults: %+v", cfg.RateLimit)
	}
	if !cfg.AdminUI.Enabled {
		t.Error("expected AdminUI.Enabled to default true")
	}
	if cfg.AdminUI.AdminGroup != "admins" {
		t.Errorf("unexpected admin group default: %q", cfg.AdminUI.AdminGroup)
	}
	if cfg.AdminUI.ConfigEditor.Enabled {
		t.Error("expected ConfigEditor.Enabled to default false")
	}
	if cfg.PasswordPolicy.MinLength != 8 || cfg.PasswordPolicy.MinStrength != 2 {
		t.Errorf("unexpected password policy defaults: %+v", cfg.PasswordPolicy)
	}
	if cfg.TLS.MinVersion != "1.2" {
		t.Errorf("unexpected TLS min version default: %q", cfg.TLS.MinVersion)
	}
	if cfg.SMTP.ImplicitTLS {
		t.Error("expected SMTP ImplicitTLS to default false")
	}
	if cfg.SMTP.Timeout.Std() != 10*time.Second {
		t.Errorf("unexpected SMTP timeout default: %v", cfg.SMTP.Timeout.Std())
	}
	if cfg.SMTP.InsecureSkipVerify {
		t.Error("expected SMTP InsecureSkipVerify to default false")
	}
}

func TestLoadServerConfigFromEnv_Overrides(t *testing.T) {
	t.Setenv(EnvLogLevel, "debug")
	t.Setenv(EnvDatabaseDSN, "postgres://u:p@host/db")
	t.Setenv(EnvDatabaseMaxConns, "25")
	t.Setenv(EnvLDAPSecureListenAddr, "0.0.0.0:636")
	t.Setenv(EnvLDAPAllowAnonymousBind, "true")
	t.Setenv(EnvOIDCIssuer, "https://auth.example.com")
	t.Setenv(EnvNetworkTrustedProxies, "10.0.0.0/8, 192.168.1.0/24")
	t.Setenv(EnvNetworkTrustDefaultGateway, "false")
	t.Setenv(EnvRateLimitThreshold, "10")
	t.Setenv(EnvAdminUIEnabled, "false")
	t.Setenv(EnvSMTPPassword, "s3cret")
	t.Setenv(EnvSMTPImplicitTLS, "true")
	t.Setenv(EnvSMTPTimeout, "30s")
	t.Setenv(EnvSMTPHeloDomain, "mail.example.com")
	t.Setenv(EnvSMTPInsecureSkipVerify, "true")

	cfg, err := LoadServerConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("expected overridden log level, got %q", cfg.Logging.Level)
	}
	if cfg.Database.DSN != "postgres://u:p@host/db" {
		t.Errorf("unexpected DSN: %q", cfg.Database.DSN)
	}
	if cfg.Database.MaxConns != 25 {
		t.Errorf("unexpected MaxConns: %d", cfg.Database.MaxConns)
	}
	if cfg.LDAP.SecureListenAddr != "0.0.0.0:636" || !cfg.LDAP.AllowAnonymousBind {
		t.Errorf("expected LDAP secure listen addr/anonymous overrides to apply: %+v", cfg.LDAP)
	}
	if cfg.OIDC.Issuer != "https://auth.example.com" {
		t.Errorf("unexpected OIDC issuer: %q", cfg.OIDC.Issuer)
	}
	if want := []string{"10.0.0.0/8", "192.168.1.0/24"}; len(cfg.Network.TrustedProxies) != 2 ||
		cfg.Network.TrustedProxies[0] != want[0] || cfg.Network.TrustedProxies[1] != want[1] {
		t.Errorf("unexpected trusted proxies: %v", cfg.Network.TrustedProxies)
	}
	if cfg.Network.TrustsDefaultGateway() {
		t.Error("expected TrustDefaultGateway=false override to apply")
	}
	if cfg.RateLimit.Threshold != 10 {
		t.Errorf("unexpected rate limit threshold: %d", cfg.RateLimit.Threshold)
	}
	if cfg.AdminUI.Enabled {
		t.Error("expected AdminUI.Enabled=false override to apply")
	}
	if cfg.SMTP.Password != "s3cret" {
		t.Errorf("unexpected SMTP password: %q", cfg.SMTP.Password)
	}
	if !cfg.SMTP.ImplicitTLS {
		t.Error("expected SMTP ImplicitTLS=true override to apply")
	}
	if cfg.SMTP.Timeout.Std() != 30*time.Second {
		t.Errorf("unexpected SMTP timeout: %v", cfg.SMTP.Timeout.Std())
	}
	if cfg.SMTP.HeloDomain != "mail.example.com" {
		t.Errorf("unexpected SMTP HELO domain: %q", cfg.SMTP.HeloDomain)
	}
	if !cfg.SMTP.InsecureSkipVerify {
		t.Error("expected SMTP InsecureSkipVerify=true override to apply")
	}
}

func TestLoadServerConfigFromEnv_OIDCClients(t *testing.T) {
	t.Setenv(EnvOIDCClients, `[{"clientID":"web","redirectURIs":["https://app.example.com/callback"],"public":true}]`)
	cfg, err := LoadServerConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.OIDC.Clients) != 1 {
		t.Fatalf("expected 1 OIDC client, got %d", len(cfg.OIDC.Clients))
	}
	c := cfg.OIDC.Clients[0]
	if c.ClientID != "web" || !c.Public || len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != "https://app.example.com/callback" {
		t.Errorf("unexpected client: %+v", c)
	}
}

func TestLoadServerConfigFromEnv_InvalidValues(t *testing.T) {
	cases := []struct {
		name string
		env  string
		val  string
	}{
		{"bad bool", EnvLDAPAllowAnonymousBind, "not-a-bool"},
		{"bad int", EnvDatabaseMaxConns, "not-a-number"},
		{"bad duration", EnvRateLimitWindow, "not-a-duration"},
		{"bad JSON clients", EnvOIDCClients, "not json"},
		{"bad trust-gateway bool", EnvNetworkTrustDefaultGateway, "maybe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.env, tc.val)
			if _, err := LoadServerConfigFromEnv(); err == nil {
				t.Errorf("expected an error for %s=%q", tc.env, tc.val)
			}
		})
	}
}
