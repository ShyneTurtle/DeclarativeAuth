package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment variable names for every ServerConfig field. There is no
// server config FILE -- see .env.example at the repo root for the same
// list with defaults, descriptions, and required/optional status.
//
// The Argon2id pepper is deliberately not among these: it's always read
// from the fixed auth.PepperEnvVar, never from a configurable-name field.
const (
	EnvLogLevel  = "DECLARATIVEAUTH_LOG_LEVEL"
	EnvLogFormat = "DECLARATIVEAUTH_LOG_FORMAT"

	EnvDatabaseDSN            = "DECLARATIVEAUTH_DATABASE_DSN"
	EnvDatabaseMaxConns       = "DECLARATIVEAUTH_DATABASE_MAX_CONNS"
	EnvDatabaseConnectTimeout = "DECLARATIVEAUTH_DATABASE_CONNECT_TIMEOUT"

	EnvLDAPListenAddr         = "DECLARATIVEAUTH_LDAP_LISTEN_ADDR"
	EnvLDAPBaseDN             = "DECLARATIVEAUTH_LDAP_BASE_DN"
	EnvLDAPAllowAnonymousBind = "DECLARATIVEAUTH_LDAP_ALLOW_ANONYMOUS_BIND"
	EnvLDAPTLSEnabled         = "DECLARATIVEAUTH_LDAP_TLS_ENABLED"
	EnvLDAPTLSCertFile        = "DECLARATIVEAUTH_LDAP_TLS_CERT_FILE"
	EnvLDAPTLSKeyFile         = "DECLARATIVEAUTH_LDAP_TLS_KEY_FILE"

	EnvOIDCIssuer     = "DECLARATIVEAUTH_OIDC_ISSUER"
	EnvOIDCListenAddr = "DECLARATIVEAUTH_OIDC_LISTEN_ADDR"
	EnvOIDCTLSEnabled = "DECLARATIVEAUTH_OIDC_TLS_ENABLED"
	EnvOIDCTLSCert    = "DECLARATIVEAUTH_OIDC_TLS_CERT_FILE"
	EnvOIDCTLSKey     = "DECLARATIVEAUTH_OIDC_TLS_KEY_FILE"
	// EnvOIDCClients holds a JSON array of {clientID, redirectURIs, public,
	// clientSecret} objects -- the one field that doesn't map cleanly to a
	// single scalar env var. e.g.:
	//   [{"clientID":"example-client","redirectURIs":["http://localhost:9000/callback"],"public":true}]
	EnvOIDCClients = "DECLARATIVEAUTH_OIDC_CLIENTS"

	EnvSMTPHost     = "DECLARATIVEAUTH_SMTP_HOST"
	EnvSMTPPort     = "DECLARATIVEAUTH_SMTP_PORT"
	EnvSMTPUsername = "DECLARATIVEAUTH_SMTP_USERNAME"
	EnvSMTPPassword = "DECLARATIVEAUTH_SMTP_PASSWORD"
	EnvSMTPFrom     = "DECLARATIVEAUTH_SMTP_FROM"

	EnvMetricsListenAddr = "DECLARATIVEAUTH_METRICS_LISTEN_ADDR"

	EnvIdentityPath           = "DECLARATIVEAUTH_IDENTITY_PATH"
	EnvIdentityReloadDebounce = "DECLARATIVEAUTH_IDENTITY_RELOAD_DEBOUNCE"

	EnvNetworkTrustedProxies      = "DECLARATIVEAUTH_NETWORK_TRUSTED_PROXIES"
	EnvNetworkTrustDefaultGateway = "DECLARATIVEAUTH_NETWORK_TRUST_DEFAULT_GATEWAY"

	EnvRateLimitThreshold   = "DECLARATIVEAUTH_RATE_LIMIT_THRESHOLD"
	EnvRateLimitBackoffBase = "DECLARATIVEAUTH_RATE_LIMIT_BACKOFF_BASE"
	EnvRateLimitBackoffMax  = "DECLARATIVEAUTH_RATE_LIMIT_BACKOFF_MAX"
	EnvRateLimitWindow      = "DECLARATIVEAUTH_RATE_LIMIT_WINDOW"

	EnvAdminUIEnabled             = "DECLARATIVEAUTH_ADMIN_UI_ENABLED"
	EnvAdminUIAdminGroup          = "DECLARATIVEAUTH_ADMIN_UI_ADMIN_GROUP"
	EnvAdminUIConfigEditorEnabled = "DECLARATIVEAUTH_ADMIN_UI_CONFIG_EDITOR_ENABLED"

	EnvTLSCertFile   = "DECLARATIVEAUTH_TLS_CERT_FILE"
	EnvTLSKeyFile    = "DECLARATIVEAUTH_TLS_KEY_FILE"
	EnvTLSMinVersion = "DECLARATIVEAUTH_TLS_MIN_VERSION"

	EnvPasswordPolicyMinLength   = "DECLARATIVEAUTH_PASSWORD_POLICY_MIN_LENGTH"
	EnvPasswordPolicyMinStrength = "DECLARATIVEAUTH_PASSWORD_POLICY_MIN_STRENGTH"
)

// LoadServerConfigFromEnv builds the server's runtime configuration purely
// from environment variables (12-factor style) -- see .env.example at the
// repo root for the full list with defaults and descriptions. The only
// YAML this project reads is the declarative identity
// (users.yaml/groups.yaml, at EnvIdentityPath), which is a deliberately
// different kind of input: who exists, not how the server runs.
func LoadServerConfigFromEnv() (*ServerConfig, error) {
	cfg := &ServerConfig{
		Logging: LoggingConfig{
			Level:  getenv(EnvLogLevel, "info"),
			Format: getenv(EnvLogFormat, "json"),
		},
		Database: DatabaseConfig{
			DSN: os.Getenv(EnvDatabaseDSN),
		},
		LDAP: LDAPConfig{
			ListenAddr: getenv(EnvLDAPListenAddr, "0.0.0.0:389"),
			BaseDN:     getenv(EnvLDAPBaseDN, "dc=example,dc=com"),
			TLS: TLSListenerConfig{
				CertFile: os.Getenv(EnvLDAPTLSCertFile),
				KeyFile:  os.Getenv(EnvLDAPTLSKeyFile),
			},
		},
		OIDC: OIDCConfig{
			Issuer:     os.Getenv(EnvOIDCIssuer),
			ListenAddr: getenv(EnvOIDCListenAddr, "0.0.0.0:8080"),
			TLS: TLSListenerConfig{
				CertFile: os.Getenv(EnvOIDCTLSCert),
				KeyFile:  os.Getenv(EnvOIDCTLSKey),
			},
		},
		SMTP: SMTPConfig{
			Host:     os.Getenv(EnvSMTPHost),
			Username: os.Getenv(EnvSMTPUsername),
			Password: os.Getenv(EnvSMTPPassword),
			From:     os.Getenv(EnvSMTPFrom),
		},
		Metrics: MetricsConfig{
			ListenAddr: getenv(EnvMetricsListenAddr, "0.0.0.0:9090"),
		},
		Identity: IdentityConfig{
			IdentityPath: getenv(EnvIdentityPath, "/etc/declarativeauth/identity"),
		},
		Network: NetworkConfig{
			TrustedProxies: getenvCSV(EnvNetworkTrustedProxies),
		},
		AdminUI: AdminUIConfig{
			AdminGroup: getenv(EnvAdminUIAdminGroup, "admins"),
		},
		TLS: TLSConfig{
			CertFile:   os.Getenv(EnvTLSCertFile),
			KeyFile:    os.Getenv(EnvTLSKeyFile),
			MinVersion: getenv(EnvTLSMinVersion, "1.2"),
		},
	}

	var err error
	if cfg.Database.MaxConns, err = getenvInt32(EnvDatabaseMaxConns, 10); err != nil {
		return nil, err
	}
	if cfg.Database.ConnectTimeout, err = getenvDuration(EnvDatabaseConnectTimeout, 5*time.Second); err != nil {
		return nil, err
	}
	if cfg.LDAP.AllowAnonymousBind, err = getenvBool(EnvLDAPAllowAnonymousBind, false); err != nil {
		return nil, err
	}
	if cfg.LDAP.TLS.Enabled, err = getenvBool(EnvLDAPTLSEnabled, false); err != nil {
		return nil, err
	}
	if cfg.OIDC.TLS.Enabled, err = getenvBool(EnvOIDCTLSEnabled, false); err != nil {
		return nil, err
	}
	if v := os.Getenv(EnvOIDCClients); v != "" {
		if err := json.Unmarshal([]byte(v), &cfg.OIDC.Clients); err != nil {
			return nil, fmt.Errorf("%s: invalid JSON: %w", EnvOIDCClients, err)
		}
	}
	if cfg.SMTP.Port, err = getenvInt(EnvSMTPPort, 0); err != nil {
		return nil, err
	}
	if cfg.Identity.ReloadDebounce, err = getenvDuration(EnvIdentityReloadDebounce, 500*time.Millisecond); err != nil {
		return nil, err
	}
	if v, ok := os.LookupEnv(EnvNetworkTrustDefaultGateway); ok && v != "" {
		b, perr := strconv.ParseBool(v)
		if perr != nil {
			return nil, fmt.Errorf("%s: invalid boolean %q", EnvNetworkTrustDefaultGateway, v)
		}
		cfg.Network.TrustDefaultGateway = &b
	}
	if cfg.RateLimit.Threshold, err = getenvInt(EnvRateLimitThreshold, 5); err != nil {
		return nil, err
	}
	if cfg.RateLimit.BackoffBase, err = getenvDuration(EnvRateLimitBackoffBase, time.Second); err != nil {
		return nil, err
	}
	if cfg.RateLimit.BackoffMax, err = getenvDuration(EnvRateLimitBackoffMax, 15*time.Minute); err != nil {
		return nil, err
	}
	if cfg.RateLimit.Window, err = getenvDuration(EnvRateLimitWindow, 24*time.Hour); err != nil {
		return nil, err
	}
	if cfg.AdminUI.Enabled, err = getenvBool(EnvAdminUIEnabled, true); err != nil {
		return nil, err
	}
	if cfg.AdminUI.ConfigEditor.Enabled, err = getenvBool(EnvAdminUIConfigEditorEnabled, false); err != nil {
		return nil, err
	}
	if cfg.PasswordPolicy.MinLength, err = getenvInt(EnvPasswordPolicyMinLength, 8); err != nil {
		return nil, err
	}
	if cfg.PasswordPolicy.MinStrength, err = getenvInt(EnvPasswordPolicyMinStrength, 2); err != nil {
		return nil, err
	}

	return cfg, nil
}

func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func getenvBool(key string, fallback bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: invalid boolean %q", key, v)
	}
	return b, nil
}

func getenvInt(key string, fallback int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid integer %q", key, v)
	}
	return n, nil
}

func getenvInt32(key string, fallback int32) (int32, error) {
	n, err := getenvInt(key, int(fallback))
	return int32(n), err
}

func getenvDuration(key string, fallback time.Duration) (Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return Duration(fallback), nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid duration %q: %w", key, v, err)
	}
	return Duration(d), nil
}

func getenvCSV(key string) []string {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
