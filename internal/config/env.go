package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment variable names for every ServerConfig field. There is no
// server config FILE -- see .env.example at the repo root for the same
// list with defaults, descriptions, and required/optional status.
const (
	EnvLogLevel  = "DECLARATIVEAUTH_LOG_LEVEL"
	EnvLogFormat = "DECLARATIVEAUTH_LOG_FORMAT"

	EnvDatabaseDSN            = "DECLARATIVEAUTH_DATABASE_DSN"
	EnvDatabaseMaxConns       = "DECLARATIVEAUTH_DATABASE_MAX_CONNS"
	EnvDatabaseConnectTimeout = "DECLARATIVEAUTH_DATABASE_CONNECT_TIMEOUT"

	// EnvLDAPListenAddr and EnvLDAPSecureListenAddr are independent: each
	// listener is only started when its address is set (no default for
	// either), and EnvLDAPSecureListenAddr is always TLS-terminating -- there
	// is no separate "LDAP TLS enabled" variable, setting this address *is*
	// what enables it.
	EnvLDAPListenAddr         = "DECLARATIVEAUTH_LDAP_LISTEN_ADDR"
	EnvLDAPSecureListenAddr   = "DECLARATIVEAUTH_LDAP_SECURE_LISTEN_ADDR"
	EnvLDAPBaseDN             = "DECLARATIVEAUTH_LDAP_BASE_DN"
	EnvLDAPAllowAnonymousBind = "DECLARATIVEAUTH_LDAP_ALLOW_ANONYMOUS_BIND"
	EnvLDAPTLSCertFile        = "DECLARATIVEAUTH_LDAP_TLS_CERT_FILE"
	EnvLDAPTLSKeyFile         = "DECLARATIVEAUTH_LDAP_TLS_KEY_FILE"

	// EnvOIDCListenAddr and EnvOIDCSecureListenAddr are the same independent
	// plaintext/secure split as the LDAP pair above.
	EnvOIDCIssuer           = "DECLARATIVEAUTH_OIDC_ISSUER"
	EnvOIDCListenAddr       = "DECLARATIVEAUTH_OIDC_LISTEN_ADDR"
	EnvOIDCSecureListenAddr = "DECLARATIVEAUTH_OIDC_SECURE_LISTEN_ADDR"
	EnvOIDCTLSCert          = "DECLARATIVEAUTH_OIDC_TLS_CERT_FILE"
	EnvOIDCTLSKey           = "DECLARATIVEAUTH_OIDC_TLS_KEY_FILE"

	EnvSMTPHost               = "DECLARATIVEAUTH_SMTP_HOST"
	EnvSMTPPort               = "DECLARATIVEAUTH_SMTP_PORT"
	EnvSMTPUsername           = "DECLARATIVEAUTH_SMTP_USERNAME"
	EnvSMTPPassword           = "DECLARATIVEAUTH_SMTP_PASSWORD"
	EnvSMTPFrom               = "DECLARATIVEAUTH_SMTP_FROM"
	EnvSMTPHeloDomain         = "DECLARATIVEAUTH_SMTP_HELO_DOMAIN"
	EnvSMTPImplicitTLS        = "DECLARATIVEAUTH_SMTP_IMPLICIT_TLS"
	EnvSMTPTimeout            = "DECLARATIVEAUTH_SMTP_TIMEOUT"
	EnvSMTPInsecureSkipVerify = "DECLARATIVEAUTH_SMTP_INSECURE_SKIP_VERIFY"

	EnvMetricsListenAddr = "DECLARATIVEAUTH_METRICS_LISTEN_ADDR"

	EnvIdentityPath           = "DECLARATIVEAUTH_IDENTITY_PATH"
	EnvIdentityReloadDebounce = "DECLARATIVEAUTH_IDENTITY_RELOAD_DEBOUNCE"

	EnvNetworkTrustedProxies      = "DECLARATIVEAUTH_NETWORK_TRUSTED_PROXIES"
	EnvNetworkTrustDefaultGateway = "DECLARATIVEAUTH_NETWORK_TRUST_DEFAULT_GATEWAY"

	EnvRateLimitThreshold   = "DECLARATIVEAUTH_RATE_LIMIT_THRESHOLD"
	EnvRateLimitBackoffBase = "DECLARATIVEAUTH_RATE_LIMIT_BACKOFF_BASE"
	EnvRateLimitBackoffMax  = "DECLARATIVEAUTH_RATE_LIMIT_BACKOFF_MAX"
	EnvRateLimitWindow      = "DECLARATIVEAUTH_RATE_LIMIT_WINDOW"

	EnvRateLimitIPThreshold   = "DECLARATIVEAUTH_RATE_LIMIT_IP_THRESHOLD"
	EnvRateLimitIPBackoffBase = "DECLARATIVEAUTH_RATE_LIMIT_IP_BACKOFF_BASE"
	EnvRateLimitIPBackoffMax  = "DECLARATIVEAUTH_RATE_LIMIT_IP_BACKOFF_MAX"
	EnvRateLimitIPWindow      = "DECLARATIVEAUTH_RATE_LIMIT_IP_WINDOW"

	EnvAdminUIEnabled             = "DECLARATIVEAUTH_ADMIN_UI_ENABLED"
	EnvAdminUIAdminGroup          = "DECLARATIVEAUTH_ADMIN_UI_ADMIN_GROUP"
	EnvAdminUIConfigEditorEnabled = "DECLARATIVEAUTH_ADMIN_UI_CONFIG_EDITOR_ENABLED"

	EnvTLSCertFile   = "DECLARATIVEAUTH_TLS_CERT_FILE"
	EnvTLSKeyFile    = "DECLARATIVEAUTH_TLS_KEY_FILE"
	EnvTLSMinVersion = "DECLARATIVEAUTH_TLS_MIN_VERSION"

	EnvPasswordPolicyMinLength   = "DECLARATIVEAUTH_PASSWORD_POLICY_MIN_LENGTH"
	EnvPasswordPolicyMinStrength = "DECLARATIVEAUTH_PASSWORD_POLICY_MIN_STRENGTH"

	// EnvWebAuthnEnabled turns passkey registration/login on or off. Defaults
	// to true: WebAuthn requires a secure context (HTTPS or localhost)
	// enforced by the browser itself, and RPID/RPOrigins fall back to the
	// OIDC issuer when unset, so this works out of the box for the common
	// case rather than needing extra opt-in configuration.
	EnvWebAuthnEnabled = "DECLARATIVEAUTH_WEBAUTHN_ENABLED"
	// EnvWebAuthnRPID is the WebAuthn Relying Party ID -- the effective
	// domain passkeys are scoped to (e.g. "auth.example.com", no scheme or
	// port). Defaults to the hostname of DECLARATIVEAUTH_OIDC_ISSUER.
	EnvWebAuthnRPID = "DECLARATIVEAUTH_WEBAUTHN_RP_ID"
	// EnvWebAuthnRPOrigins is a comma-separated list of fully qualified
	// origins (scheme + host + optional port) permitted to complete a
	// WebAuthn ceremony. Defaults to [DECLARATIVEAUTH_OIDC_ISSUER].
	EnvWebAuthnRPOrigins = "DECLARATIVEAUTH_WEBAUTHN_RP_ORIGINS"
	// EnvWebAuthnRPDisplayName is the human-readable Relying Party name
	// shown by the browser/OS passkey UI during registration.
	EnvWebAuthnRPDisplayName = "DECLARATIVEAUTH_WEBAUTHN_RP_DISPLAY_NAME"
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
			ListenAddr:       os.Getenv(EnvLDAPListenAddr),
			SecureListenAddr: os.Getenv(EnvLDAPSecureListenAddr),
			BaseDN:           os.Getenv(EnvLDAPBaseDN),
			TLS: TLSListenerConfig{
				CertFile: os.Getenv(EnvLDAPTLSCertFile),
				KeyFile:  os.Getenv(EnvLDAPTLSKeyFile),
			},
		},
		OIDC: OIDCConfig{
			Issuer:           os.Getenv(EnvOIDCIssuer),
			ListenAddr:       os.Getenv(EnvOIDCListenAddr),
			SecureListenAddr: os.Getenv(EnvOIDCSecureListenAddr),
			TLS: TLSListenerConfig{
				CertFile: os.Getenv(EnvOIDCTLSCert),
				KeyFile:  os.Getenv(EnvOIDCTLSKey),
			},
		},
		SMTP: SMTPConfig{
			Host:       os.Getenv(EnvSMTPHost),
			Username:   os.Getenv(EnvSMTPUsername),
			Password:   os.Getenv(EnvSMTPPassword),
			From:       os.Getenv(EnvSMTPFrom),
			HeloDomain: os.Getenv(EnvSMTPHeloDomain),
		},
		Metrics: MetricsConfig{
			// No default: unset means metrics are disabled entirely (see
			// EnvMetricsListenAddr).
			ListenAddr: os.Getenv(EnvMetricsListenAddr),
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
	if cfg.SMTP.Port, err = getenvInt(EnvSMTPPort, 0); err != nil {
		return nil, err
	}
	if cfg.SMTP.ImplicitTLS, err = getenvBool(EnvSMTPImplicitTLS, false); err != nil {
		return nil, err
	}
	if cfg.SMTP.Timeout, err = getenvDuration(EnvSMTPTimeout, 10*time.Second); err != nil {
		return nil, err
	}
	if cfg.SMTP.InsecureSkipVerify, err = getenvBool(EnvSMTPInsecureSkipVerify, false); err != nil {
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
	// Disabled (0) by default: a hard lockout -- account or IP -- is itself
	// a denial-of-service lever for anyone who knows a target's username,
	// or shares a NAT/VPN/CGNAT egress IP with an attacker. Operators who
	// want it can opt in; see the DoS tradeoff noted in .env.example.
	if cfg.RateLimit.Threshold, err = getenvInt(EnvRateLimitThreshold, 0); err != nil {
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
	// Independent from the account dimension above: its own threshold
	// (disabled by default, same reasoning), its own backoff/window. A
	// deployment can run one dimension, both, or neither.
	if cfg.RateLimit.IPThreshold, err = getenvInt(EnvRateLimitIPThreshold, 0); err != nil {
		return nil, err
	}
	if cfg.RateLimit.IPBackoffBase, err = getenvDuration(EnvRateLimitIPBackoffBase, time.Second); err != nil {
		return nil, err
	}
	if cfg.RateLimit.IPBackoffMax, err = getenvDuration(EnvRateLimitIPBackoffMax, 15*time.Minute); err != nil {
		return nil, err
	}
	if cfg.RateLimit.IPWindow, err = getenvDuration(EnvRateLimitIPWindow, 24*time.Hour); err != nil {
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

	if cfg.WebAuthn.Enabled, err = getenvBool(EnvWebAuthnEnabled, true); err != nil {
		return nil, err
	}
	cfg.WebAuthn.RPDisplayName = getenv(EnvWebAuthnRPDisplayName, "DeclarativeAuth")
	cfg.WebAuthn.RPID = os.Getenv(EnvWebAuthnRPID)
	cfg.WebAuthn.RPOrigins = getenvCSV(EnvWebAuthnRPOrigins)
	if cfg.WebAuthn.RPID == "" || len(cfg.WebAuthn.RPOrigins) == 0 {
		if issuerURL, perr := url.Parse(cfg.OIDC.Issuer); perr == nil && issuerURL.Hostname() != "" {
			if cfg.WebAuthn.RPID == "" {
				cfg.WebAuthn.RPID = issuerURL.Hostname()
			}
			if len(cfg.WebAuthn.RPOrigins) == 0 {
				cfg.WebAuthn.RPOrigins = []string{issuerURL.Scheme + "://" + issuerURL.Host}
			}
		}
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
