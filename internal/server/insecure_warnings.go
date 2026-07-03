package server

import (
	"log/slog"

	"declarativeauth/internal/config"
)

// warnInsecureConfig logs a WARN line for every configuration choice that
// could silently expose credentials or identity data, so an operator who
// didn't intend it finds out from the logs at startup rather than from an
// incident later. None of these block startup -- some (e.g. TLS-disabled
// listeners behind a reverse proxy that terminates TLS itself) are
// legitimate, so this can only warn, not know for certain something is
// wrong. See also the client-side guard, internal/web/static/secure-guard.js,
// which refuses to submit a password over a page that isn't a secure
// context.
func warnInsecureConfig(cfg *config.ServerConfig, logger *slog.Logger) {
	if !cfg.OIDC.TLS.Enabled {
		logger.Warn(config.EnvOIDCTLSEnabled+" is false: web login, password reset, and admin traffic (including passwords) will be sent in plaintext unless a TLS-terminating reverse proxy sits in front of this listener",
			"component", "startup", "listener", "oidc")
	}
	if !cfg.LDAP.TLS.Enabled {
		logger.Warn(config.EnvLDAPTLSEnabled+" is false: LDAP bind credentials will be sent in plaintext unless a TLS-terminating reverse proxy/stunnel sits in front of this listener",
			"component", "startup", "listener", "ldap")
	}
	if cfg.LDAP.AllowAnonymousBind {
		logger.Warn(config.EnvLDAPAllowAnonymousBind+" is true: unauthenticated clients can query LDAP search (including flattened group membership) without presenting any credentials",
			"component", "startup")
	}
	if cfg.PasswordPolicy.MinLength > 0 && cfg.PasswordPolicy.MinLength < 8 {
		logger.Warn(config.EnvPasswordPolicyMinLength+" is set below the recommended minimum of 8",
			"component", "startup", "minLength", cfg.PasswordPolicy.MinLength)
	}
	if cfg.PasswordPolicy.MinStrength > 0 && cfg.PasswordPolicy.MinStrength < 2 {
		logger.Warn(config.EnvPasswordPolicyMinStrength+" is set below the recommended minimum of 2 (\"fair\"): users will be able to set trivially guessable passwords",
			"component", "startup", "minStrength", cfg.PasswordPolicy.MinStrength)
	}
	if cfg.AdminUI.Enabled && cfg.AdminUI.ConfigEditor.Enabled && !cfg.OIDC.TLS.Enabled {
		logger.Warn(config.EnvAdminUIConfigEditorEnabled+" is true while "+config.EnvOIDCTLSEnabled+" is false: an admin session cookie and the declarative identity files it can rewrite are both exposed to anyone on the network path, absent a TLS-terminating reverse proxy",
			"component", "startup")
	}
}
