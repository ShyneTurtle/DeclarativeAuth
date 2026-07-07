// Package config loads, validates, and hot-reloads the declarative
// users/groups identity files, and builds the server's own runtime
// configuration from environment variables (see env.go).
package config

// GroupFile is the on-disk shape of groups.yaml.
type GroupFile struct {
	APIVersion string      `json:"apiVersion"`
	Kind       string      `json:"kind"`
	Groups     []GroupSpec `json:"groups"`
}

// GroupSpec is a single declared group.
type GroupSpec struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	MemberOfGroups []string `json:"memberOfGroups"`
	// RequireMFA, when true, requires every member of this group (direct or
	// transitive) to complete email-based MFA at login.
	RequireMFA bool `json:"requireMFA"`
}

// UserFile is the on-disk shape of users.yaml.
type UserFile struct {
	APIVersion string     `json:"apiVersion"`
	Kind       string     `json:"kind"`
	Users      []UserSpec `json:"users"`
}

// UserSpec is a single declared user. No password/secret field exists here
// by design — credentials live in Postgres, never in the declarative files.
type UserSpec struct {
	Username       string   `json:"username"`
	Email          string   `json:"email"`
	FirstName      string   `json:"firstName"`
	Name           string   `json:"name"`
	DisplayName    string   `json:"displayName"`
	Enabled        *bool    `json:"enabled"`
	MemberOfGroups []string `json:"memberOfGroups"`
	// MFAEnabled declaratively forces email-based MFA on for this user,
	// regardless of group membership. Unlike Enabled, this has no "unset"
	// tri-state: it defaults to false (not individually required), and
	// group-level RequireMFA or the user's own self-service opt-in
	// (managed from their profile page, not here) can still require it.
	MFAEnabled bool `json:"mfaEnabled"`
}

// ServerConfig is the server's runtime configuration: listeners, database,
// SMTP, rate limiting, TLS, admin UI. It's built entirely from environment
// variables by LoadServerConfigFromEnv (see env.go for the full list of
// variable names and defaults) -- there is no server config file.
//
// This is a separate, deliberately different kind of input from the
// declarative identity (users.yaml/groups.yaml, see GroupFile/UserFile
// above): identity is "who exists", checked into a repo and hot-reloaded;
// this is "how the process runs", set once at process start like any
// 12-factor app.
//
// The Argon2id HMAC pepper is deliberately not a field here: it's always
// read from the fixed auth.PepperEnvVar environment variable, never from a
// configurable-name field, so there's exactly one place to look for it.
type ServerConfig struct {
	Logging        LoggingConfig
	Database       DatabaseConfig
	LDAP           LDAPConfig
	OIDC           OIDCConfig
	SMTP           SMTPConfig
	Metrics        MetricsConfig
	Identity       IdentityConfig
	Network        NetworkConfig
	RateLimit      RateLimitConfig
	AdminUI        AdminUIConfig
	TLS            TLSConfig
	PasswordPolicy PasswordPolicyConfig
	WebAuthn       WebAuthnConfig
}

type LoggingConfig struct {
	Level  string
	Format string
}

type DatabaseConfig struct {
	DSN            string
	MaxConns       int32
	ConnectTimeout Duration
}

type LDAPConfig struct {
	ListenAddr         string
	BaseDN             string
	TLS                TLSListenerConfig
	AllowAnonymousBind bool
}

type OIDCConfig struct {
	Issuer     string
	ListenAddr string
	TLS        TLSListenerConfig
	Clients    []OIDCClient
}

// OIDCClient is a statically declared OIDC relying party. There is no
// dynamic client registration in v1 (no admin UI for it). The full list is
// configured as one JSON-array environment variable (EnvOIDCClients),
// since a list of objects doesn't map cleanly onto individual scalar env
// vars.
type OIDCClient struct {
	ClientID     string   `json:"clientID"`
	RedirectURIs []string `json:"redirectURIs"`
	Public       bool     `json:"public"`
	ClientSecret string   `json:"clientSecret"`
}

type TLSConfig struct {
	CertFile   string
	KeyFile    string
	MinVersion string
}

type TLSListenerConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
}

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// HeloDomain is the domain sent in the SMTP HELO/EHLO greeting.
	// Defaults to "localhost" if unset (see mail.Config.HeloDomain) --
	// override with a real domain you control when relaying through a
	// listener that validates it (e.g. against SPF).
	HeloDomain string
	// ImplicitTLS, when true, wraps the connection in TLS before any SMTP
	// dialogue (the "SMTPS" scheme, conventionally port 465), instead of
	// connecting in plaintext and opportunistically upgrading via STARTTLS
	// (port 587/25). These are mutually exclusive on the wire: pointing this
	// client at an implicit-TLS-only listener without setting this would
	// otherwise hang forever, each side waiting for the other to speak first
	// in the protocol it expects (fixed connection-wide Timeout below bounds
	// that either way).
	ImplicitTLS bool
	// Timeout bounds the whole SMTP exchange (connect, optional TLS
	// handshake, AUTH, DATA) via a single deadline set right after
	// connecting, not just the initial dial -- a plain dial timeout wouldn't
	// catch a protocol-level hang like ImplicitTLS mismatched against the
	// server. Defaults to 10s (see EnvSMTPTimeout) if zero.
	Timeout Duration
	// InsecureSkipVerify disables TLS certificate verification for the SMTP
	// connection (ImplicitTLS and STARTTLS alike). Only for relays with a
	// self-signed or otherwise unverifiable cert you can't fix the trust
	// store for -- it makes the connection vulnerable to MITM.
	InsecureSkipVerify bool
}

type MetricsConfig struct {
	ListenAddr string
}

// IdentityConfig points at the declarative identity directory -- the one
// piece of YAML this project still reads. See EnvIdentityPath.
type IdentityConfig struct {
	IdentityPath   string
	ReloadDebounce Duration
}

type NetworkConfig struct {
	TrustedProxies []string
	// TrustDefaultGateway, when true (the default), additionally trusts the
	// process's own default gateway (e.g. the Docker bridge gateway) for
	// X-Forwarded-* headers, on top of anything listed in TrustedProxies.
	// This is what makes forwarded headers work out of the box for the
	// common "reverse proxy runs on the Docker host / a sidecar, talking to
	// the container through its bridge gateway" deployment shape, without
	// requiring an operator to hardcode a Docker-assigned CIDR that can
	// differ per host or restart. Set to false to disable and rely solely
	// on TrustedProxies.
	TrustDefaultGateway *bool
}

// TrustsDefaultGateway reports whether the default gateway should be
// trusted, defaulting to true when unset.
func (c NetworkConfig) TrustsDefaultGateway() bool {
	return c.TrustDefaultGateway == nil || *c.TrustDefaultGateway
}

type RateLimitConfig struct {
	Threshold   int
	BackoffBase Duration
	BackoffMax  Duration
	Window      Duration
}

type AdminUIConfig struct {
	Enabled      bool
	ConfigEditor ConfigEditorConfig
	AdminGroup   string
}

type ConfigEditorConfig struct {
	Enabled bool
}

// PasswordPolicyConfig sets the minimum requirements enforced when a user
// sets their password (password reset / first-password setup). See
// auth.PasswordPolicy, which this is converted to.
type PasswordPolicyConfig struct {
	MinLength   int
	MinStrength int
}

// WebAuthnConfig configures passkey (WebAuthn) registration and login. RPID
// and RPOrigins default to the OIDC issuer's host/origin when unset (see
// LoadServerConfigFromEnv), since that's the domain users actually log in
// against; they only need to be set explicitly when passkeys should be
// scoped to a different (e.g. broader parent) domain than the issuer.
type WebAuthnConfig struct {
	Enabled       bool
	RPID          string
	RPOrigins     []string
	RPDisplayName string
}
