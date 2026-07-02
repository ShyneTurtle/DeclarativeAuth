// Package config loads, validates, and hot-reloads the declarative
// users/groups identity files and the server's own runtime configuration.
package config

import "time"

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
}

// ServerConfig is the parsed shape of declarativeauth.yaml.
//
// The Argon2id HMAC pepper is deliberately not a field here: it's always
// read from the fixed auth.PepperEnvVar environment variable, never from a
// configurable-name field, so there's exactly one place to look for it.
type ServerConfig struct {
	Logging        LoggingConfig        `json:"logging"`
	Database       DatabaseConfig       `json:"database"`
	LDAP           LDAPConfig           `json:"ldap"`
	OIDC           OIDCConfig           `json:"oidc"`
	SMTP           SMTPConfig           `json:"smtp"`
	Metrics        MetricsConfig        `json:"metrics"`
	Config         IdentityConfig       `json:"config"`
	Network        NetworkConfig        `json:"network"`
	RateLimit      RateLimitConfig      `json:"rateLimit"`
	AdminUI        AdminUIConfig        `json:"adminUI"`
	TLS            TLSConfig            `json:"tls"`
	PasswordPolicy PasswordPolicyConfig `json:"passwordPolicy"`
}

type LoggingConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

type DatabaseConfig struct {
	DSN            string   `json:"dsn"`
	MaxConns       int32    `json:"maxConns"`
	ConnectTimeout Duration `json:"connectTimeout"`
}

type LDAPConfig struct {
	ListenAddr         string            `json:"listenAddr"`
	BaseDN             string            `json:"baseDN"`
	TLS                TLSListenerConfig `json:"tls"`
	ProxyProtocol      bool              `json:"proxyProtocol"`
	AllowAnonymousBind bool              `json:"allowAnonymousBind"`
}

type OIDCConfig struct {
	Issuer     string            `json:"issuer"`
	ListenAddr string            `json:"listenAddr"`
	TLS        TLSListenerConfig `json:"tls"`
	Clients    []OIDCClient      `json:"clients"`
}

// OIDCClient is a statically declared OIDC relying party. There is no
// dynamic client registration in v1 (no admin UI for it).
type OIDCClient struct {
	ClientID     string   `json:"clientID"`
	RedirectURIs []string `json:"redirectURIs"`
	Public       bool     `json:"public"`
	ClientSecret string   `json:"clientSecret"`
}

type TLSConfig struct {
	CertFile   string `json:"certFile"`
	KeyFile    string `json:"keyFile"`
	MinVersion string `json:"minVersion"`
}

type TLSListenerConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

type SMTPConfig struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	PasswordEnv string `json:"passwordEnv"`
	From        string `json:"from"`
}

type MetricsConfig struct {
	ListenAddr string `json:"listenAddr"`
}

type IdentityConfig struct {
	IdentityPath   string   `json:"identityPath"`
	ReloadDebounce Duration `json:"reloadDebounce"`
}

type NetworkConfig struct {
	TrustedProxies []string `json:"trustedProxies"`
	// TrustDefaultGateway, when true (the default), additionally trusts the
	// process's own default gateway (e.g. the Docker bridge gateway) for
	// X-Forwarded-* headers, on top of anything listed in TrustedProxies.
	// This is what makes forwarded headers work out of the box for the
	// common "reverse proxy runs on the Docker host / a sidecar, talking to
	// the container through its bridge gateway" deployment shape, without
	// requiring an operator to hardcode a Docker-assigned CIDR that can
	// differ per host or restart. Set to false to disable and rely solely
	// on TrustedProxies.
	TrustDefaultGateway *bool `json:"trustDefaultGateway"`
}

// TrustsDefaultGateway reports whether the default gateway should be
// trusted, defaulting to true when unset.
func (c NetworkConfig) TrustsDefaultGateway() bool {
	return c.TrustDefaultGateway == nil || *c.TrustDefaultGateway
}

type RateLimitConfig struct {
	Threshold   int      `json:"threshold"`
	BackoffBase Duration `json:"backoffBase"`
	BackoffMax  Duration `json:"backoffMax"`
	Window      Duration `json:"window"`
}

type AdminUIConfig struct {
	Enabled      bool               `json:"enabled"`
	ConfigEditor ConfigEditorConfig `json:"configEditor"`
	AdminGroup   string             `json:"adminGroup"`
}

type ConfigEditorConfig struct {
	Enabled bool `json:"enabled"`
}

// PasswordPolicyConfig sets the minimum requirements enforced when a user
// sets their password (password reset / first-password setup). 0 for
// either field falls back to its documented default -- see
// auth.PasswordPolicy, which this is converted to.
type PasswordPolicyConfig struct {
	MinLength   int `json:"minLength"`
	MinStrength int `json:"minStrength"`
}

// Defaults applies documented default values for any unset fields.
func (c *ServerConfig) Defaults() {
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.Database.MaxConns == 0 {
		c.Database.MaxConns = 10
	}
	if c.Database.ConnectTimeout == 0 {
		c.Database.ConnectTimeout = Duration(5 * time.Second)
	}
	if c.Config.ReloadDebounce == 0 {
		c.Config.ReloadDebounce = Duration(500 * time.Millisecond)
	}
	if c.RateLimit.Threshold == 0 {
		c.RateLimit.Threshold = 5
	}
	if c.RateLimit.BackoffBase == 0 {
		c.RateLimit.BackoffBase = Duration(time.Second)
	}
	if c.RateLimit.BackoffMax == 0 {
		c.RateLimit.BackoffMax = Duration(15 * time.Minute)
	}
	if c.RateLimit.Window == 0 {
		c.RateLimit.Window = Duration(24 * time.Hour)
	}
	if c.AdminUI.AdminGroup == "" {
		c.AdminUI.AdminGroup = "admins"
	}
	if c.LDAP.BaseDN == "" {
		c.LDAP.BaseDN = "dc=example,dc=com"
	}
	if c.PasswordPolicy.MinLength == 0 {
		c.PasswordPolicy.MinLength = 8
	}
	if c.PasswordPolicy.MinStrength == 0 {
		c.PasswordPolicy.MinStrength = 2
	}
}
