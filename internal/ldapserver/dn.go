// Package ldapserver is a minimal LDAPv3 server exposing Bind and Search
// only (identity is read-only and declarative; no Add/Modify/Delete). It
// presents users' flattened group membership so downstream LDAP filters
// don't need to understand nested groups.
package ldapserver

import (
	"fmt"
	"strings"
)

// Config holds the LDAP server's addressing/schema settings.
type Config struct {
	BaseDN             string
	AllowAnonymousBind bool
}

// UserDN returns the canonical DN for a username: uid=<username>,ou=users,<baseDN>.
func UserDN(baseDN, username string) string {
	return fmt.Sprintf("uid=%s,ou=users,%s", username, baseDN)
}

// GroupDN returns the canonical DN for a group: cn=<name>,ou=groups,<baseDN>.
func GroupDN(baseDN, name string) string {
	return fmt.Sprintf("cn=%s,ou=groups,%s", name, baseDN)
}

// UsernameFromBindDN extracts a username from either a full user DN or a
// bare username supplied as the bind DN (accepted as a simplification).
func UsernameFromBindDN(baseDN, dn string) (string, bool) {
	if dn == "" {
		return "", false
	}
	suffix := ",ou=users," + baseDN
	if strings.HasSuffix(dn, suffix) && strings.HasPrefix(dn, "uid=") {
		return dn[len("uid=") : len(dn)-len(suffix)], true
	}
	if !strings.Contains(dn, "=") {
		return dn, true
	}
	return "", false
}

// GroupNameFromDN extracts a group name from a group DN, e.g.
// "cn=engineering,ou=groups,dc=example,dc=com" -> "engineering".
func GroupNameFromDN(baseDN, dn string) (string, bool) {
	suffix := ",ou=groups," + baseDN
	if strings.HasSuffix(dn, suffix) && strings.HasPrefix(dn, "cn=") {
		return dn[len("cn=") : len(dn)-len(suffix)], true
	}
	return "", false
}
