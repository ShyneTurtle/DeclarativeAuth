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
	// RequireTLS rejects Bind and Search (the RootDSE probe excepted --
	// clients need it pre-TLS to discover StartTLS support in the first
	// place) over a connection that isn't TLS, whether that's the secure
	// listener or the plaintext listener after a successful StartTLS. It
	// does not disable the plaintext listener itself.
	RequireTLS bool
	// SambaReadersGroup, SambaDomainSID, SambaDomainName: empty
	// SambaReadersGroup (the default) disables Samba integration entirely.
	// See config.EnvLDAPSambaReadersGroup and friends.
	SambaReadersGroup string
	SambaDomainSID    string
	SambaDomainName   string
}

// SambaDomainDN returns the DN of the synthetic sambaDomain entry:
// sambaDomainName=<name>,<baseDN>.
func SambaDomainDN(baseDN, domainName string) string {
	return fmt.Sprintf("sambaDomainName=%s,%s", domainName, baseDN)
}

// UserDN returns the canonical DN for a username: uid=<username>,ou=users,<baseDN>.
func UserDN(baseDN, username string) string {
	return fmt.Sprintf("uid=%s,ou=users,%s", username, baseDN)
}

// GroupDN returns the canonical DN for a group: cn=<name>,ou=groups,<baseDN>.
func GroupDN(baseDN, name string) string {
	return fmt.Sprintf("cn=%s,ou=groups,%s", name, baseDN)
}

// UsersOUDN returns the DN of the "ou=users" container itself.
func UsersOUDN(baseDN string) string {
	return "ou=users," + baseDN
}

// GroupsOUDN returns the DN of the "ou=groups" container itself.
func GroupsOUDN(baseDN string) string {
	return "ou=groups," + baseDN
}

// splitDN breaks a DN into its RDN components, trimming the incidental
// whitespace RFC 4514 allows around each one (e.g. "cn=x, ou=y, dc=z").
// The split on "," is deliberately naive -- no support for an escaped
// "\," inside a value -- since usernames, group names, and the configured
// baseDN in this system are plain identifiers, never DN-escaped values.
func splitDN(dn string) []string {
	if dn == "" {
		return nil
	}
	parts := strings.Split(dn, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// rdnValue reports whether component is an RDN of the given attribute type
// (case-insensitive, per RFC 4512 attribute-type matching), returning its
// value with exactly the case it was supplied in. Attribute *values* are
// never case-folded here: every identity lookup elsewhere in this codebase
// (map keys in identity.Snapshot.Users/Groups) is an exact, case-sensitive
// match, so folding a username or group name's case here would let a
// differently-cased DN silently resolve to a different account, or to
// nothing.
func rdnValue(component, attr string) (string, bool) {
	eq := strings.Index(component, "=")
	if eq < 0 {
		return "", false
	}
	if !strings.EqualFold(strings.TrimSpace(component[:eq]), attr) {
		return "", false
	}
	return strings.TrimSpace(component[eq+1:]), true
}

// dnEqualFold reports whether two DNs are structurally equal: same number
// of RDNs, each pair case-insensitively equal (attribute type and value
// alike). Used only for comparing against fixed, operator-configured paths
// (the base DN, "ou=users"/"ou=groups") -- never for the identity-bearing
// leaf RDN, which stays exact-case (see rdnValue).
func dnEqualFold(a, b string) bool {
	pa, pb := splitDN(a), splitDN(b)
	if len(pa) != len(pb) {
		return false
	}
	for i := range pa {
		if !strings.EqualFold(pa[i], pb[i]) {
			return false
		}
	}
	return true
}

// dnTrimSuffixFold reports whether dn's trailing RDN components
// case-insensitively match suffix's (see dnEqualFold), returning dn's
// remaining leading components, case preserved, on match.
func dnTrimSuffixFold(dn, suffix string) (rest []string, ok bool) {
	dnParts := splitDN(dn)
	suffixParts := splitDN(suffix)
	if len(dnParts) < len(suffixParts) {
		return nil, false
	}
	offset := len(dnParts) - len(suffixParts)
	for i, sp := range suffixParts {
		if !strings.EqualFold(dnParts[offset+i], sp) {
			return nil, false
		}
	}
	return dnParts[:offset], true
}

// UsernameFromBindDN extracts a username from either a full user DN or a
// bare username supplied as the bind DN (accepted as a simplification).
func UsernameFromBindDN(baseDN, dn string) (string, bool) {
	if dn == "" {
		return "", false
	}
	if rest, ok := dnTrimSuffixFold(dn, UsersOUDN(baseDN)); ok && len(rest) == 1 {
		if username, ok := rdnValue(rest[0], "uid"); ok {
			return username, true
		}
	}
	if !strings.Contains(dn, "=") {
		return strings.TrimSpace(dn), true
	}
	return "", false
}

// UsernameFromLeafDN extracts a username strictly from a full user DN
// (unlike UsernameFromBindDN, it does NOT accept a bare username) -- used
// when matching a SearchRequest's base object, where a bare string like
// "jsmith" is just an unmatched, non-DN base, not a bind-DN shorthand.
func UsernameFromLeafDN(baseDN, dn string) (string, bool) {
	rest, ok := dnTrimSuffixFold(dn, UsersOUDN(baseDN))
	if !ok || len(rest) != 1 {
		return "", false
	}
	return rdnValue(rest[0], "uid")
}

// GroupNameFromDN extracts a group name from a group DN, e.g.
// "cn=engineering,ou=groups,dc=example,dc=com" -> "engineering".
func GroupNameFromDN(baseDN, dn string) (string, bool) {
	rest, ok := dnTrimSuffixFold(dn, GroupsOUDN(baseDN))
	if !ok || len(rest) != 1 {
		return "", false
	}
	return rdnValue(rest[0], "cn")
}
