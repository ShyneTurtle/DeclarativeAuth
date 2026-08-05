package ldapserver

import "declarativeauth/internal/identity"

// Attribute is a single LDAP attribute with its (possibly multi-valued) values.
type Attribute struct {
	Name   string
	Values []string
}

// oidStartTLS is the LDAPOID for the StartTLS extended operation (RFC 4511
// §4.14.1 / RFC 2830).
const oidStartTLS = "1.3.6.1.4.1.1466.20037"

// oidPagedResults is the LDAPOID for the simple paged results control
// (RFC 2696), advertised in RootDSE's supportedControl and used by
// search.go to page large result sets.
const oidPagedResults = "1.2.840.113556.1.4.319"

// SubschemaDN is the fixed DN of the subschema subentry advertised by
// RootDSE's subschemaSubentry attribute.
const SubschemaDN = "cn=subschema"

// UserEntry renders a user's LDAP attributes, including the fully flattened
// memberOf list read directly off the snapshot — O(1), no per-request graph
// traversal.
func UserEntry(baseDN string, u identity.User, flattenedGroups []string) []Attribute {
	memberOf := make([]string, len(flattenedGroups))
	for i, g := range flattenedGroups {
		memberOf[i] = GroupDN(baseDN, g)
	}
	return []Attribute{
		{Name: "objectClass", Values: []string{"declarativeAuthUser", "inetOrgPerson"}},
		{Name: "uid", Values: []string{u.Username}},
		{Name: "cn", Values: []string{u.DisplayNameOrDefault()}},
		{Name: "givenName", Values: nonEmpty(u.FirstName)},
		{Name: "sn", Values: nonEmpty(u.Name)},
		{Name: "mail", Values: nonEmpty(u.Email)},
		{Name: "memberOf", Values: memberOf},
	}
}

// GroupEntry renders a group's LDAP attributes, including "member" -- every
// user transitively (flattened, diamond-safe) in the group, as full user
// DNs. RFC 4519's groupOfNames declares "member" a MUST attribute; a group
// with zero flattened members (legal in this system's declarative config)
// necessarily violates that MUST, same as any other empty-group LDAP
// server -- there is no valid groupOfNames encoding of "no members yet".
func GroupEntry(baseDN string, g identity.Group, flattenedMembers []string) []Attribute {
	members := make([]string, len(flattenedMembers))
	for i, username := range flattenedMembers {
		members[i] = UserDN(baseDN, username)
	}
	return []Attribute{
		{Name: "objectClass", Values: []string{"groupOfNames"}},
		{Name: "cn", Values: []string{g.Name}},
		{Name: "description", Values: nonEmpty(g.Description)},
		{Name: "member", Values: members},
	}
}

// BaseEntry renders the root entry at baseDN itself (e.g.
// "dc=example,dc=com"), so a base-scope search directly on it -- what most
// LDAP tooling does first to confirm the naming context exists -- returns a
// real object instead of nothing.
func BaseEntry(baseDN string) []Attribute {
	dc, _ := rdnValue(firstRDN(baseDN), "dc")
	attrs := []Attribute{
		{Name: "objectClass", Values: []string{"top", "dcObject", "organization"}},
	}
	if dc != "" {
		attrs = append(attrs, Attribute{Name: "dc", Values: []string{dc}}, Attribute{Name: "o", Values: []string{dc}})
	}
	return attrs
}

// OUEntry renders an organizational-unit container entry (e.g.
// "ou=users,<baseDN>"), so a base-scope search directly on it returns a
// real object instead of nothing.
func OUEntry(name string) []Attribute {
	return []Attribute{
		{Name: "objectClass", Values: []string{"top", "organizationalUnit"}},
		{Name: "ou", Values: []string{name}},
	}
}

// RootDSEEntry renders the root DSE (RFC 4512 §5.1): the nameless entry a
// well-behaved client fetches first (base-scope search on an empty base
// object) to discover the naming context, protocol version, schema
// location, and supported controls/extensions before doing anything else.
func RootDSEEntry(baseDN string, startTLSAvailable bool) []Attribute {
	attrs := []Attribute{
		{Name: "objectClass", Values: []string{"top"}},
		{Name: "namingContexts", Values: []string{baseDN}},
		{Name: "supportedLDAPVersion", Values: []string{"3"}},
		{Name: "subschemaSubentry", Values: []string{SubschemaDN}},
		{Name: "supportedControl", Values: []string{oidPagedResults}},
		{Name: "vendorName", Values: []string{"DeclarativeAuth"}},
	}
	if startTLSAvailable {
		attrs = append(attrs, Attribute{Name: "supportedExtension", Values: []string{oidStartTLS}})
	}
	return attrs
}

// SubschemaEntry renders the subschema subentry at SubschemaDN: minimal
// standard-OID objectClass/attributeType descriptions covering exactly the
// schema elements this server actually emits (see UserEntry/GroupEntry),
// so a strict client validating entries against the advertised schema
// doesn't reject them for referencing "unknown" definitions.
func SubschemaEntry() []Attribute {
	return []Attribute{
		{Name: "objectClass", Values: []string{"top", "subschema", "subentry"}},
		{Name: "cn", Values: []string{"subschema"}},
		{Name: "objectClasses", Values: []string{
			`( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )`,
			`( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( description ) )`,
			`( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL )`,
			`( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL MAY ( uid $ mail $ givenName ) )`,
			`( 2.5.6.9 NAME 'groupOfNames' SUP top STRUCTURAL MUST ( member $ cn ) MAY description )`,
			`( 2.5.6.5 NAME 'organizationalUnit' SUP top STRUCTURAL MUST ou )`,
			`( 0.9.2342.19200300.100.4.13 NAME 'domain' SUP top STRUCTURAL MUST dc MAY o )`,
			`( 1.3.6.1.4.1.61313.1.1 NAME 'declarativeAuthUser' SUP top AUXILIARY MAY ( memberOf ) )`,
		}},
		{Name: "attributeTypes", Values: []string{
			`( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )`,
			`( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )`,
			`( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )`,
			`( 2.5.4.4 NAME 'sn' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )`,
			`( 2.5.4.42 NAME 'givenName' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )`,
			`( 0.9.2342.19200300.100.1.3 NAME 'mail' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )`,
			`( 2.5.4.13 NAME 'description' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )`,
			`( 2.5.4.31 NAME 'member' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )`,
			`( 1.2.840.113556.1.2.102 NAME 'memberOf' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )`,
			`( 2.5.4.10 NAME 'o' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )`,
			`( 0.9.2342.19200300.100.1.25 NAME 'dc' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )`,
			`( 2.5.4.11 NAME 'ou' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )`,
		}},
	}
}

// firstRDN returns the leading RDN component of a DN, e.g.
// "dc=example,dc=com" -> "dc=example".
func firstRDN(dn string) string {
	parts := splitDN(dn)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}
