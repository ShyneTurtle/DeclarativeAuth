package ldapserver

import (
	"fmt"
	"sort"
	"strings"

	"declarativeauth/internal/identity"
)

// Attribute is a single LDAP attribute with its (possibly multi-valued) values.
type Attribute struct {
	Name   string
	Values []string
	// Sensitive attributes (the Samba NT hash) are never returned to a "*"
	// or empty (default) attribute selection, only when named explicitly --
	// see buildSearchResultEntry in search.go. This is on top of, not
	// instead of, only building these attributes into the entry at all for
	// a bind privileged via the samba-readers group in the first place.
	Sensitive bool
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

// SambaUserAttrs is a user's Samba-specific attributes (sambaSID derived
// from the configured domain SID + that user's assigned RID, sambaNTPassword
// from store.SambaCredential.NTHash), added to UserEntry's output only for
// a search privileged via the samba-readers group -- see handleSearch.
type SambaUserAttrs struct {
	SID     string
	NTHash  string
	Enabled bool
	// PwdLastSet is store.SambaCredential.PasswordSetAt as Unix seconds, rendered as
	// sambaPwdLastSet. Required, not cosmetic: ldapsam treats a sambaSamAccount with
	// no sambaPwdLastSet (or "0") as "password never set" and forces a "must change
	// password" prompt on every logon -- found live, blocking every Samba login
	// regardless of how the account was actually provisioned.
	PwdLastSet string
	// PrimaryGroupSID is rendered as sambaPrimaryGroupSID for compatibility
	// with LDAP-aware Samba tooling that reads it (e.g. `samba-tool domain
	// classicupgrade`). On its own it does NOT fix pdbedit/smbd showing
	// "Primary Group SID: (NULL SID)" -- verified against Samba 4.17's own
	// source (source3/passdb/pdb_ldap.c): init_sam_from_ldap never reads
	// this attribute for a live ldapsam bind. The actual mechanism,
	// get_primary_group_sid() in source3/passdb/lookup_sid.c, always calls
	// getpwnam(3) on the Samba host and maps its pw_gid to a SID; it never
	// asks LDAP for a group SID directly. See UIDNumber/GIDNumber below,
	// which is what that getpwnam(3) call needs (via NSS -- nss_ldap/sssd/
	// nslcd, or winbind with `ldapsam:trusted = yes` -- pointed at this
	// same LDAP server) to resolve to anything other than
	// NT_STATUS_NO_SUCH_USER, confirmed to be the real root cause of the
	// NULL SID by running pdbedit against this server in the devcontainer.
	PrimaryGroupSID string
	// UIDNumber/GIDNumber add posixAccount, making this user resolvable via
	// NSS getpwnam(3) once the Samba host's nsswitch.conf is pointed at
	// this LDAP server -- see PrimaryGroupSID above for why that's what
	// actually matters, not sambaPrimaryGroupSID. GIDNumber is always
	// SambaDomainUsersRID (513): this system has no notion of a per-user
	// primary group, matching PrimaryGroupSID.
	UIDNumber string
	GIDNumber string
}

// SambaDomainUsersRID is the well-known RID for the "Domain Users" group,
// fixed by the Windows/Samba SID scheme (not configurable) -- see
// PrimaryGroupSID.
const SambaDomainUsersRID = 513

// SambaWellKnownGroupName is the "Domain Users" group every user's
// PrimaryGroupSID points at. It has no row in identity.Snapshot.Groups --
// it's not a declared group, just the fixed RID-513 group the Windows/Samba
// SID scheme requires to exist -- so it's synthesized directly into search
// results (see SambaWellKnownGroupEntry) instead of being sourced from
// config like every other group. Real ldapsam backends normally bootstrap
// this entry into LDAP themselves on first run; this server's identity is
// read-only via LDAP, so nothing ever would otherwise.
const SambaWellKnownGroupName = "Domain Users"

// SambaGroupAttrs is a declarative group's Samba-specific attributes,
// added to GroupEntry's output only for a search privileged via the
// samba-readers group -- mirrors SambaUserAttrs. RID is assigned once per
// group name and persisted (see store.SambaGroupStore), the same way a
// user's RID is.
type SambaGroupAttrs struct {
	SID string
	// GIDNumber mirrors the RID embedded in SID, rendered as a POSIX gid --
	// required by posixGroup (MUST gidNumber) and read by Samba's
	// pdb_enum_group_members-style group-membership lookups alongside
	// memberUid, which is what actually makes a declarative group usable in
	// a Windows ACL: sambaGroupMapping alone gives the group a resolvable
	// name/SID, but membership resolution for building a user's access
	// token comes from here, not from groupOfNames' DN-valued "member".
	GIDNumber string
}

// UserEntry renders a user's LDAP attributes, including the fully flattened
// memberOf list read directly off the snapshot — O(1), no per-request graph
// traversal. samba, when non-nil, adds a sambaSamAccount auxiliary
// objectClass with sambaSID/sambaNTPassword/sambaAcctFlags -- the caller is
// responsible for only ever passing a non-nil value to an already-privileged
// requester (see internal/ldapserver.Config.SambaReadersGroup).
func UserEntry(baseDN string, u identity.User, flattenedGroups []string, samba *SambaUserAttrs, custom map[string][]string) []Attribute {
	memberOf := make([]string, len(flattenedGroups))
	for i, g := range flattenedGroups {
		memberOf[i] = GroupDN(baseDN, g)
	}
	objectClasses := []string{"declarativeAuthUser", "inetOrgPerson"}
	if samba != nil {
		objectClasses = append(objectClasses, "sambaSamAccount")
		if samba.UIDNumber != "" {
			objectClasses = append(objectClasses, "posixAccount")
		}
	}
	if len(custom) > 0 {
		objectClasses = append(objectClasses, "extensibleObject")
	}
	attrs := []Attribute{
		{Name: "objectClass", Values: objectClasses},
		{Name: "uid", Values: []string{u.Username}},
		{Name: "cn", Values: []string{u.DisplayNameOrDefault()}},
		{Name: "givenName", Values: nonEmpty(u.FirstName)},
		{Name: "sn", Values: nonEmpty(u.Name)},
		{Name: "mail", Values: nonEmpty(u.Email)},
		{Name: "memberOf", Values: memberOf},
	}
	if samba != nil {
		attrs = append(attrs,
			Attribute{Name: "sambaSID", Values: []string{samba.SID}, Sensitive: true},
			Attribute{Name: "sambaAcctFlags", Values: []string{sambaAcctFlags(samba.Enabled)}, Sensitive: true},
		)
		if samba.PrimaryGroupSID != "" {
			attrs = append(attrs, Attribute{Name: "sambaPrimaryGroupSID", Values: []string{samba.PrimaryGroupSID}, Sensitive: true})
		}
		if samba.UIDNumber != "" {
			attrs = append(attrs,
				Attribute{Name: "uidNumber", Values: []string{samba.UIDNumber}, Sensitive: true},
				Attribute{Name: "gidNumber", Values: []string{samba.GIDNumber}, Sensitive: true},
				// Fixed, not declarative: this system has no notion of a
				// per-user home directory or login shell, and neither is
				// meant for interactive Unix login -- this exists purely so
				// getpwnam(3) (see PrimaryGroupSID) resolves to something.
				Attribute{Name: "homeDirectory", Values: []string{"/home/" + u.Username}, Sensitive: true},
				Attribute{Name: "loginShell", Values: []string{"/bin/false"}, Sensitive: true},
			)
		}
		if samba.NTHash != "" {
			attrs = append(attrs, Attribute{Name: "sambaNTPassword", Values: []string{samba.NTHash}, Sensitive: true})
		}
		if samba.PwdLastSet != "" {
			attrs = append(attrs, Attribute{Name: "sambaPwdLastSet", Values: []string{samba.PwdLastSet}, Sensitive: true})
		}
	}
	attrs = append(attrs, customAttributesToAttrs(custom)...)
	return attrs
}

// customAttributesToAttrs renders a resolved custom-attribute map (see
// identity.ResolveCustomAttributes) as ordinary, non-Sensitive LDAP
// attributes: these are plain directory data declared by the operator (a
// phone number, a cost center), not the Samba namespace's gated credential
// material, so they're visible to any search that would otherwise see this
// entry at all. Sorted by name for a deterministic wire order.
func customAttributesToAttrs(custom map[string][]string) []Attribute {
	if len(custom) == 0 {
		return nil
	}
	names := make([]string, 0, len(custom))
	for name := range custom {
		names = append(names, name)
	}
	sort.Strings(names)
	attrs := make([]Attribute, 0, len(names))
	for _, name := range names {
		attrs = append(attrs, Attribute{Name: name, Values: custom[name]})
	}
	return attrs
}

// sambaAcctFlags renders Samba's fixed-width (11 characters between the
// brackets) account-control-block string, e.g. "[U          ]" for an
// enabled normal user or "[UD         ]" once disabled.
func sambaAcctFlags(enabled bool) string {
	flags := "U"
	if !enabled {
		flags += "D"
	}
	return "[" + flags + strings.Repeat(" ", 11-len(flags)) + "]"
}

// SambaDomainEntry renders the synthetic, read-only sambaDomain entry
// smbd looks up (by sambaDomainName, searching under the LDAP suffix) to
// learn the domain SID before it can compute or verify any user's sambaSID.
// Samba's ldapsam backend normally creates this entry itself on first run
// if missing -- identity is read-only via LDAP here, so it must already
// exist, sourced entirely from EnvLDAPSambaDomainSID/EnvLDAPSambaDomainName
// rather than ever being written by this server.
func SambaDomainEntry(domainName, domainSID string) []Attribute {
	return []Attribute{
		{Name: "objectClass", Values: []string{"sambaDomain"}},
		{Name: "sambaDomainName", Values: []string{domainName}},
		{Name: "sambaSID", Values: []string{domainSID}},
	}
}

// GroupEntry renders a group's LDAP attributes, including "member" -- every
// user transitively (flattened, diamond-safe) in the group, as full user
// DNs. RFC 4519's groupOfNames declares "member" a MUST attribute; a group
// with zero flattened members (legal in this system's declarative config)
// necessarily violates that MUST, same as any other empty-group LDAP
// server -- there is no valid groupOfNames encoding of "no members yet".
// samba, when non-nil, adds posixGroup/sambaGroupMapping so the group can be
// resolved by SID and used in a Windows ACL -- the caller is responsible for
// only ever passing a non-nil value to an already-privileged requester, same
// as UserEntry.
func GroupEntry(baseDN string, g identity.Group, flattenedMembers []string, samba *SambaGroupAttrs, custom map[string][]string) []Attribute {
	members := make([]string, len(flattenedMembers))
	for i, username := range flattenedMembers {
		members[i] = UserDN(baseDN, username)
	}
	objectClasses := []string{"groupOfNames"}
	if samba != nil {
		objectClasses = append(objectClasses, "posixGroup", "sambaGroupMapping")
	}
	if len(custom) > 0 {
		objectClasses = append(objectClasses, "extensibleObject")
	}
	attrs := []Attribute{
		{Name: "objectClass", Values: objectClasses},
		{Name: "cn", Values: []string{g.Name}},
		{Name: "description", Values: nonEmpty(g.Description)},
		{Name: "member", Values: members},
	}
	if samba != nil {
		attrs = append(attrs,
			Attribute{Name: "gidNumber", Values: []string{samba.GIDNumber}, Sensitive: true},
			Attribute{Name: "memberUid", Values: flattenedMembers, Sensitive: true},
			Attribute{Name: "sambaSID", Values: []string{samba.SID}, Sensitive: true},
			Attribute{Name: "sambaGroupType", Values: []string{"2"}, Sensitive: true}, // 2 = SID_NAME_DOM_GRP
		)
	}
	attrs = append(attrs, customAttributesToAttrs(custom)...)
	return attrs
}

// SambaWellKnownGroupEntry renders the synthetic "Domain Users" group (see
// SambaWellKnownGroupName) every user's sambaPrimaryGroupSID points at.
// Unlike GroupEntry it's never built from identity.Snapshot -- there is no
// membership list to synthesize (a user's primary group is implied by
// SambaUserAttrs.PrimaryGroupSID on their own entry, not by enumerating this
// group's members), only the identity a SID-to-name/gid lookup needs.
func SambaWellKnownGroupEntry(domainSID string) []Attribute {
	return []Attribute{
		{Name: "objectClass", Values: []string{"groupOfNames", "posixGroup", "sambaGroupMapping"}},
		{Name: "cn", Values: []string{SambaWellKnownGroupName}},
		{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", SambaDomainUsersRID)}, Sensitive: true},
		{Name: "sambaSID", Values: []string{fmt.Sprintf("%s-%d", domainSID, SambaDomainUsersRID)}, Sensitive: true},
		{Name: "sambaGroupType", Values: []string{"2"}, Sensitive: true},
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
			`( 1.3.6.1.4.1.7165.2.2.6 NAME 'sambaSamAccount' SUP top AUXILIARY MUST ( uid $ sambaSID ) MAY ( sambaNTPassword $ sambaPwdLastSet $ sambaAcctFlags $ sambaDomainName $ sambaPrimaryGroupSID ) )`,
			`( 1.3.6.1.4.1.7165.2.2.5 NAME 'sambaDomain' SUP top STRUCTURAL MUST ( sambaDomainName $ sambaSID ) )`,
			// RFC 2307 declares posixAccount/posixGroup STRUCTURAL;
			// declared AUXILIARY here since every entry that carries either
			// also carries inetOrgPerson/groupOfNames, and an entry can
			// only have one STRUCTURAL class.
			`( 1.3.6.1.1.1.2.0 NAME 'posixAccount' SUP top AUXILIARY MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory ) MAY ( userPassword $ loginShell $ gecos $ description ) )`,
			`( 1.3.6.1.1.1.2.2 NAME 'posixGroup' SUP top AUXILIARY MUST ( cn $ gidNumber ) MAY ( memberUid $ description ) )`,
			`( 1.3.6.1.4.1.7165.2.2.4 NAME 'sambaGroupMapping' SUP top AUXILIARY MUST ( sambaSID $ sambaGroupType ) MAY ( displayName $ description ) )`,
			// The standard RFC 4512 "any attribute allowed" class -- added to
			// an entry only when it actually carries at least one declarative
			// customAttribute/userCustomAttribute/directUserCustomAttribute
			// (see UserEntry/GroupEntry), since those attribute names are
			// arbitrary and unbounded and can't be enumerated here ahead of
			// time the way every other attributeType in this list is.
			`( 1.3.6.1.4.1.1466.101.120.111 NAME 'extensibleObject' SUP top AUXILIARY )`,
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
			`( 1.3.6.1.4.1.7165.2.1.20 NAME 'sambaSID' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )`,
			`( 1.3.6.1.4.1.7165.2.1.25 NAME 'sambaNTPassword' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )`,
			`( 1.3.6.1.4.1.7165.2.1.24 NAME 'sambaPwdLastSet' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )`,
			`( 1.3.6.1.4.1.7165.2.1.26 NAME 'sambaAcctFlags' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )`,
			`( 1.3.6.1.4.1.7165.2.1.38 NAME 'sambaDomainName' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )`,
			`( 1.3.6.1.4.1.7165.2.1.21 NAME 'sambaPrimaryGroupSID' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )`,
			`( 1.3.6.1.1.1.1.1 NAME 'gidNumber' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )`,
			`( 1.3.6.1.1.1.1.12 NAME 'memberUid' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )`,
			`( 1.3.6.1.4.1.7165.2.1.19 NAME 'sambaGroupType' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )`,
			`( 2.16.840.1.113730.3.1.241 NAME 'displayName' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )`,
			`( 1.3.6.1.1.1.1.0 NAME 'uidNumber' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )`,
			`( 1.3.6.1.1.1.1.3 NAME 'homeDirectory' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )`,
			`( 1.3.6.1.1.1.1.4 NAME 'loginShell' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )`,
			`( 1.3.6.1.1.1.1.2 NAME 'gecos' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )`,
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
