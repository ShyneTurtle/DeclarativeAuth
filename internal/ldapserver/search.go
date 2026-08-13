package ldapserver

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"declarativeauth/internal/identity"
	"declarativeauth/internal/store"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

const (
	scopeBaseObject   = 0
	scopeSingleLevel  = 1
	scopeWholeSubtree = 2
)

type entry struct {
	dn    string
	attrs []Attribute
	// forceAllAttrs bypasses the client's requested-attribute selection --
	// used for RootDSE/subschema, which are informational/capability
	// entries a client fetches by explicit attribute name anyway, and
	// which this server always returns in full rather than tracking which
	// of their attributes count as "operational" per RFC 4512.
	forceAllAttrs bool
}

// attrSelection is a SearchRequest's decoded attribute-selection list
// (RFC 4511 §4.5.1).
type attrSelection struct {
	all   bool // "*", or the list was empty -- the default
	none  bool // "1.1" -- explicitly no attributes
	names map[string]bool
}

func (sel attrSelection) includes(name string) bool {
	if sel.all {
		return true
	}
	if sel.none {
		return false
	}
	return sel.names[strings.ToLower(name)]
}

// includesExplicit reports whether name was asked for by its exact name --
// unlike includes, a "*"/empty (all) selection does NOT count. Used to gate
// Attribute.Sensitive values: a wildcard dump of "every attribute" must
// never surface the Samba NT hash, only a request that names it directly
// (which is how Samba's own ldapsam backend actually asks for it).
func (sel attrSelection) includesExplicit(name string) bool {
	if sel.none {
		return false
	}
	return sel.names[strings.ToLower(name)]
}

func parseAttrSelection(p *ber.Packet) attrSelection {
	if p == nil || len(p.Children) == 0 {
		return attrSelection{all: true}
	}
	names := make(map[string]bool, len(p.Children))
	for _, c := range p.Children {
		name, _ := c.Value.(string)
		switch name {
		case "", "*":
			return attrSelection{all: true}
		case "1.1":
			return attrSelection{none: true}
		default:
			names[strings.ToLower(name)] = true
		}
	}
	return attrSelection{names: names}
}

// handleSearch processes a SearchRequest against the current snapshot,
// supporting equality/AND/OR/present filters over user and group entries
// under baseDN, plus RootDSE/subschema discovery entries, requested-
// attribute selection, typesOnly, and simple paged results (RFC 2696).
func (h *Handler) handleSearch(w io.Writer, isTLS bool, sourceIP, boundUser string, messageID int64, op *ber.Packet, controlsPacket *ber.Packet, startTLSAvailable bool) {
	if h.OnSearch != nil {
		h.OnSearch(sourceIP)
	}
	if len(op.Children) < 8 {
		writeResult(w, messageID, ldap.ApplicationSearchResultDone, ldap.LDAPResultProtocolError, "", "malformed search request")
		return
	}
	baseObject, _ := op.Children[0].Value.(string)
	scope, _ := op.Children[1].Value.(int64)
	typesOnly, _ := op.Children[5].Value.(bool)
	filterPacket := op.Children[6]
	requested := parseAttrSelection(op.Children[7])

	// RootDSE discovery (an empty-base, base-scope search) is the very
	// first thing most LDAP client libraries do on connect, before any
	// bind -- rejecting it for lack of a prior bind would break that
	// discovery flow for no confidentiality benefit (it exposes server
	// capabilities, not identity data).
	isRootDSEProbe := baseObject == "" && int(scope) == scopeBaseObject
	if h.Config.RequireTLS && !isTLS && !isRootDSEProbe {
		writeResult(w, messageID, ldap.ApplicationSearchResultDone, ldap.LDAPResultConfidentialityRequired, "", "TLS required: use the secure listener or StartTLS")
		return
	}
	if boundUser == "" && !h.Config.AllowAnonymousBind && !isRootDSEProbe {
		writeResult(w, messageID, ldap.ApplicationSearchResultDone, ldap.LDAPResultInsufficientAccessRights, "", "bind required before search")
		return
	}

	filter, err := parseFilter(filterPacket)
	if err != nil {
		writeResult(w, messageID, ldap.ApplicationSearchResultDone, ldap.LDAPResultUnavailableCriticalExtension, "", "unsupported filter")
		return
	}

	snap := h.Snapshot()

	// Only a bind authenticated as a member of the configured
	// samba-readers group -- never anonymous, never any other user -- ever
	// sees sambaSamAccount/sambaDomain data. Fetched once per search
	// (not once per matched entry) and passed down.
	var sambaCreds map[string]store.SambaCredential
	sambaPrivileged := h.Config.SambaReadersGroup != "" && boundUser != "" && snap.IsMemberOf(boundUser, h.Config.SambaReadersGroup)
	if sambaPrivileged && h.Credentials != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		sambaCreds, err = h.Credentials.AllSambaCredentials(ctx)
		cancel()
		if err != nil {
			if h.Logger != nil {
				h.Logger.Error("fetching samba credentials failed", "component", "ldapserver", "error", err)
			}
			writeResult(w, messageID, ldap.ApplicationSearchResultDone, ldap.LDAPResultOther, "", "internal error")
			return
		}
	}

	entries := h.entriesFor(snap, baseObject, int(scope), startTLSAvailable, sambaPrivileged, sambaCreds)
	sort.Slice(entries, func(i, j int) bool { return entries[i].dn < entries[j].dn })

	var matched []entry
	for _, e := range entries {
		if filter.matches(e.attrs) {
			matched = append(matched, e)
		}
	}

	start, end := 0, len(matched)
	var respControls []*ber.Packet
	if page, ok := findPagedResults(parseControls(controlsPacket)); ok {
		start = page.offset
		if start > len(matched) {
			start = len(matched)
		}
		end = len(matched)
		if page.size > 0 && start+page.size < end {
			end = start + page.size
		}
		remaining := len(matched) - end
		respControls = append(respControls, pagedResultsControl(remaining, end, remaining > 0))
	}

	for _, e := range matched[start:end] {
		writeMessage(w, messageID, buildSearchResultEntry(e, requested, typesOnly))
	}
	writeMessageWithControls(w, messageID, newLDAPResultPacket(ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess, "", ""), respControls)
}

func (h *Handler) entriesFor(snap *identity.Snapshot, baseObject string, scope int, startTLSAvailable bool, sambaPrivileged bool, sambaCreds map[string]store.SambaCredential) []entry {
	baseDN := h.Config.BaseDN

	if baseObject == "" {
		return []entry{{dn: "", attrs: RootDSEEntry(baseDN, startTLSAvailable), forceAllAttrs: true}}
	}
	if dnEqualFold(baseObject, SubschemaDN) {
		return []entry{{dn: SubschemaDN, attrs: SubschemaEntry(), forceAllAttrs: true}}
	}
	if sambaPrivileged && dnEqualFold(baseObject, SambaDomainDN(baseDN, h.Config.SambaDomainName)) {
		if scope == scopeSingleLevel {
			return nil // leaf: no children
		}
		return []entry{{dn: SambaDomainDN(baseDN, h.Config.SambaDomainName), attrs: SambaDomainEntry(h.Config.SambaDomainName, h.Config.SambaDomainSID)}}
	}

	if username, ok := UsernameFromLeafDN(baseDN, baseObject); ok {
		if scope == scopeSingleLevel {
			return nil // a user entry is a leaf: no children
		}
		if u, exists := snap.Users[username]; exists {
			samba := h.sambaAttrsFor(username, u, sambaPrivileged, sambaCreds)
			return []entry{{dn: UserDN(baseDN, username), attrs: UserEntry(baseDN, u, snap.FlattenedMemberOf[username], samba)}}
		}
		return nil
	}
	if name, ok := GroupNameFromDN(baseDN, baseObject); ok {
		if scope == scopeSingleLevel {
			return nil // a group entry is a leaf: no children
		}
		if g, exists := snap.Groups[name]; exists {
			return []entry{{dn: GroupDN(baseDN, name), attrs: GroupEntry(baseDN, g, snap.FlattenedMembers[name])}}
		}
		return nil
	}
	if dnEqualFold(baseObject, UsersOUDN(baseDN)) {
		return h.usersSubtree(snap, scope, sambaPrivileged, sambaCreds)
	}
	if dnEqualFold(baseObject, GroupsOUDN(baseDN)) {
		return h.groupsSubtree(snap, scope)
	}
	if dnEqualFold(baseObject, baseDN) {
		switch scope {
		case scopeBaseObject:
			return []entry{{dn: baseDN, attrs: BaseEntry(baseDN)}}
		case scopeSingleLevel:
			entries := []entry{
				{dn: UsersOUDN(baseDN), attrs: OUEntry("users")},
				{dn: GroupsOUDN(baseDN), attrs: OUEntry("groups")},
			}
			if sambaPrivileged {
				entries = append(entries, entry{dn: SambaDomainDN(baseDN, h.Config.SambaDomainName), attrs: SambaDomainEntry(h.Config.SambaDomainName, h.Config.SambaDomainSID)})
			}
			return entries
		case scopeWholeSubtree:
			entries := []entry{{dn: baseDN, attrs: BaseEntry(baseDN)}}
			entries = append(entries, h.usersSubtree(snap, scopeWholeSubtree, sambaPrivileged, sambaCreds)...)
			entries = append(entries, h.groupsSubtree(snap, scopeWholeSubtree)...)
			if sambaPrivileged {
				entries = append(entries, entry{dn: SambaDomainDN(baseDN, h.Config.SambaDomainName), attrs: SambaDomainEntry(h.Config.SambaDomainName, h.Config.SambaDomainSID)})
			}
			return entries
		}
	}
	return nil
}

func (h *Handler) usersSubtree(snap *identity.Snapshot, scope int, sambaPrivileged bool, sambaCreds map[string]store.SambaCredential) []entry {
	baseDN := h.Config.BaseDN
	var entries []entry
	if scope == scopeBaseObject || scope == scopeWholeSubtree {
		entries = append(entries, entry{dn: UsersOUDN(baseDN), attrs: OUEntry("users")})
	}
	if scope == scopeBaseObject {
		return entries
	}
	for username, u := range snap.Users {
		samba := h.sambaAttrsFor(username, u, sambaPrivileged, sambaCreds)
		entries = append(entries, entry{dn: UserDN(baseDN, username), attrs: UserEntry(baseDN, u, snap.FlattenedMemberOf[username], samba)})
	}
	return entries
}

// sambaAttrsFor builds a user's Samba attributes for a privileged search,
// or nil if the search isn't privileged or no NT hash has been computed for
// this user yet (never logged in / never had a password set since the
// samba-readers-group feature was configured -- see
// auth.Authenticator.Authenticate's lazy backfill and store.CredentialStore.Upsert).
func (h *Handler) sambaAttrsFor(username string, u identity.User, sambaPrivileged bool, sambaCreds map[string]store.SambaCredential) *SambaUserAttrs {
	if !sambaPrivileged {
		return nil
	}
	cred, ok := sambaCreds[username]
	if !ok {
		return nil
	}
	return &SambaUserAttrs{
		SID:        fmt.Sprintf("%s-%d", h.Config.SambaDomainSID, cred.RID),
		NTHash:     cred.NTHash,
		Enabled:    u.Enabled,
		PwdLastSet: strconv.FormatInt(cred.PasswordSetAt.Unix(), 10),
	}
}

func (h *Handler) groupsSubtree(snap *identity.Snapshot, scope int) []entry {
	baseDN := h.Config.BaseDN
	var entries []entry
	if scope == scopeBaseObject || scope == scopeWholeSubtree {
		entries = append(entries, entry{dn: GroupsOUDN(baseDN), attrs: OUEntry("groups")})
	}
	if scope == scopeBaseObject {
		return entries
	}
	for name, g := range snap.Groups {
		entries = append(entries, entry{dn: GroupDN(baseDN, name), attrs: GroupEntry(baseDN, g, snap.FlattenedMembers[name])})
	}
	return entries
}

func buildSearchResultEntry(e entry, sel attrSelection, typesOnly bool) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "SearchResultEntry")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.dn, "objectName"))

	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PartialAttributeList")
	for _, a := range e.attrs {
		if len(a.Values) == 0 {
			continue
		}
		if a.Sensitive {
			if !sel.includesExplicit(a.Name) {
				continue
			}
		} else if !e.forceAllAttrs && !sel.includes(a.Name) {
			continue
		}
		pa := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PartialAttribute")
		pa.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a.Name, "type"))
		vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		if !typesOnly {
			for _, v := range a.Values {
				vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "value"))
			}
		}
		pa.AppendChild(vals)
		attrs.AppendChild(pa)
	}
	p.AppendChild(attrs)
	return p
}
