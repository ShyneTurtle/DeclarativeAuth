package ldapserver

import (
	"io"
	"strings"

	"declarativeauth/internal/identity"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

const (
	scopeBaseObject = 0
)

type entry struct {
	dn    string
	attrs []Attribute
}

// handleSearch processes a SearchRequest against the current snapshot,
// supporting equality/AND/OR/present filters over user and group entries
// under baseDN.
func (h *Handler) handleSearch(w io.Writer, sourceIP, boundUser string, messageID int64, op *ber.Packet) {
	if h.OnSearch != nil {
		h.OnSearch(sourceIP)
	}
	if boundUser == "" && !h.Config.AllowAnonymousBind {
		writeResult(w, messageID, ldap.ApplicationSearchResultDone, ldap.LDAPResultInsufficientAccessRights, "", "bind required before search")
		return
	}
	if len(op.Children) < 7 {
		writeResult(w, messageID, ldap.ApplicationSearchResultDone, ldap.LDAPResultProtocolError, "", "malformed search request")
		return
	}
	baseObject, _ := op.Children[0].Value.(string)
	scope, _ := op.Children[1].Value.(int64)
	filterPacket := op.Children[6]

	filter, err := parseFilter(filterPacket)
	if err != nil {
		writeResult(w, messageID, ldap.ApplicationSearchResultDone, ldap.LDAPResultUnavailableCriticalExtension, "", "unsupported filter")
		return
	}

	snap := h.Snapshot()
	entries := h.entriesFor(snap, baseObject, int(scope))

	for _, e := range entries {
		if !filter.matches(e.attrs) {
			continue
		}
		writeMessage(w, messageID, buildSearchResultEntry(e))
	}
	writeResult(w, messageID, ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess, "", "")
}

func (h *Handler) entriesFor(snap *identity.Snapshot, baseObject string, scope int) []entry {
	baseDN := h.Config.BaseDN
	var entries []entry

	if username, ok := UsernameFromBindDN(baseDN, baseObject); ok && strings.HasSuffix(baseObject, ",ou=users,"+baseDN) {
		if u, exists := snap.Users[username]; exists {
			entries = append(entries, entry{dn: UserDN(baseDN, username), attrs: UserEntry(baseDN, u, snap.FlattenedMemberOf[username])})
		}
		return entries
	}
	if name, ok := GroupNameFromDN(baseDN, baseObject); ok {
		if g, exists := snap.Groups[name]; exists {
			entries = append(entries, entry{dn: GroupDN(baseDN, name), attrs: GroupEntry(g)})
		}
		return entries
	}

	if scope == scopeBaseObject {
		return nil
	}

	includeUsers := baseObject == baseDN || baseObject == "ou=users,"+baseDN
	includeGroups := baseObject == baseDN || baseObject == "ou=groups,"+baseDN

	if includeUsers {
		for username, u := range snap.Users {
			entries = append(entries, entry{dn: UserDN(baseDN, username), attrs: UserEntry(baseDN, u, snap.FlattenedMemberOf[username])})
		}
	}
	if includeGroups {
		for name, g := range snap.Groups {
			entries = append(entries, entry{dn: GroupDN(baseDN, name), attrs: GroupEntry(g)})
		}
	}
	return entries
}

func buildSearchResultEntry(e entry) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "SearchResultEntry")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.dn, "objectName"))

	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PartialAttributeList")
	for _, a := range e.attrs {
		if len(a.Values) == 0 {
			continue
		}
		pa := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PartialAttribute")
		pa.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a.Name, "type"))
		vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		for _, v := range a.Values {
			vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "value"))
		}
		pa.AppendChild(vals)
		attrs.AppendChild(pa)
	}
	p.AppendChild(attrs)
	return p
}
