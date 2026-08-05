package ldapserver

import (
	"strconv"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// requestControl is a parsed request Control (RFC 4511 §4.1.11): OID plus
// raw controlValue bytes. Criticality is ignored -- every control this
// server recognizes is optional/advisory, and any control it doesn't
// recognize is silently skipped rather than rejected, even if marked
// critical, since this server's control support is intentionally minimal
// (paged results only).
type requestControl struct {
	oid   string
	value []byte
}

// parseControls decodes a LDAPMessage's optional Controls [0] SEQUENCE (the
// sibling of protocolOp, not part of it -- see server.go's handleConn).
func parseControls(p *ber.Packet) []requestControl {
	if p == nil {
		return nil
	}
	var controls []requestControl
	for _, c := range p.Children {
		if len(c.Children) < 1 {
			continue
		}
		oid, _ := c.Children[0].Value.(string)
		var value []byte
		if last := c.Children[len(c.Children)-1]; len(c.Children) >= 2 &&
			last.ClassType == ber.ClassUniversal && last.Tag == ber.TagOctetString {
			value = last.ByteValue
		}
		controls = append(controls, requestControl{oid: oid, value: value})
	}
	return controls
}

// pagedResultsRequest is the decoded value of a simple paged results
// control (RFC 2696): SEQUENCE { size INTEGER, cookie OCTET STRING }.
type pagedResultsRequest struct {
	size   int
	offset int
}

// findPagedResults locates and decodes a paged-results control among the
// request's controls, if present.
//
// The cookie is this server's own previously-issued decimal offset (see
// pagedResultsControl) -- there's no server-side session state to validate
// it against, so a garbled cookie is treated leniently as "start over from
// offset 0" rather than an error: paging here is purely a slicing
// convenience over data the client is already fully authorized to read in
// one unpaged search, so a bad cookie can't expose anything a plain
// restart-from-scratch search wouldn't.
func findPagedResults(controls []requestControl) (req pagedResultsRequest, present bool) {
	for _, c := range controls {
		if c.oid != oidPagedResults {
			continue
		}
		inner, err := ber.DecodePacketErr(c.value)
		if err != nil || len(inner.Children) < 2 {
			return pagedResultsRequest{}, true
		}
		size, _ := inner.Children[0].Value.(int64)
		offset := 0
		if cookie := inner.Children[1].ByteValue; len(cookie) > 0 {
			if n, err := strconv.Atoi(string(cookie)); err == nil && n >= 0 {
				offset = n
			}
		}
		return pagedResultsRequest{size: int(size), offset: offset}, true
	}
	return pagedResultsRequest{}, false
}

// pagedResultsControl builds the response paged-results control: remaining
// is the exact count of further matching entries past this page, cookie is
// the offset a follow-up search should resume from (empty means "no more
// pages", the client-facing signal that pagination is complete).
func pagedResultsControl(remaining, nextOffset int, more bool) *ber.Packet {
	cookie := ""
	if more {
		cookie = strconv.Itoa(nextOffset)
	}
	inner := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "realSearchControlValue")
	inner.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(remaining), "size"))
	inner.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, cookie, "cookie"))
	return newControl(oidPagedResults, inner.Bytes())
}
