package ldapserver

import (
	"io"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func writeMessage(w io.Writer, messageID int64, protocolOp *ber.Packet) error {
	return writeMessageWithControls(w, messageID, protocolOp, nil)
}

// writeMessageWithControls is writeMessage plus an optional Controls [0]
// SEQUENCE (RFC 4511 §4.1.11) trailing the protocolOp -- used to return
// e.g. a paged-results response control alongside a SearchResultDone.
func writeMessageWithControls(w io.Writer, messageID int64, protocolOp *ber.Packet, controls []*ber.Packet) error {
	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	msg.AppendChild(protocolOp)
	if len(controls) > 0 {
		wrapper := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
		for _, c := range controls {
			wrapper.AppendChild(c)
		}
		msg.AppendChild(wrapper)
	}
	_, err := w.Write(msg.Bytes())
	return err
}

// newControl builds a Control SEQUENCE (RFC 4511 §4.1.11): controlType,
// criticality (always FALSE here -- every control this server returns is
// advisory), controlValue.
func newControl(oid string, value []byte) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, oid, "controlType"))
	p.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "criticality"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(value), "controlValue"))
	return p
}

// newLDAPResultPacket builds an application-tagged LDAPResult-shaped
// SEQUENCE: resultCode, matchedDN, diagnosticMessage. Used for BindResponse,
// SearchResultDone, and (with tag 24) unsolicited ExtendedResponse notices.
func newLDAPResultPacket(appTag ber.Tag, resultCode int, matchedDN, diagnostic string) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appTag, nil, "LDAPResult")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(resultCode), "resultCode"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, matchedDN, "matchedDN"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diagnostic, "diagnosticMessage"))
	return p
}

func writeResult(w io.Writer, messageID int64, appTag ber.Tag, resultCode int, matchedDN, diagnostic string) error {
	return writeMessage(w, messageID, newLDAPResultPacket(appTag, resultCode, matchedDN, diagnostic))
}

// writeExtendedResult sends an ExtendedResponse (application tag 24), used
// here as a disconnect notice on protocol violations.
func writeExtendedResult(w io.Writer, messageID int64, resultCode int, diagnostic string) error {
	return writeResult(w, messageID, 24, resultCode, "", diagnostic)
}

// writeExtendedResponse sends an ExtendedResponse to an ExtendedRequest
// (RFC 4511 §4.12), optionally echoing back a responseName [10] LDAPOID --
// e.g. the StartTLS OID on success, so the client can confirm which
// extended operation the response belongs to.
func writeExtendedResponse(w io.Writer, messageID int64, resultCode int, diagnostic, responseOID string) error {
	p := newLDAPResultPacket(24, resultCode, "", diagnostic)
	if responseOID != "" {
		p.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 10, responseOID, "responseName"))
	}
	return writeMessage(w, messageID, p)
}
