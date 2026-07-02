package ldapserver

import (
	"io"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func writeMessage(w io.Writer, messageID int64, protocolOp *ber.Packet) error {
	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	msg.AppendChild(protocolOp)
	_, err := w.Write(msg.Bytes())
	return err
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
// here as a disconnect notice on protocol violations / unsupported ops.
func writeExtendedResult(w io.Writer, messageID int64, resultCode int, diagnostic string) error {
	return writeResult(w, messageID, 24, resultCode, "", diagnostic)
}
