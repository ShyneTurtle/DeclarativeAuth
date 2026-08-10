package auth

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"unicode/utf16"

	//lint:ignore SA1019 required for Samba/NTLM interop -- see NTHash's doc comment below.
	"golang.org/x/crypto/md4"
)

// NTHash returns the Samba/NTLM "NT hash" of password: MD4 over its
// UTF-16LE encoding, hex-encoded uppercase -- the exact value Samba's
// ldapsam passdb backend expects in the sambaNTPassword attribute to
// compute NTLM challenge-responses itself.
//
// This is deliberately NOT a secure password hash: unsalted MD4 is fast to
// brute-force offline if leaked, nowhere near Argon2id. It exists only
// because the NTLM protocol requires the verifier to hold this exact
// derived value -- there is no way to make Samba/SMB authentication work
// without it. See internal/ldapserver's samba-readers-group gating for how
// read access to it is restricted to a trusted Samba service bind.
func NTHash(password string) string {
	u16 := utf16.Encode([]rune(password))
	b := make([]byte, len(u16)*2)
	for i, r := range u16 {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	h := md4.New()
	h.Write(b)
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}
