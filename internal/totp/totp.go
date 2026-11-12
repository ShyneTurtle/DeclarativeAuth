// Package totp implements RFC 6238 time-based one-time passwords
// (HMAC-SHA1, 6 digits, 30s step -- the profile every authenticator app
// supports) plus the AES-GCM sealing used to keep secrets encrypted at rest.
package totp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// Digits is the length of a code.
	Digits = 6
	// Period is the validity window of one code, in seconds.
	Period = 30
	// secretBytes is the secret length: 160 bits, the RFC 4226 recommendation.
	secretBytes = 20
	// skewSteps is how many steps either side of "now" are accepted, to
	// tolerate client clock drift.
	skewSteps = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a fresh random secret.
func GenerateSecret() ([]byte, error) {
	s := make([]byte, secretBytes)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	return s, nil
}

// EncodeSecret renders a secret as the unpadded base32 string authenticator
// apps expect for manual entry.
func EncodeSecret(secret []byte) string { return b32.EncodeToString(secret) }

// Step converts a point in time to its RFC 6238 time-step counter.
func Step(t time.Time) int64 { return t.Unix() / Period }

// Code computes the code for a given step.
func Code(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	// RFC 4226 §5.3 dynamic truncation.
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	mod := uint32(1)
	for i := 0; i < Digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", Digits, bin%mod)
}

// Verify checks code against the steps around now and returns the matching
// step. A match at or before lastStep is rejected: each code is single-use,
// so an observed code can't be replayed inside its validity window.
func Verify(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	if len(code) != Digits {
		return 0, false
	}
	cur := Step(now)
	matched := int64(-1)
	// No early exit: every candidate step is always compared.
	for d := int64(-skewSteps); d <= skewSteps; d++ {
		step := cur + d
		if subtle.ConstantTimeCompare([]byte(Code(secret, step)), []byte(code)) == 1 && step > lastStep {
			matched = step
		}
	}
	if matched < 0 {
		return 0, false
	}
	return matched, true
}

// OTPAuthURI builds the otpauth:// provisioning URI encoded in enrolment QR
// codes.
func OTPAuthURI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", EncodeSecret(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(Digits))
	q.Set("period", fmt.Sprint(Period))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Cipher seals secrets with AES-256-GCM so a database leak alone doesn't
// expose them.
type Cipher struct{ aead cipher.AEAD }

// NewCipher builds a Cipher from a 32-byte key.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("totp encryption key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

// Seal encrypts plaintext, binding it to aad (the username) so a sealed
// secret copied onto another account's row doesn't decrypt.
func (c *Cipher) Seal(plaintext []byte, aad string) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return c.aead.Seal(nonce, nonce, plaintext, []byte(aad)), nil
}

// Open reverses Seal.
func (c *Cipher) Open(sealed []byte, aad string) ([]byte, error) {
	n := c.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("sealed totp secret too short")
	}
	return c.aead.Open(nil, sealed[:n], sealed[n:], []byte(aad))
}

// ParseKey decodes the hex-encoded encryption key from configuration.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) != 64 {
		return nil, fmt.Errorf("expected 64 hex characters (32 bytes), got %d", len(s))
	}
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		var b byte
		if _, err := fmt.Sscanf(s[2*i:2*i+2], "%02x", &b); err != nil {
			return nil, errors.New("not valid hex")
		}
		key[i] = b
	}
	return key, nil
}
