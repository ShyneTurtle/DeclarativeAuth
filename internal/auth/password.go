// Package auth ties identity and store together: password hashing,
// credential verification, persisted brute-force backoff, and trusted-proxy
// aware client IP resolution, shared identically by LDAP bind and OIDC/web
// login.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are OWASP-minimum-recommended.
type Argon2Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2Params is ~20-50ms per hash on typical hardware, comfortably
// inside the <1s login SLO.
var DefaultArgon2Params = Argon2Params{
	Memory:      19 * 1024,
	Iterations:  2,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

// Hasher hashes and verifies passwords using Argon2id.
type Hasher struct {
	Params Argon2Params
}

// Hash returns a PHC-formatted argon2id hash string.
func (h *Hasher) Hash(password string) (string, error) {
	salt := make([]byte, h.Params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, h.Params.Iterations, h.Params.Memory, h.Params.Parallelism, h.Params.KeyLength)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.Params.Memory, h.Params.Iterations, h.Params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// Verify checks password against an encoded hash using a constant-time
// comparison, resistant to timing side-channels.
func (h *Hasher) Verify(password, encoded string) (bool, error) {
	params, salt, key, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}
	candidate := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(key)))
	return subtle.ConstantTimeCompare(candidate, key) == 1, nil
}

// ValidHashFormat reports whether encoded is a well-formed PHC argon2id
// hash string (the same format Hash produces) -- checked structurally,
// without verifying any password against it. Used to fail loudly at
// config-load time on a malformed declaratively-supplied hash (see
// config.UserSpec.PasswordHash/PasswordHashFile), rather than only
// discovering it's broken the first time someone tries to log in.
func ValidHashFormat(encoded string) bool {
	_, _, _, err := decodeHash(encoded)
	return err == nil
}

func decodeHash(encoded string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Argon2Params{}, nil, nil, fmt.Errorf("invalid encoded hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Argon2Params{}, nil, nil, err
	}
	var p Argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return Argon2Params{}, nil, nil, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Argon2Params{}, nil, nil, err
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Argon2Params{}, nil, nil, err
	}
	return p, salt, key, nil
}
