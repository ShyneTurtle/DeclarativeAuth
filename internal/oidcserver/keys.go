// Package oidcserver is a minimal, embedded OpenID Connect provider:
// authorization code flow with PKCE, ID tokens signed with an in-process
// ECDSA key, and a JWKS/discovery surface. Deliberately hand-rolled rather
// than built on a heavier OP framework, to keep the single-binary footprint
// small and avoid depending on a large, fast-moving Storage interface for a
// feature surface this small (one grant type, static clients).
package oidcserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"math/big"
)

// KeySet holds the provider's signing key. Generated fresh at process
// startup; not persisted or rotated across restarts in v1 (documented
// limitation — a restart invalidates outstanding ID tokens' verifiability
// against a *new* key ID, though already-issued tokens remain valid JWTs
// signed by the *old* key until they expire, they just won't be found in a
// freshly-restarted process's single-key JWKS).
type KeySet struct {
	Kid        string
	PrivateKey *ecdsa.PrivateKey
}

// NewKeySet generates a fresh P-256 signing key.
func NewKeySet() (*KeySet, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	kid := base64.RawURLEncoding.EncodeToString(randBytes(8))
	return &KeySet{Kid: kid, PrivateKey: key}, nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// JWK renders the public key as a JSON Web Key map, suitable for the JWKS
// endpoint.
func (k *KeySet) JWK() map[string]any {
	pub := k.PrivateKey.PublicKey
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"kid": k.Kid,
		"use": "sig",
		"alg": "ES256",
		"x":   base64.RawURLEncoding.EncodeToString(bigIntToBytes(pub.X, 32)),
		"y":   base64.RawURLEncoding.EncodeToString(bigIntToBytes(pub.Y, 32)),
	}
}

// bigIntToBytes left-pads a big.Int's bytes to a fixed width, required by the
// JWK spec for EC coordinates (P-256 coordinates must be exactly 32 bytes).
func bigIntToBytes(i *big.Int, size int) []byte {
	b := i.Bytes()
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
