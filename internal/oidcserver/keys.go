package oidcserver

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"declarativeauth/internal/store"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SigningKey is a decoded, ready-to-use JWT signing key: an ES256 (P-256
// ECDSA) or RS256 (RSA) key.
type SigningKey struct {
	Kid       string
	Algorithm string
	Signer    crypto.Signer
}

// SigningMethod returns the jwt-go signing method matching this key's
// algorithm.
func (k SigningKey) SigningMethod() jwt.SigningMethod {
	if k.Algorithm == "RS256" {
		return jwt.SigningMethodRS256
	}
	return jwt.SigningMethodES256
}

// JWK renders the public key as a JSON Web Key map, suitable for the JWKS
// endpoint.
func (k SigningKey) JWK() (map[string]any, error) {
	switch pub := k.Signer.Public().(type) {
	case *ecdsa.PublicKey:
		return map[string]any{
			"kty": "EC", "crv": "P-256", "kid": k.Kid, "use": "sig", "alg": "ES256",
			"x": base64.RawURLEncoding.EncodeToString(bigIntToBytes(pub.X, 32)),
			"y": base64.RawURLEncoding.EncodeToString(bigIntToBytes(pub.Y, 32)),
		}, nil
	case *rsa.PublicKey:
		return map[string]any{
			"kty": "RSA", "kid": k.Kid, "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", pub)
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

// generateKey creates a fresh signing key for algorithm ("ES256" or
// "RS256") and PEM-encodes its PKCS8 private key for storage.
func generateKey(algorithm string) (SigningKey, string, error) {
	var signer crypto.Signer
	var err error
	switch algorithm {
	case "RS256":
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	case "ES256":
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return SigningKey{}, "", fmt.Errorf("unsupported signing algorithm %q", algorithm)
	}
	if err != nil {
		return SigningKey{}, "", err
	}
	kid := base64.RawURLEncoding.EncodeToString(randBytes(8))
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return SigningKey{}, "", err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return SigningKey{Kid: kid, Algorithm: algorithm, Signer: signer}, string(pemBytes), nil
}

// parseKey decodes a PEM/PKCS8-encoded private key back into a SigningKey.
func parseKey(kid, algorithm, pemStr string) (SigningKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return SigningKey{}, errors.New("invalid PEM block")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return SigningKey{}, err
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return SigningKey{}, fmt.Errorf("key type %T is not a signer", priv)
	}
	return SigningKey{Kid: kid, Algorithm: algorithm, Signer: signer}, nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func newDBKey(algorithm string) (store.OIDCSigningKey, error) {
	key, pemStr, err := generateKey(algorithm)
	if err != nil {
		return store.OIDCSigningKey{}, err
	}
	return store.OIDCSigningKey{Kid: key.Kid, Algorithm: key.Algorithm, PrivateKeyPEM: pemStr}, nil
}

// KeyStore is the Postgres-backed, replica-shared JWT signing key manager.
// It caches the active key set in memory so signing and verification don't
// hit the database on every request; a cache miss in Lookup falls through to
// a direct DB read once, to tolerate a key rotated by another replica
// slightly ahead of this one's next periodic Refresh.
type KeyStore struct {
	db *store.OIDCKeyStore

	mu      sync.RWMutex
	current SigningKey
	active  map[string]SigningKey
}

// NewKeyStore loads the signing key set for pool, bootstrapping it (and
// rotating an overdue key, including across a restart) if necessary.
func NewKeyStore(ctx context.Context, pool *pgxpool.Pool, algorithm string, rotationInterval, overlap time.Duration) (*KeyStore, error) {
	ks := &KeyStore{db: &store.OIDCKeyStore{Pool: pool}}
	if _, err := ks.db.RotateIfDue(ctx, rotationInterval, overlap, func() (store.OIDCSigningKey, error) {
		return newDBKey(algorithm)
	}); err != nil {
		return nil, err
	}
	if err := ks.Refresh(ctx); err != nil {
		return nil, err
	}
	return ks, nil
}

// Refresh reloads the active key set (current signer + any key still inside
// its retirement overlap window) from the database into the in-memory cache.
func (ks *KeyStore) Refresh(ctx context.Context) error {
	dbKeys, err := ks.db.Active(ctx)
	if err != nil {
		return err
	}
	active := make(map[string]SigningKey, len(dbKeys))
	var current SigningKey
	for _, dk := range dbKeys {
		k, err := parseKey(dk.Kid, dk.Algorithm, dk.PrivateKeyPEM)
		if err != nil {
			return fmt.Errorf("parsing signing key %s: %w", dk.Kid, err)
		}
		active[dk.Kid] = k
		if dk.IsCurrent {
			current = k
		}
	}
	ks.mu.Lock()
	ks.active = active
	ks.current = current
	ks.mu.Unlock()
	return nil
}

// RotateIfDue checks whether the current key is due for rotation and, if
// so, rotates it and refreshes the local cache. Safe to call from every
// replica on a shared ticker -- see store.OIDCKeyStore.RotateIfDue.
func (ks *KeyStore) RotateIfDue(ctx context.Context, algorithm string, interval, overlap time.Duration) (bool, error) {
	rotated, err := ks.db.RotateIfDue(ctx, interval, overlap, func() (store.OIDCSigningKey, error) {
		return newDBKey(algorithm)
	})
	if err != nil {
		return false, err
	}
	if err := ks.Refresh(ctx); err != nil {
		return rotated, err
	}
	return rotated, nil
}

// Current returns the active signing key.
func (ks *KeyStore) Current() SigningKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.current
}

// Lookup finds a key by kid among the cached active set, falling back to a
// direct database read on a cache miss (e.g. a key another replica just
// rotated in). Reports false for an unknown, or expired-past-overlap, kid.
func (ks *KeyStore) Lookup(ctx context.Context, kid string) (SigningKey, bool) {
	ks.mu.RLock()
	k, ok := ks.active[kid]
	ks.mu.RUnlock()
	if ok {
		return k, true
	}

	dk, err := ks.db.Lookup(ctx, kid)
	if err != nil {
		return SigningKey{}, false
	}
	if dk.RetireAt != nil && time.Now().After(*dk.RetireAt) {
		return SigningKey{}, false
	}
	parsed, err := parseKey(dk.Kid, dk.Algorithm, dk.PrivateKeyPEM)
	if err != nil {
		return SigningKey{}, false
	}
	return parsed, true
}

// JWKS renders every active key as a JSON Web Key, for the JWKS endpoint.
func (ks *KeyStore) JWKS() ([]map[string]any, error) {
	ks.mu.RLock()
	keys := make([]SigningKey, 0, len(ks.active))
	for _, k := range ks.active {
		keys = append(keys, k)
	}
	ks.mu.RUnlock()

	sort.Slice(keys, func(i, j int) bool { return keys[i].Kid < keys[j].Kid })
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		jwk, err := k.JWK()
		if err != nil {
			return nil, err
		}
		out = append(out, jwk)
	}
	return out, nil
}

// SupportedAlgorithms returns the distinct signing algorithms among the
// active key set, for the discovery document.
func (ks *KeyStore) SupportedAlgorithms() []string {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	seen := map[string]bool{}
	var out []string
	for _, k := range ks.active {
		if !seen[k.Algorithm] {
			seen[k.Algorithm] = true
			out = append(out, k.Algorithm)
		}
	}
	sort.Strings(out)
	return out
}
