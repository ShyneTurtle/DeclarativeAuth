package oidcserver

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// AuthCode is a short-lived authorization code minted at /authorize and
// redeemed exactly once at /token. Kept in-memory: auth-code lifetime is
// minutes, so single-replica-safe by default; a DB-backed implementation is
// a documented option for multi-replica HA (see internal/oidcserver docs).
type AuthCode struct {
	Code                string
	ClientID            string
	Username            string
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	Used                bool
}

// CodeStore is an in-memory, mutex-guarded store of pending authorization codes.
type CodeStore struct {
	mu    sync.Mutex
	codes map[string]*AuthCode
}

// NewCodeStore constructs an empty CodeStore.
func NewCodeStore() *CodeStore {
	return &CodeStore{codes: map[string]*AuthCode{}}
}

// Issue mints and stores a new authorization code, returning it.
func (s *CodeStore) Issue(ac AuthCode) (string, error) {
	code, err := randomToken(32)
	if err != nil {
		return "", err
	}
	ac.Code = code
	ac.ExpiresAt = time.Now().Add(2 * time.Minute)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code] = &ac
	return code, nil
}

// Redeem validates and consumes a code (single-use, unexpired). Returns nil
// if the code is invalid/expired/already used.
func (s *CodeStore) Redeem(code string) *AuthCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, ok := s.codes[code]
	if !ok || ac.Used || time.Now().After(ac.ExpiresAt) {
		return nil
	}
	ac.Used = true
	delete(s.codes, code)
	return ac
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
