// Package tls loads and hot-rotates the certificate used to terminate
// HTTPS and LDAPS, with a self-signed dev fallback. Both listeners share one
// certificate pair by default (Section 9b of the project plan).
package tls

import (
	"crypto/tls"
	"fmt"
	"sync/atomic"
)

// Source serves the current certificate via GetCertificate, so rotation
// (Watcher) never requires rebuilding a listener's tls.Config.
type Source struct {
	cert atomic.Pointer[tls.Certificate]
}

// NewSource loads an initial cert/key pair from disk.
func NewSource(certFile, keyFile string) (*Source, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading TLS cert/key: %w", err)
	}
	s := &Source{}
	s.cert.Store(&cert)
	return s, nil
}

// NewSelfSignedSource generates and serves an ephemeral, dev-only cert.
func NewSelfSignedSource() (*Source, error) {
	cert, err := generateSelfSigned()
	if err != nil {
		return nil, err
	}
	s := &Source{}
	s.cert.Store(cert)
	return s, nil
}

// GetCertificate implements tls.Config.GetCertificate.
func (s *Source) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.cert.Load(), nil
}

// Reload re-reads the cert/key pair from disk and atomically swaps it in.
// On failure, the previous cert keeps serving (mirrors the identity-config
// reload safety model).
func (s *Source) Reload(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	s.cert.Store(&cert)
	return nil
}

// Config builds a *tls.Config backed by this Source.
func (s *Source) Config(minVersion uint16) *tls.Config {
	if minVersion == 0 {
		minVersion = tls.VersionTLS12
	}
	return &tls.Config{
		GetCertificate: s.GetCertificate,
		MinVersion:     minVersion,
	}
}
