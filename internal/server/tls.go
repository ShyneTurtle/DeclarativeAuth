package server

import (
	"context"
	stdtls "crypto/tls"
	"log/slog"
	"net"
	"path/filepath"

	"declarativeauth/internal/config"
	dtls "declarativeauth/internal/tls"
)

// buildTLSConfig resolves the effective cert/key source for a listener: nil
// (no TLS, reverse-proxy-termination mode, Section 9b) if the listener
// disables TLS; a listener-specific cert/key pair if set; the shared
// top-level cert/key pair; or an ephemeral self-signed dev cert as a last
// resort. When file-backed, a hot-rotation watcher goroutine is started,
// stopping when ctx is cancelled.
func buildTLSConfig(ctx context.Context, top config.TLSConfig, listener config.TLSListenerConfig, logger *slog.Logger) (*stdtls.Config, error) {
	if !listener.Enabled {
		return nil, nil // reverse-proxy-TLS-termination mode
	}

	certFile, keyFile := listener.CertFile, listener.KeyFile
	if certFile == "" {
		certFile = top.CertFile
	}
	if keyFile == "" {
		keyFile = top.KeyFile
	}

	var src *dtls.Source
	var err error
	if certFile == "" || keyFile == "" {
		if logger != nil {
			logger.Warn("self-signed certificate in use, not for production", "component", "tls")
		}
		src, err = dtls.NewSelfSignedSource()
	} else {
		src, err = dtls.NewSource(certFile, keyFile)
		if err == nil {
			dir := filepath.Dir(certFile)
			stop := make(chan struct{})
			go func() {
				<-ctx.Done()
				close(stop)
			}()
			go func() { _ = src.WatchAndReload(dir, certFile, keyFile, logger, stop) }()
		}
	}
	if err != nil {
		return nil, err
	}
	return src.Config(parseMinVersion(top.MinVersion)), nil
}

// parseMinVersion maps the config's tls.minVersion string ("1.2" or "1.3")
// to the crypto/tls constant; unset/unrecognized values return 0, which
// Source.Config treats as its own default (TLS 1.2).
func parseMinVersion(v string) uint16 {
	switch v {
	case "1.3":
		return stdtls.VersionTLS13
	case "1.2":
		return stdtls.VersionTLS12
	default:
		return 0
	}
}

func listenLDAP(addr string, tlsConfig *stdtls.Config) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if tlsConfig != nil {
		return stdtls.NewListener(ln, tlsConfig), nil
	}
	return ln, nil
}
