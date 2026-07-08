package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"declarativeauth/internal/config"
)

// runHealthcheck hits this same process's own /readyz over loopback and
// exits 0/1 accordingly. It exists because the runtime image is distroless
// (no shell, no curl/wget), so Docker's HEALTHCHECK -- which can only exec a
// binary already in the image -- has nothing else to call; this doubles as
// that binary. /readyz (not /healthz) is used deliberately: it also pings
// Postgres, so a healthy status actually means "can serve logins", not just
// "process is alive".
func runHealthcheck(args []string) error {
	cfg, err := config.LoadServerConfigFromEnv()
	if err != nil {
		return err
	}

	// Prefer the secure listener when both are configured, since that's the
	// one an operator actually cares is healthy in a TLS deployment.
	addr, scheme, useTLS := cfg.OIDC.SecureListenAddr, "https", true
	if addr == "" {
		addr, scheme, useTLS = cfg.OIDC.ListenAddr, "http", false
	}
	if addr == "" {
		return fmt.Errorf("neither %s nor %s is set", config.EnvOIDCSecureListenAddr, config.EnvOIDCListenAddr)
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parsing OIDC listen addr: %w", err)
	}

	client := &http.Client{Timeout: 3 * time.Second}
	if useTLS {
		// Loopback self-check: the cert's SAN won't include "127.0.0.1" in
		// most deployments, and there's no attacker-in-the-middle position
		// between a process and itself, so skipping verification here is
		// safe and avoids needing the CA bundle at healthcheck time.
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	url := fmt.Sprintf("%s://127.0.0.1:%s/readyz", scheme, port)
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("readyz check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("readyz returned %d", resp.StatusCode)
	}
	return nil
}
