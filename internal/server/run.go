// Package server composes the top-level process: it owns the LDAP listener
// and the HTTP mux (OIDC + web + admin + metrics) and coordinates graceful
// shutdown.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"declarativeauth/internal/admin"
	"declarativeauth/internal/auth"
	"declarativeauth/internal/config"
	"declarativeauth/internal/ldapserver"
	"declarativeauth/internal/mail"
	"declarativeauth/internal/metrics"
	"declarativeauth/internal/oidcserver"
	"declarativeauth/internal/store"
	"declarativeauth/internal/web"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/errgroup"
)

// Run starts all configured listeners and blocks until ctx is cancelled
// (e.g. on SIGTERM/SIGINT), then shuts them down gracefully.
//
// This is intentionally additive across build phases: each phase (LDAP,
// OIDC/web, metrics, TLS, admin) adds its listener here without reworking
// this seam.
func Run(ctx context.Context, cfg *config.ServerConfig, holder *config.SnapshotHolder, pool *pgxpool.Pool, logger *slog.Logger, reg *metrics.Registry) error {
	warnInsecureConfig(cfg, logger)

	trustedCIDRs := append([]string{}, cfg.Network.TrustedProxies...)
	if cfg.Network.TrustsDefaultGateway() {
		if gw, err := auth.DefaultGatewayIP(); err == nil {
			trustedCIDRs = append(trustedCIDRs, gw.String()+"/32")
			logger.Info("trusting default gateway for forwarded headers", "component", "network", "gateway", gw.String())
		} else {
			logger.Debug("could not determine default gateway, "+config.EnvNetworkTrustDefaultGateway+" has no effect", "component", "network", "error", err)
		}
	}
	trustedProxies, err := auth.NewTrustedProxies(trustedCIDRs)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", config.EnvNetworkTrustedProxies, err)
	}

	// Each dimension defaults to disabled (DECLARATIVEAUTH_RATE_LIMIT_THRESHOLD
	// / _IP_THRESHOLD <= 0) and is independently configurable: a hard
	// lockout is itself a denial-of-service lever (the account dimension
	// against one known username, the IP dimension against every user
	// sharing a NAT/VPN/CGNAT egress IP), so operators opt in to whichever
	// dimension(s) fit their deployment rather than getting either by
	// default. When both are disabled, skip constructing the limiter
	// entirely (not just neutering its decisions) so a fully-disabled
	// feature doesn't still cost a Postgres round-trip on every
	// login/reset attempt -- Authenticate and handleResetSubmit both
	// already treat a nil RateLimiter as "unthrottled". When only one
	// dimension is enabled, RateLimiter itself skips the disabled one.
	var loginRateLimiter, resetRateLimiter, oidcTokenRateLimiter *auth.RateLimiter
	if cfg.RateLimit.Threshold > 0 || cfg.RateLimit.IPThreshold > 0 {
		lockouts := &store.LockoutStore{Pool: pool}
		userParams := auth.ParamsFromConfig(
			cfg.RateLimit.Threshold,
			cfg.RateLimit.BackoffBase.Std(),
			cfg.RateLimit.BackoffMax.Std(),
			cfg.RateLimit.Window.Std(),
		)
		ipParams := auth.ParamsFromConfig(
			cfg.RateLimit.IPThreshold,
			cfg.RateLimit.IPBackoffBase.Std(),
			cfg.RateLimit.IPBackoffMax.Std(),
			cfg.RateLimit.IPWindow.Std(),
		)
		loginRateLimiter = &auth.RateLimiter{Lockouts: lockouts, Params: userParams, IPParams: ipParams}
		// Same store and thresholds as login, but namespaced (KeyPrefix) so
		// password-reset spam and login brute-forcing don't share a budget
		// -- see auth.RateLimiter.KeyPrefix and web.ResetHandlers.RateLimiter.
		resetRateLimiter = &auth.RateLimiter{Lockouts: lockouts, Params: userParams, IPParams: ipParams, KeyPrefix: "reset:"}
		// Throttles /token (client_id + source IP), namespaced the same way
		// -- see oidcserver.Provider.RateLimiter.
		oidcTokenRateLimiter = &auth.RateLimiter{Lockouts: lockouts, Params: userParams, IPParams: ipParams, KeyPrefix: "oidc-token:"}
	}

	sessionStore := &store.SessionStore{Pool: pool}
	authenticator := &auth.Authenticator{
		Snapshot:    holder.Get,
		Credentials: &store.CredentialStore{Pool: pool},
		Hasher:      &auth.Hasher{Params: auth.DefaultArgon2Params},
		RateLimiter: loginRateLimiter,
		Logger:      logger,
	}
	auditStore := &store.AuditStore{Pool: pool}
	hasher := &auth.Hasher{Params: auth.DefaultArgon2Params}

	mailClient := &mail.Client{Config: mail.Config{
		Host: cfg.SMTP.Host, Port: cfg.SMTP.Port,
		Username: cfg.SMTP.Username, Password: cfg.SMTP.Password, From: cfg.SMTP.From,
		HeloDomain:  cfg.SMTP.HeloDomain,
		ImplicitTLS: cfg.SMTP.ImplicitTLS, Timeout: cfg.SMTP.Timeout.Std(),
		InsecureSkipVerify: cfg.SMTP.InsecureSkipVerify,
	}}

	g, gctx := errgroup.WithContext(ctx)

	if cfg.LDAP.ListenAddr != "" || cfg.LDAP.SecureListenAddr != "" {
		ldapHandler := &ldapserver.Handler{
			Config: ldapserver.Config{
				BaseDN:             cfg.LDAP.BaseDN,
				AllowAnonymousBind: cfg.LDAP.AllowAnonymousBind,
				RequireTLS:         cfg.LDAP.RequireTLS,
			},
			Snapshot:      holder.Get,
			Authenticator: authenticator,
			TrustedProxy:  trustedProxies,
			Logger:        logger,
			OnBind: func(username string, success bool, sourceIP, reason string) {
				eventType := "ldap_bind_failure"
				result := "failure"
				if success {
					eventType = "ldap_bind_success"
					result = "success"
				}
				if reg != nil {
					reg.LDAPBindsTotal.WithLabelValues(result).Inc()
					reg.LoginAttemptsTotal.WithLabelValues("ldap", result).Inc()
				}
				if err := auditStore.Write(context.Background(), store.AuditEvent{
					Username: username, EventType: eventType, SourceIP: net.ParseIP(sourceIP), Detail: reason,
				}); err != nil {
					logger.Error("audit write failed", "component", "ldapserver", "event_type", eventType, "error", err)
				}
			},
			OnSearch: func(sourceIP string) {
				if reg != nil {
					reg.LDAPSearchesTotal.Inc()
				}
			},
		}
		// The plaintext and secure LDAP listeners get separate *Server
		// values (sharing the same Handler) because they need different
		// TLSConfig behavior: the plaintext listener's TLSConfig is what it
		// offers to a StartTLS request mid-connection, while the secure
		// listener is already TLS-terminated at accept time (via
		// listenLDAP below) and must never additionally offer StartTLS.
		if cfg.LDAP.ListenAddr != "" {
			// Resolved the same way as any other secure listener's
			// cert/key (listener-specific override, then the shared
			// top-level pair, then a self-signed dev fallback) so
			// StartTLS "just works" on the plaintext port with no extra
			// configuration -- it's opt-in per connection, so plaintext
			// clients that never send StartTLS are entirely unaffected.
			startTLSConfig, err := buildTLSConfig(gctx, cfg.TLS, cfg.LDAP.TLS, logger)
			if err != nil {
				return fmt.Errorf("ldap StartTLS: %w", err)
			}
			ln, err := listenLDAP(cfg.LDAP.ListenAddr, nil)
			if err != nil {
				return fmt.Errorf("listening on ldap addr: %w", err)
			}
			plaintextSrv := &ldapserver.Server{Handler: ldapHandler, TLSConfig: startTLSConfig}
			addr := cfg.LDAP.ListenAddr
			g.Go(func() error {
				logger.Info("ldap listener started", "component", "ldapserver", "addr", addr, "tls", false, "starttls", true)
				return plaintextSrv.Serve(gctx, ln)
			})
		}
		if cfg.LDAP.SecureListenAddr != "" {
			tlsCfg, err := buildTLSConfig(gctx, cfg.TLS, cfg.LDAP.TLS, logger)
			if err != nil {
				return fmt.Errorf("ldap TLS: %w", err)
			}
			ln, err := listenLDAP(cfg.LDAP.SecureListenAddr, tlsCfg)
			if err != nil {
				return fmt.Errorf("listening on ldap secure addr: %w", err)
			}
			secureSrv := &ldapserver.Server{Handler: ldapHandler}
			addr := cfg.LDAP.SecureListenAddr
			g.Go(func() error {
				logger.Info("ldap listener started", "component", "ldapserver", "addr", addr, "tls", true)
				return secureSrv.Serve(gctx, ln)
			})
		}
	}

	if cfg.OIDC.ListenAddr != "" || cfg.OIDC.SecureListenAddr != "" {
		sessions := &web.SessionManager{
			Sessions: sessionStore,
			Secure:   cfg.OIDC.SecureListenAddr != "",
			Logger:   logger,
		}
		oidcKeys, err := oidcserver.NewKeyStore(gctx, pool, cfg.OIDC.SigningAlg, cfg.OIDC.KeyRotationInterval.Std(), cfg.OIDC.KeyOverlap.Std())
		if err != nil {
			return fmt.Errorf("initializing OIDC signing keys: %w", err)
		}
		oidcCodes := &store.OIDCCodeStore{Pool: pool}
		oidcRevocations := &store.RevokedTokenStore{Pool: pool}
		provider := oidcserver.NewProvider(cfg, oidcKeys, oidcCodes, sessionStore, oidcRevocations, holder.Get, sessions.CurrentUserWithAuthTime, logger, oidcTokenRateLimiter, trustedProxies)
		g.Go(func() error {
			return maintainOIDCState(gctx, oidcKeys, oidcCodes, oidcRevocations, cfg.OIDC.SigningAlg, cfg.OIDC.KeyRotationInterval.Std(), cfg.OIDC.KeyOverlap.Std(), logger)
		})
		mfaSettings := &store.UserMFASettingsStore{Pool: pool}
		mfaChallenges := &store.EmailChallengeStore{Pool: pool}
		mfaPolicy := &auth.MFAPolicy{Snapshot: holder.Get, Settings: mfaSettings}
		webHandlers := &web.Handlers{
			Authenticator:  authenticator,
			Sessions:       sessions,
			TrustedProxies: trustedProxies,
			Audit:          auditStore,
			Snapshot:       holder.Get,
			AdminGroup:     cfg.AdminUI.AdminGroup,
			MFAPolicy:      mfaPolicy,
			MFAChallenges:  mfaChallenges,
			MFAMail:        mailClient,
			OnLoginResult: func(success bool, d time.Duration) {
				if reg == nil {
					return
				}
				result := "failure"
				if success {
					result = "success"
				}
				reg.LoginAttemptsTotal.WithLabelValues("oidc", result).Inc()
				reg.LoginDurationSeconds.WithLabelValues("oidc").Observe(d.Seconds())
			},
			Logger: logger,
		}

		webMux := webHandlers.NewMux()
		resetHandlers := &web.ResetHandlers{
			Tokens:   &store.ResetTokenStore{Pool: pool},
			Creds:    &store.CredentialStore{Pool: pool},
			Snapshot: holder.Get,
			Mail:     mailClient,
			Hasher:   hasher,
			Audit:    auditStore,
			Sessions: sessions,
			BaseURL:  cfg.OIDC.Issuer,
			Policy: auth.PasswordPolicy{
				MinLength:   cfg.PasswordPolicy.MinLength,
				MinStrength: cfg.PasswordPolicy.MinStrength,
			},
			Logger:      logger,
			RateLimiter: resetRateLimiter,
		}
		resetHandlers.RegisterRoutes(webMux, trustedProxies, sessions.CurrentUser, cfg.AdminUI.AdminGroup)

		mfaHandlers := &web.MFAHandlers{
			Snapshot:       holder.Get,
			Settings:       mfaSettings,
			Challenges:     mfaChallenges,
			Mail:           mailClient,
			Sessions:       sessions,
			TrustedProxies: trustedProxies,
			Audit:          auditStore,
			Logger:         logger,
		}
		mfaHandlers.RegisterRoutes(webMux)

		if cfg.WebAuthn.Enabled {
			if cfg.WebAuthn.RPID == "" || len(cfg.WebAuthn.RPOrigins) == 0 {
				logger.Warn("webauthn enabled but RP ID/origins could not be determined (set "+config.EnvOIDCIssuer+" or "+config.EnvWebAuthnRPID+"/"+config.EnvWebAuthnRPOrigins+"); passkeys disabled", "component", "webauthn")
			} else if wa, err := webauthn.New(&webauthn.Config{
				RPID:          cfg.WebAuthn.RPID,
				RPDisplayName: cfg.WebAuthn.RPDisplayName,
				RPOrigins:     cfg.WebAuthn.RPOrigins,
			}); err != nil {
				logger.Warn("webauthn configuration invalid, passkeys disabled", "component", "webauthn", "error", err)
			} else {
				webauthnCredentials := &store.WebAuthnCredentialStore{Pool: pool}
				passkeyHandlers := &web.PasskeyHandlers{
					WebAuthn:       wa,
					Credentials:    webauthnCredentials,
					Ceremonies:     &store.WebAuthnCeremonyStore{Pool: pool},
					Snapshot:       holder.Get,
					Sessions:       sessions,
					TrustedProxies: trustedProxies,
					Audit:          auditStore,
					OnLoginResult: func(success bool, d time.Duration) {
						if reg == nil {
							return
						}
						result := "failure"
						if success {
							result = "success"
						}
						reg.LoginAttemptsTotal.WithLabelValues("passkey", result).Inc()
						reg.LoginDurationSeconds.WithLabelValues("passkey").Observe(d.Seconds())
					},
					Logger: logger,
				}
				passkeyHandlers.RegisterRoutes(webMux)
				webHandlers.Passkeys = webauthnCredentials
				logger.Info("webauthn passkeys enabled", "component", "webauthn", "rp_id", cfg.WebAuthn.RPID)
			}
		}

		if cfg.AdminUI.Enabled {
			adminHandlers := &admin.Handlers{
				Snapshot:            holder.Get,
				CurrentUser:         sessions.CurrentUser,
				AdminGroup:          cfg.AdminUI.AdminGroup,
				Mail:                mailClient,
				IdentityPath:        cfg.Identity.IdentityPath,
				ConfigEditorEnabled: cfg.AdminUI.ConfigEditor.Enabled,
				TrustedProxies:      trustedProxies,
				OnSMTPTest: func(success bool) {
					if reg == nil {
						return
					}
					result := "failure"
					if success {
						result = "success"
					}
					reg.SMTPTestTotal.WithLabelValues(result).Inc()
				},
				Logger: logger,
			}
			adminMux := adminHandlers.NewMux()
			webMux.Handle("/admin", adminMux)
			webMux.Handle("/admin/", adminMux)
		}

		mux := http.NewServeMux()
		mux.Handle("/", webMux)
		oidcMux := provider.NewMux()
		mux.Handle("/.well-known/", oidcMux)
		mux.Handle("/authorize", oidcMux)
		mux.Handle("/token", oidcMux)
		mux.Handle("/userinfo", oidcMux)
		mux.Handle("/revoke", oidcMux)
		mux.Handle("/introspect", oidcMux)
		mux.HandleFunc("/healthz", healthzHandler)
		mux.HandleFunc("/readyz", readyzHandler(pool))

		if cfg.OIDC.ListenAddr != "" {
			httpSrv := &http.Server{Addr: cfg.OIDC.ListenAddr, Handler: mux}
			addr := cfg.OIDC.ListenAddr
			g.Go(func() error {
				logger.Info("oidc/web listener started", "component", "oidcserver", "addr", addr, "tls", false)
				return serveHTTPUntilDone(gctx, httpSrv, false, logger)
			})
		}
		if cfg.OIDC.SecureListenAddr != "" {
			tlsCfg, err := buildTLSConfig(gctx, cfg.TLS, cfg.OIDC.TLS, logger)
			if err != nil {
				return fmt.Errorf("oidc TLS: %w", err)
			}
			httpSrv := &http.Server{Addr: cfg.OIDC.SecureListenAddr, Handler: mux, TLSConfig: tlsCfg}
			addr := cfg.OIDC.SecureListenAddr
			g.Go(func() error {
				logger.Info("oidc/web listener started", "component", "oidcserver", "addr", addr, "tls", true)
				return serveHTTPUntilDone(gctx, httpSrv, true, logger)
			})
		}
	}

	if cfg.Metrics.ListenAddr != "" && reg != nil {
		mux := http.NewServeMux()
		mux.Handle("/metrics", reg.Handler())
		metricsSrv := &http.Server{Addr: cfg.Metrics.ListenAddr, Handler: mux}
		g.Go(func() error {
			logger.Info("metrics listener started", "component", "metrics", "addr", cfg.Metrics.ListenAddr)
			return serveHTTPUntilDone(gctx, metricsSrv, false, logger)
		})

		g.Go(func() error { return reportActiveSessions(gctx, sessionStore, reg) })
	}

	return g.Wait()
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func readyzHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("db unavailable: " + err.Error()))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}

func serveHTTPUntilDone(ctx context.Context, srv *http.Server, useTLS bool, logger *slog.Logger) error {
	errCh := make(chan error, 1)
	go func() {
		var err error
		if useTLS {
			err = srv.ListenAndServeTLS("", "") // certs come from srv.TLSConfig.GetCertificate
		} else {
			err = srv.ListenAndServe()
		}
		errCh <- err
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "component", "server", "addr", srv.Addr, "error", err)
		}
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

// maintainOIDCState runs on every replica: it checks whether the shared
// signing key is due for rotation (safe to call concurrently -- see
// store.OIDCKeyStore.RotateIfDue, which serializes racing replicas via row
// locking), refreshing this replica's local key cache either way so a
// rotation performed by another replica is picked up promptly, and sweeps
// expired authorization codes so the table doesn't grow unbounded.
func maintainOIDCState(ctx context.Context, keys *oidcserver.KeyStore, codes *store.OIDCCodeStore, revocations *store.RevokedTokenStore, algorithm string, rotationInterval, overlap time.Duration, logger *slog.Logger) error {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if rotated, err := keys.RotateIfDue(ctx, algorithm, rotationInterval, overlap); err != nil {
				logger.Error("oidc signing key rotation failed", "component", "oidcserver", "error", err)
			} else if rotated {
				logger.Info("oidc signing key rotated", "component", "oidcserver")
			}
			if _, err := codes.DeleteExpired(ctx); err != nil {
				logger.Error("oidc authorization code cleanup failed", "component", "oidcserver", "error", err)
			}
			if _, err := revocations.DeleteExpired(ctx); err != nil {
				logger.Error("oidc revoked token cleanup failed", "component", "oidcserver", "error", err)
			}
		}
	}
}

func reportActiveSessions(ctx context.Context, sessions *store.SessionStore, reg *metrics.Registry) error {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if n, err := sessions.CountActive(ctx); err == nil {
				reg.ActiveSessions.Set(float64(n))
			}
		}
	}
}
