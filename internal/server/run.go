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
	"os"
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
	pepper := os.Getenv(auth.PepperEnvVar)
	if pepper == "" {
		return fmt.Errorf("%s is not set", auth.PepperEnvVar)
	}

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

	sessionStore := &store.SessionStore{Pool: pool}
	authenticator := &auth.Authenticator{
		Snapshot:    holder.Get,
		Credentials: &store.CredentialStore{Pool: pool},
		Hasher:      &auth.Hasher{Pepper: []byte(pepper), Params: auth.DefaultArgon2Params},
		RateLimiter: &auth.RateLimiter{
			Lockouts: &store.LockoutStore{Pool: pool},
			Params: auth.ParamsFromConfig(
				cfg.RateLimit.Threshold,
				cfg.RateLimit.BackoffBase.Std(),
				cfg.RateLimit.BackoffMax.Std(),
				cfg.RateLimit.Window.Std(),
			),
		},
		Logger: logger,
	}
	auditStore := &store.AuditStore{Pool: pool}
	hasher := &auth.Hasher{Pepper: []byte(pepper), Params: auth.DefaultArgon2Params}

	mailClient := &mail.Client{Config: mail.Config{
		Host: cfg.SMTP.Host, Port: cfg.SMTP.Port,
		Username: cfg.SMTP.Username, Password: cfg.SMTP.Password, From: cfg.SMTP.From,
		HeloDomain:  cfg.SMTP.HeloDomain,
		ImplicitTLS: cfg.SMTP.ImplicitTLS, Timeout: cfg.SMTP.Timeout.Std(),
		InsecureSkipVerify: cfg.SMTP.InsecureSkipVerify,
	}}

	g, gctx := errgroup.WithContext(ctx)

	if cfg.LDAP.ListenAddr != "" {
		tlsCfg, err := buildTLSConfig(gctx, cfg.TLS, cfg.LDAP.TLS, logger)
		if err != nil {
			return fmt.Errorf("ldap TLS: %w", err)
		}
		ln, err := listenLDAP(cfg.LDAP.ListenAddr, tlsCfg)
		if err != nil {
			return fmt.Errorf("listening on ldap addr: %w", err)
		}
		ldapHandler := &ldapserver.Handler{
			Config: ldapserver.Config{
				BaseDN:             cfg.LDAP.BaseDN,
				AllowAnonymousBind: cfg.LDAP.AllowAnonymousBind,
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
		ldapSrv := &ldapserver.Server{Handler: ldapHandler}
		g.Go(func() error {
			logger.Info("ldap listener started", "component", "ldapserver", "addr", cfg.LDAP.ListenAddr, "tls", tlsCfg != nil)
			return ldapSrv.Serve(gctx, ln)
		})
	}

	if cfg.OIDC.ListenAddr != "" {
		sessions := &web.SessionManager{
			Sessions: sessionStore,
			Secure:   cfg.OIDC.TLS.Enabled,
			Logger:   logger,
		}
		keys, err := oidcserver.NewKeySet()
		if err != nil {
			return fmt.Errorf("generating OIDC signing key: %w", err)
		}
		provider := oidcserver.NewProvider(cfg, keys, holder.Get, sessions.CurrentUser)
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
			Logger: logger,
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
		mux.HandleFunc("/healthz", healthzHandler)
		mux.HandleFunc("/readyz", readyzHandler(pool))

		tlsCfg, err := buildTLSConfig(gctx, cfg.TLS, cfg.OIDC.TLS, logger)
		if err != nil {
			return fmt.Errorf("oidc TLS: %w", err)
		}
		httpSrv := &http.Server{Addr: cfg.OIDC.ListenAddr, Handler: mux, TLSConfig: tlsCfg}
		g.Go(func() error {
			logger.Info("oidc/web listener started", "component", "oidcserver", "addr", cfg.OIDC.ListenAddr, "tls", tlsCfg != nil)
			return serveHTTPUntilDone(gctx, httpSrv, tlsCfg != nil, logger)
		})
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
