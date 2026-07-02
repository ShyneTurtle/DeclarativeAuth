package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"declarativeauth/internal/config"
	"declarativeauth/internal/logging"
	"declarativeauth/internal/metrics"
	"declarativeauth/internal/server"
	"declarativeauth/internal/store"
)

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "/etc/declarativeauth/config/declarativeauth.yaml", "path to declarativeauth.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		return err
	}

	logger := logging.New(cfg.Logging.Level, cfg.Logging.Format)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := store.Open(ctx, cfg.Database.DSN, cfg.Database.MaxConns)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := store.Migrate(cfg.Database.DSN); err != nil {
		return err
	}
	logger.Info("migrations applied", "component", "store")

	metricsRegistry := metrics.New()

	holder := &config.SnapshotHolder{}
	watcher := &config.Watcher{
		IdentityPath: cfg.Config.IdentityPath,
		Debounce:     cfg.Config.ReloadDebounce.Std(),
		Holder:       holder,
		Logger:       logger,
	}
	watcher.SetMetrics(config.WatcherMetrics{
		ReloadSuccess: func() { metricsRegistry.ConfigReloadTotal.WithLabelValues("success").Inc() },
		ReloadFailure: func() { metricsRegistry.ConfigReloadTotal.WithLabelValues("failure").Inc() },
		ChangeCount: func(kind string, n int) {
			metricsRegistry.ConfigReloadChanges.WithLabelValues(kind).Add(float64(n))
		},
	})
	if err := watcher.LoadInitial(); err != nil {
		return err
	}

	stopWatch := make(chan struct{})
	go func() {
		if err := watcher.Run(stopWatch); err != nil {
			logger.Error("config watcher stopped", "component", "config", "error", err)
		}
	}()

	snap := holder.Get()
	logger.Info("declarativeauth ready",
		"component", "server",
		"users", len(snap.Users),
		"groups", len(snap.Groups),
		"ldap_addr", cfg.LDAP.ListenAddr,
		"oidc_addr", cfg.OIDC.ListenAddr,
		"metrics_addr", cfg.Metrics.ListenAddr,
	)

	if err := server.Run(ctx, cfg, holder, pool, logger, metricsRegistry); err != nil {
		close(stopWatch)
		return err
	}
	close(stopWatch)
	logger.Info("shutdown complete", "component", "server")
	return nil
}
