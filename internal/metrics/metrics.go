// Package metrics defines and exposes the Prometheus metric set described
// in the project plan: login latency/outcome (the <1s login SLO), LDAP
// bind/search counts, config reload observability, lockouts, SMTP,
// Postgres pool health, and TLS certificate expiry.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Registry bundles all DeclarativeAuth metrics behind a single Prometheus
// registry, separate from the default global registry so /metrics output is
// deterministic and test-isolated.
type Registry struct {
	Registerer prometheus.Registerer
	Gatherer   prometheus.Gatherer

	LoginAttemptsTotal   *prometheus.CounterVec
	LoginDurationSeconds *prometheus.HistogramVec
	ActiveSessions       prometheus.Gauge
	LDAPBindsTotal       *prometheus.CounterVec
	LDAPSearchesTotal    prometheus.Counter
	ConfigReloadTotal    *prometheus.CounterVec
	ConfigReloadDuration prometheus.Histogram
	ConfigReloadChanges  *prometheus.CounterVec
	LoginLockoutsTotal   *prometheus.CounterVec
	SMTPSendTotal        *prometheus.CounterVec
	SMTPTestTotal        *prometheus.CounterVec
	DBPoolAcquireSeconds prometheus.Histogram
	DBPoolConnections    *prometheus.GaugeVec
	TLSCertExpiry        *prometheus.GaugeVec
}

// New builds a Registry with all metrics registered.
func New() *Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	r := &Registry{
		Registerer: reg,
		Gatherer:   reg,

		LoginAttemptsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "declarativeauth_login_attempts_total",
			Help: "Login attempts by protocol and result.",
		}, []string{"protocol", "result"}),

		LoginDurationSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "declarativeauth_login_duration_seconds",
			Help:    "Login latency, directly measuring the <1s login SLO.",
			Buckets: prometheus.DefBuckets,
		}, []string{"protocol"}),

		ActiveSessions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "declarativeauth_active_sessions",
			Help: "Number of active (non-revoked, non-expired) sessions.",
		}),

		LDAPBindsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "declarativeauth_ldap_binds_total",
			Help: "LDAP bind attempts by result.",
		}, []string{"result"}),

		LDAPSearchesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "declarativeauth_ldap_searches_total",
			Help: "Total LDAP search requests.",
		}),

		ConfigReloadTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "declarativeauth_config_reload_total",
			Help: "Declarative config reload attempts by result.",
		}, []string{"result"}),

		ConfigReloadDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "declarativeauth_config_reload_duration_seconds",
			Help: "Time to parse+validate+resolve a config reload.",
		}),

		ConfigReloadChanges: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "declarativeauth_config_reload_changes_total",
			Help: "Entities added/removed/modified per reload, by type.",
		}, []string{"type"}),

		LoginLockoutsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "declarativeauth_login_lockouts_total",
			Help: "Brute-force backoff activations by dimension.",
		}, []string{"dimension"}),

		SMTPSendTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "declarativeauth_smtp_send_total",
			Help: "Outbound emails by purpose and result.",
		}, []string{"purpose", "result"}),

		SMTPTestTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "declarativeauth_smtp_test_total",
			Help: "Admin-triggered SMTP test sends by result.",
		}, []string{"result"}),

		DBPoolAcquireSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "declarativeauth_db_pool_acquire_duration_seconds",
			Help: "Time to acquire a Postgres connection from the pool.",
		}),

		DBPoolConnections: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "declarativeauth_db_pool_connections",
			Help: "Postgres pool connections by state.",
		}, []string{"state"}),

		TLSCertExpiry: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "declarativeauth_tls_cert_expiry_timestamp_seconds",
			Help: "Unix timestamp of the currently loaded certificate's NotAfter, by listener.",
		}, []string{"listener"}),
	}

	reg.MustRegister(
		r.LoginAttemptsTotal, r.LoginDurationSeconds, r.ActiveSessions,
		r.LDAPBindsTotal, r.LDAPSearchesTotal,
		r.ConfigReloadTotal, r.ConfigReloadDuration, r.ConfigReloadChanges,
		r.LoginLockoutsTotal, r.SMTPSendTotal, r.SMTPTestTotal,
		r.DBPoolAcquireSeconds, r.DBPoolConnections, r.TLSCertExpiry,
	)
	return r
}

// Handler returns the /metrics HTTP handler for this registry.
func (r *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(r.Gatherer, promhttp.HandlerOpts{})
}
