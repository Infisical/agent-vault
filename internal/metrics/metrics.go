// Package metrics exposes a Prometheus /metrics endpoint for Agent Vault.
// Collection is opt-in via AGENT_VAULT_METRICS_ENABLED — when disabled, no
// collectors are registered and the proxy hot path does no extra work.
package metrics

import (
	"context"
	"net/http"
	"os"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/Infisical/agent-vault/internal/requestlog"
)

// EnabledFromEnv reports whether AGENT_VAULT_METRICS_ENABLED is set to a
// truthy value (e.g. "true", "1"). Defaults to disabled.
func EnabledFromEnv() bool {
	b, err := strconv.ParseBool(os.Getenv("AGENT_VAULT_METRICS_ENABLED"))
	return err == nil && b
}

// ProposalCounter is the subset of store.Store that the proposals gauge
// needs. Declared here instead of importing internal/store to keep this
// package's dependency surface minimal; store.Store satisfies it structurally.
type ProposalCounter interface {
	CountProposalsByStatus(ctx context.Context) (map[string]int, error)
}

// Metrics owns a dedicated Prometheus registry (never the global default
// registry) so that constructing multiple instances — e.g. once per test —
// never collides on duplicate registration.
type Metrics struct {
	registry *prometheus.Registry

	proxyRequestsTotal   *prometheus.CounterVec
	proxyRequestDuration *prometheus.HistogramVec
}

// New creates a Metrics instance with the proxy collectors registered. If
// proposals is non-nil, a live proposals-by-status gauge is also registered,
// queried directly from the store on every scrape rather than tracked via
// incremented counters — so it can never drift regardless of which code
// path transitioned a proposal's status.
func New(proposals ProposalCounter) *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		registry: reg,
		proxyRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "agent_vault_proxy_requests_total",
			Help: "Total proxied requests, labeled by matched service name and response status code.",
		}, []string{"service", "status"}),
		proxyRequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "agent_vault_proxy_request_duration_seconds",
			Help:    "Latency of proxied requests in seconds, labeled by matched service name.",
			Buckets: prometheus.DefBuckets,
		}, []string{"service"}),
	}

	reg.MustRegister(m.proxyRequestsTotal, m.proxyRequestDuration)
	if proposals != nil {
		reg.MustRegister(newProposalsCollector(proposals))
	}

	return m
}

// Handler returns an http.Handler serving this Metrics instance's registry
// in the standard Prometheus text exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Sink returns a requestlog.Sink that records proxy metrics from the same
// per-request Record the audit-log sink consumes. Stack it into a
// requestlog.MultiSink alongside the persistence sink — matches the
// package's documented pattern for adding sinks without touching the
// proxy hot path itself.
func (m *Metrics) Sink() requestlog.Sink {
	return proxySink{m: m}
}

type proxySink struct{ m *Metrics }

// Record implements requestlog.Sink. Must not block meaningfully — Counter
// and Histogram observations are in-memory and effectively instant.
func (s proxySink) Record(_ context.Context, r requestlog.Record) {
	service := r.MatchedService
	if service == "" {
		service = "unmatched"
	}
	s.m.proxyRequestsTotal.WithLabelValues(service, strconv.Itoa(r.Status)).Inc()
	s.m.proxyRequestDuration.WithLabelValues(service).Observe(float64(r.LatencyMs) / 1000)
}
