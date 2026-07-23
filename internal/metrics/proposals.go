package metrics

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
)

// proposalStatuses lists every lifecycle status a proposal can be in
// (proposal.Status), so the gauge always reports all four series — even
// series with a current count of zero — rather than only whichever
// statuses happen to have rows right now.
var proposalStatuses = []string{"pending", "applied", "rejected", "expired"}

// proposalsCollector queries ProposalCounter live on every scrape instead of
// tracking a running total, so it reflects the proposals table exactly
// regardless of which code path (approve, reject, expiry sweep) moved a
// proposal between statuses.
type proposalsCollector struct {
	counter ProposalCounter
	desc    *prometheus.Desc
}

func newProposalsCollector(counter ProposalCounter) *proposalsCollector {
	return &proposalsCollector{
		counter: counter,
		desc: prometheus.NewDesc(
			"agent_vault_proposals",
			"Current number of proposals in each lifecycle status, across all vaults.",
			[]string{"status"}, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *proposalsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

// Collect implements prometheus.Collector. A query failure is logged and
// skipped for this scrape rather than surfaced as a scrape error, so a
// transient store issue doesn't take down the whole /metrics response.
func (c *proposalsCollector) Collect(ch chan<- prometheus.Metric) {
	counts, err := c.counter.CountProposalsByStatus(context.Background())
	if err != nil {
		slog.Warn("metrics: failed to collect proposal counts", slog.String("error", err.Error())) //nolint:gosec // G706: structured slog attrs, handlers quote control chars
		return
	}
	for _, status := range proposalStatuses {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, float64(counts[status]), status)
	}
}
