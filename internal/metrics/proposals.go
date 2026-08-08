package metrics

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// proposalStatuses lists every lifecycle status a proposal can be in
// (proposal.Status), so the gauge always reports all four series — even
// series with a current count of zero — rather than only whichever
// statuses happen to have rows right now.
var proposalStatuses = []string{"pending", "applied", "rejected", "expired"}

const (
	// proposalsCacheTTL bounds how often a scrape actually queries the
	// store. GET /metrics is unauthenticated (like /health), so without
	// this, a flood of scrapes could open unbounded concurrent
	// CountProposalsByStatus queries and exhaust the database connection
	// pool. Caching also means concurrent scrapers block briefly on the
	// mutex below and then share one fresh result instead of each issuing
	// their own query.
	proposalsCacheTTL = 5 * time.Second
	// proposalsQueryTimeout caps how long a single query may hold the lock
	// (and a connection from the pool) before giving up, so a slow or
	// hanging database can't pin every scrape indefinitely.
	proposalsQueryTimeout = 3 * time.Second
)

// proposalsCollector queries ProposalCounter live on every scrape instead of
// tracking a running total, so it reflects the proposals table exactly
// regardless of which code path (approve, reject, expiry sweep) moved a
// proposal between statuses. Results are cached briefly (see
// proposalsCacheTTL) to bound load on the store.
type proposalsCollector struct {
	counter ProposalCounter
	desc    *prometheus.Desc

	mu       sync.Mutex
	cached   map[string]int
	cachedAt time.Time
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

// Collect implements prometheus.Collector. No series are emitted at all if
// a query has never succeeded (e.g. the very first scrape hits a store
// error), matching the pre-existing "skip on error" behavior rather than
// reporting misleading zeros.
func (c *proposalsCollector) Collect(ch chan<- prometheus.Metric) {
	counts, ok := c.counts()
	if !ok {
		return
	}
	for _, status := range proposalStatuses {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, float64(counts[status]), status)
	}
}

// counts returns the cached proposal counts, refreshing them from the store
// at most once per proposalsCacheTTL. Holding the mutex for the duration of
// a refresh means concurrent scrapes serialize on one in-flight query rather
// than each starting their own. A query failure is logged and the previous
// cached value (if any) is served rather than zeros, so a transient store
// issue doesn't take down the whole /metrics response or report a false
// dip; ok is false only when no successful query has ever completed.
func (c *proposalsCollector) counts() (_ map[string]int, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cached != nil && time.Since(c.cachedAt) < proposalsCacheTTL {
		return c.cached, true
	}

	ctx, cancel := context.WithTimeout(context.Background(), proposalsQueryTimeout)
	defer cancel()

	counts, err := c.counter.CountProposalsByStatus(ctx)
	if err != nil {
		slog.Warn("metrics: failed to collect proposal counts", slog.String("error", err.Error())) //nolint:gosec // G706: structured slog attrs, handlers quote control chars
		return c.cached, c.cached != nil
	}

	c.cached = counts
	c.cachedAt = time.Now()
	return c.cached, true
}
