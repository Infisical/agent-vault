package metrics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/requestlog"
)

func TestEnabledFromEnv(t *testing.T) {
	cases := map[string]bool{
		"":      false,
		"false": false,
		"0":     false,
		"bogus": false,
		"true":  true,
		"1":     true,
	}
	for v, want := range cases {
		t.Setenv("AGENT_VAULT_METRICS_ENABLED", v)
		if got := EnabledFromEnv(); got != want {
			t.Errorf("EnabledFromEnv() with %q = %v, want %v", v, got, want)
		}
	}
}

type fakeProposalCounter struct {
	counts map[string]int
	err    error
}

func (f fakeProposalCounter) CountProposalsByStatus(context.Context) (map[string]int, error) {
	return f.counts, f.err
}

func TestMetrics_ProxySinkRecordsRequests(t *testing.T) {
	m := New(nil)
	sink := m.Sink()

	sink.Record(context.Background(), requestlog.Record{MatchedService: "stripe", Status: 200, LatencyMs: 42})
	sink.Record(context.Background(), requestlog.Record{MatchedService: "stripe", Status: 500, LatencyMs: 10})
	sink.Record(context.Background(), requestlog.Record{MatchedService: "", Status: 403, LatencyMs: 1})

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := rec.Body.String()
	if !strings.Contains(body, `agent_vault_proxy_requests_total{service="stripe",status="200"} 1`) {
		t.Errorf("expected stripe/200 counter, got:\n%s", body)
	}
	if !strings.Contains(body, `agent_vault_proxy_requests_total{service="stripe",status="500"} 1`) {
		t.Errorf("expected stripe/500 counter, got:\n%s", body)
	}
	if !strings.Contains(body, `agent_vault_proxy_requests_total{service="unmatched",status="403"} 1`) {
		t.Errorf("expected unmatched/403 counter (empty MatchedService relabeled), got:\n%s", body)
	}
	if !strings.Contains(body, "agent_vault_proxy_request_duration_seconds") {
		t.Errorf("expected duration histogram to be present, got:\n%s", body)
	}
}

func TestMetrics_ProposalsGaugeOmittedWhenNilCounter(t *testing.T) {
	m := New(nil)

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if strings.Contains(rec.Body.String(), "agent_vault_proposals") {
		t.Errorf("expected no proposals gauge when constructed with a nil counter, got:\n%s", rec.Body.String())
	}
}

func TestMetrics_ProposalsGaugeReportsAllStatuses(t *testing.T) {
	m := New(fakeProposalCounter{counts: map[string]int{"pending": 3, "applied": 5}})

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := rec.Body.String()
	for _, want := range []string{
		`agent_vault_proposals{status="pending"} 3`,
		`agent_vault_proposals{status="applied"} 5`,
		// Statuses absent from the store's result map must still be
		// reported as zero, not omitted, so dashboards don't show gaps.
		`agent_vault_proposals{status="rejected"} 0`,
		`agent_vault_proposals{status="expired"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in body, got:\n%s", want, body)
		}
	}
}

// countingProposalCounter records how many times CountProposalsByStatus is
// actually invoked, and can optionally block until released — used to prove
// concurrent scrapes serialize on one in-flight query rather than each
// hammering the store, and that a slow query is bounded by a timeout.
type countingProposalCounter struct {
	calls   atomic.Int32
	counts  map[string]int
	err     error
	release chan struct{} // if non-nil, CountProposalsByStatus blocks until closed or ctx is done
}

func (f *countingProposalCounter) CountProposalsByStatus(ctx context.Context) (map[string]int, error) {
	f.calls.Add(1)
	if f.release != nil {
		select {
		case <-f.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.counts, f.err
}

func TestProposalsCollector_CachesWithinTTL(t *testing.T) {
	counter := &countingProposalCounter{counts: map[string]int{"pending": 1}}
	c := newProposalsCollector(counter)

	for i := 0; i < 5; i++ {
		if _, ok := c.counts(); !ok {
			t.Fatal("expected counts() to succeed")
		}
	}

	if got := counter.calls.Load(); got != 1 {
		t.Fatalf("expected the store to be queried once within the cache TTL, got %d calls", got)
	}
}

// TestProposalsCollector_ConcurrentScrapesShareOneQuery is the regression
// test for the Greptile-flagged issue: GET /metrics is unauthenticated, so
// without caching, a flood of concurrent scrapes would each open their own
// CountProposalsByStatus query and could exhaust the database connection
// pool. With the mutex-guarded cache, concurrent callers serialize on one
// in-flight query and share its result.
func TestProposalsCollector_ConcurrentScrapesShareOneQuery(t *testing.T) {
	counter := &countingProposalCounter{counts: map[string]int{"pending": 1}, release: make(chan struct{})}
	c := newProposalsCollector(counter)

	const concurrency = 20
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := c.counts(); !ok {
				t.Error("expected counts() to succeed")
			}
		}()
	}

	// Give every goroutine a chance to reach the query before releasing it.
	time.Sleep(50 * time.Millisecond)
	close(counter.release)
	wg.Wait()

	if got := counter.calls.Load(); got != 1 {
		t.Fatalf("expected exactly one underlying query for %d concurrent scrapes, got %d", concurrency, got)
	}
}

func TestProposalsCollector_QueryTimesOutRatherThanBlockingForever(t *testing.T) {
	counter := &countingProposalCounter{counts: map[string]int{"pending": 1}, release: make(chan struct{})}
	// Never release — the query must give up on its own via the timeout.
	c := newProposalsCollector(counter)

	done := make(chan struct{})
	go func() {
		c.counts()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(proposalsQueryTimeout + 2*time.Second):
		t.Fatal("expected counts() to give up once the query timeout elapsed, but it kept blocking")
	}
}

func TestMetrics_ProposalsGaugeSkipsOnStoreError(t *testing.T) {
	m := New(fakeProposalCounter{err: errors.New("db unavailable")})

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	// A failed proposals query must not break the rest of the scrape.
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 even when the proposals collector errors, got %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "agent_vault_proposals{") {
		t.Errorf("expected proposals series to be skipped on store error, got:\n%s", rec.Body.String())
	}
}
