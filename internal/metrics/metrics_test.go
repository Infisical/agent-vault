package metrics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
