package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/metrics"
	"github.com/Infisical/agent-vault/internal/requestlog"
)

func TestHandleMetrics_NotFoundWhenUnattached(t *testing.T) {
	srv := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when metrics are not attached, got %d", rec.Code)
	}
}

func TestHandleMetrics_ServesPrometheusFormatWhenAttached(t *testing.T) {
	srv := newTestServer()
	m := metrics.New(nil)
	srv.AttachMetrics(m)

	// A CounterVec with no observations yet emits no series at all — record
	// one via the sink first, the same hot path attachMetricsIfEnabled wires
	// up in cmd/server.go.
	m.Sink().Record(context.Background(), requestlog.Record{MatchedService: "stripe", Status: 200})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "agent_vault_proxy_requests_total") {
		t.Fatalf("expected proxy request counter metric family, got:\n%s", rec.Body.String())
	}
}

// countingProposalStore satisfies metrics.ProposalCounter for the purpose of
// this test without pulling in a full store.Store implementation.
type countingProposalStore struct{ counts map[string]int }

func (c countingProposalStore) CountProposalsByStatus(context.Context) (map[string]int, error) {
	return c.counts, nil
}

func TestHandleMetrics_ReportsLiveProposalCounts(t *testing.T) {
	srv := newTestServer()
	srv.AttachMetrics(metrics.New(countingProposalStore{counts: map[string]int{"pending": 2}}))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), `agent_vault_proposals{status="pending"} 2`) {
		t.Fatalf("expected pending proposal gauge, got:\n%s", rec.Body.String())
	}
}
