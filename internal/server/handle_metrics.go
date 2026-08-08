package server

import "net/http"

// handleMetrics serves the Prometheus text exposition format when metrics
// are enabled (AGENT_VAULT_METRICS_ENABLED=true, wired via AttachMetrics).
// Unauthenticated, like /health and /v1/status — opt-in and meant to be
// scraped from a trusted network, consistent with this server's other
// public observability routes.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.metrics == nil {
		http.NotFound(w, r)
		return
	}
	s.metrics.Handler().ServeHTTP(w, r)
}
