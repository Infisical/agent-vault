package server

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

const (
	logsDefaultLimit = 50
	logsMaxLimit     = 200
)

type logItem struct {
	ID             int64    `json:"id"`
	Ingress        string   `json:"ingress"`
	Method         string   `json:"method"`
	Host           string   `json:"host"`
	Path           string   `json:"path"`
	MatchedService string   `json:"matched_service"`
	CredentialKeys []string `json:"credential_keys"`
	Status         int      `json:"status"`
	LatencyMs      int64    `json:"latency_ms"`
	ErrorCode      string   `json:"error_code"`
	ActorType      string   `json:"actor_type"`
	ActorID        string   `json:"actor_id"`
	CreatedAt      string   `json:"created_at"`
}

func (s *Server) handleVaultLogsList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return
	}

	// Logs live alongside Proposals: member+ can read, proxy-only (agents)
	// cannot. Owner-scoped instance-wide logs will be a separate handler.
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	q := r.URL.Query()
	opts := store.ListRequestLogsOpts{
		VaultID:        &ns.ID,
		Ingress:        q.Get("ingress"),
		StatusBucket:   q.Get("status_bucket"),
		MatchedService: q.Get("service"),
	}

	if raw := q.Get("before"); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil && v > 0 {
			opts.Before = v
		}
	}
	if raw := q.Get("after"); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil && v > 0 {
			opts.After = v
		}
	}
	if opts.Before > 0 && opts.After > 0 {
		jsonError(w, http.StatusBadRequest, "before and after are mutually exclusive")
		return
	}

	limit := logsDefaultLimit
	if raw := q.Get("limit"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			limit = v
		}
	}
	if limit > logsMaxLimit {
		limit = logsMaxLimit
	}
	opts.Limit = limit

	rows, err := s.store.ListRequestLogs(ctx, opts)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list logs")
		return
	}

	items := make([]logItem, len(rows))
	var latestID int64
	for i, r := range rows {
		if i == 0 {
			latestID = r.ID
		}
		items[i] = logItem{
			ID:             r.ID,
			Ingress:        r.Ingress,
			Method:         r.Method,
			Host:           r.Host,
			Path:           r.Path,
			MatchedService: r.MatchedService,
			CredentialKeys: r.CredentialKeys,
			Status:         r.Status,
			LatencyMs:      r.LatencyMs,
			ErrorCode:      r.ErrorCode,
			ActorType:      r.ActorType,
			ActorID:        r.ActorID,
			CreatedAt:      r.CreatedAt.Format(time.RFC3339),
		}
	}

	// When the caller is tailing (passed after=) and no new rows exist, we
	// echo back their cursor so the next poll stays on the same high-water
	// mark without a separate round-trip to learn "still nothing new".
	if latestID == 0 {
		latestID = opts.After
	}

	// next_cursor is the id to pass as `before` on the next page going back
	// in time. Nil when we don't have a full page (end of history) or when
	// the caller is tailing forward (`after` set).
	var nextCursor any
	if opts.After == 0 && len(rows) == limit {
		nextCursor = rows[len(rows)-1].ID
	}

	jsonOK(w, map[string]any{
		"logs":        items,
		"next_cursor": nextCursor,
		"latest_id":   latestID,
	})
}
