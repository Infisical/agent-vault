package brokercore

import (
	"log/slog"
	"time"
)

// Ingress labels identify which entrypoint handled a proxied request.
// Persisted into request logs and filterable by the Logs UI, so a typo
// at any call site would silently desync filters from the real data.
const (
	IngressExplicit = "explicit"
	IngressMITM     = "mitm"
)

// Actor types identify the principal behind a proxied request. Same
// reason for constants as the ingress labels above.
const (
	ActorTypeUser  = "user"
	ActorTypeAgent = "agent"
)

// ProxyEvent is the shape of a single structured per-request log line
// emitted by both the explicit /proxy/ handler and the transparent MITM
// forward handler. It is intentionally shallow and contains only
// non-secret metadata — no header values, no bodies, no query strings.
type ProxyEvent struct {
	Ingress        string   // one of IngressExplicit, IngressMITM
	Method         string   // HTTP method from the agent request
	Host           string   // target host (with port if present)
	Path           string   // r.URL.Path only — no query, no fragment
	MatchedService string   // broker service host that matched, or "" if none
	CredentialKeys []string // upper-snake credential key names only
	Status         int      // upstream status; 0 if never dispatched
	TotalMs        int64    // handler entry → emit, in milliseconds
	Err            string   // short error code, or "" on success
}

// Emit fills in the terminal fields (Status, Err, TotalMs measured from
// start) and writes the event at Debug level. Shared by both ingress
// paths so the log-line shape stays consistent.
func (e *ProxyEvent) Emit(logger *slog.Logger, start time.Time, status int, errCode string) {
	e.Status = status
	e.Err = errCode
	e.TotalMs = time.Since(start).Milliseconds()
	LogProxyEvent(logger, *e)
}

// LogProxyEvent emits e at Debug level on logger. Handler-level filtering
// in slog means info-level runs drop these lines at effectively zero cost.
// Safe to call with a nil logger (no-op) so handlers don't have to guard.
func LogProxyEvent(logger *slog.Logger, e ProxyEvent) {
	if logger == nil {
		return
	}
	logger.Debug("proxy_request",
		slog.String("ingress", e.Ingress),
		slog.String("method", e.Method),
		slog.String("host", e.Host),
		slog.String("path", e.Path),
		slog.String("matched_service", e.MatchedService),
		slog.Any("credential_keys", e.CredentialKeys),
		slog.Int("status", e.Status),
		slog.Int64("total_ms", e.TotalMs),
		slog.String("err", e.Err),
	)
}

// LogCredentialMissing emits the operator-visible Warn line when a host
// matched a service but the referenced credential couldn't be resolved.
// Kept at info-level (Warn) because it's a user-actionable misconfig, not
// a debug signal. Secret-free: only vault id, service host, and key names.
func LogCredentialMissing(logger *slog.Logger, vaultID, service string, keys []string) {
	if logger == nil {
		return
	}
	logger.Warn("credential resolution failed",
		"vault", vaultID,
		"service", service,
		"credential_keys", keys,
	)
}
