// Package requestlog persists per-request broker metadata (method, host,
// path, status, latency) so operators can audit what traffic flowed
// through a vault. Bodies, headers, and query strings are never
// captured. A Sink is the pluggable output layer: the shipped
// implementation writes to SQLite, but future sinks (HTTP webhooks,
// stdout JSONL) satisfy the same interface without changes to the
// proxy hot path.
package requestlog

import (
	"context"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/store"
)

// Record is the in-memory shape handed to sinks. It is a superset of
// brokercore.ProxyEvent with the actor/vault context the handler knows
// but brokercore does not. Adapters convert Record → store.RequestLog
// at the SQLite boundary.
type Record struct {
	VaultID        string
	ActorType      string
	ActorID        string
	Ingress        string
	Method         string
	Host           string
	Path           string
	MatchedService string
	CredentialKeys []string
	Status         int
	LatencyMs      int64
	ErrorCode      string
}

// Sink accepts records on the hot proxy path. Implementations MUST NOT
// block meaningfully: Record runs inline with every proxied request.
// Return is void by design — sinks are fire-and-forget; durability
// guarantees live inside the implementation.
type Sink interface {
	Record(ctx context.Context, r Record)
}

// Nop is a Sink that discards records. Safe default when the server
// is constructed without a configured sink (tests, tooling).
type Nop struct{}

// Record implements Sink.
func (Nop) Record(context.Context, Record) {}

// MultiSink fans each record out to every wrapped sink. Later sinks
// (HTTP webhook, stdout JSONL) stack here without touching the proxy.
type MultiSink []Sink

// Record implements Sink by forwarding to each wrapped sink in order.
func (m MultiSink) Record(ctx context.Context, r Record) {
	for _, s := range m {
		if s == nil {
			continue
		}
		s.Record(ctx, r)
	}
}

// FromEvent lifts a brokercore.ProxyEvent plus the actor/vault context
// the ingress handler knows (but brokercore does not) into a Record.
// Callers pass the terminal event — after ProxyEvent.Emit has filled in
// Status, Err, and TotalMs.
func FromEvent(ev brokercore.ProxyEvent, vaultID, actorType, actorID string) Record {
	return Record{
		VaultID:        vaultID,
		ActorType:      actorType,
		ActorID:        actorID,
		Ingress:        ev.Ingress,
		Method:         ev.Method,
		Host:           ev.Host,
		Path:           ev.Path,
		MatchedService: ev.MatchedService,
		CredentialKeys: ev.CredentialKeys,
		Status:         ev.Status,
		LatencyMs:      ev.TotalMs,
		ErrorCode:      ev.Err,
	}
}

// toStoreRow converts a Record to the persisted shape. Kept in the
// package (not on store.RequestLog) so the store package stays free of
// requestlog imports.
func toStoreRow(r Record) store.RequestLog {
	return store.RequestLog{
		VaultID:        r.VaultID,
		ActorType:      r.ActorType,
		ActorID:        r.ActorID,
		Ingress:        r.Ingress,
		Method:         r.Method,
		Host:           r.Host,
		Path:           r.Path,
		MatchedService: r.MatchedService,
		CredentialKeys: r.CredentialKeys,
		Status:         r.Status,
		LatencyMs:      r.LatencyMs,
		ErrorCode:      r.ErrorCode,
	}
}
