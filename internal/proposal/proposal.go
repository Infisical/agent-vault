package proposal

import (
	"encoding/json"

	"github.com/Infisical/agent-vault/internal/broker"
)

// Status represents the lifecycle state of a proposal.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApplied  Status = "applied"
	StatusRejected Status = "rejected"
	StatusExpired  Status = "expired"
)

// Action represents the operation a proposed service or credential slot performs.
type Action string

const (
	ActionSet    Action = "set"    // idempotent upsert: add or replace
	ActionDelete Action = "delete" // remove existing
)

// Service is a proposed broker service change. Identity for both "set"
// (upsert) and "delete" is Name — the canonical per-vault slug. Server
// handlers ingesting proposals from older clients auto-fill Name from
// broker.Slugify(Host, Path) before merging; ActionDelete with no Name
// resolves uniquely against Host (with 409 on multi-match).
//
// Host accepts a bare hostname, a one-level wildcard, or an inline
// path-scoped form (`slack.com/api/*`). Ingest splits the inline form
// into Host + Path before validation; MarshalJSON re-joins on read so
// the wire surface is symmetric with writes. Path is internal to the
// matcher and not exposed on JSON.
//
// For "set" actions, at least one of Auth or Enabled must be specified.
// When Enabled is provided without Auth and a service with that Name
// already exists, the merge preserves the existing service's Auth and
// overlays only the Enabled flag — this is the enable/disable flow.
// Substitutions must accompany Auth (Validate rejects set+Substitutions
// without Auth) since the merge only carries them on full replacements.
type Service struct {
	Action Action `json:"action"`
	Name   string `json:"name,omitempty"`
	Host   string `json:"host"`
	// Path keeps the json tag so legacy in-flight proposals (stored
	// split before MarshalJSON joined them) still round-trip cleanly.
	// MarshalJSON suppresses it on output via the omitempty path.
	Path          string                `json:"path,omitempty"`
	Enabled       *bool                 `json:"enabled,omitempty"`
	Auth          *broker.Auth          `json:"auth,omitempty"`
	Substitutions []broker.Substitution `json:"substitutions,omitempty"`
}

// MatcherPattern returns the joined inline form of Host and Path —
// e.g. `slack.com` for a host-only rule and `slack.com/api/*` for a
// path-scoped rule. Mirrors broker.Service.MatcherPattern.
func (s Service) MatcherPattern() string {
	if s.Path == "" {
		return s.Host
	}
	return s.Host + s.Path
}

// MarshalJSON emits the joined inline form on `host` and suppresses
// the internal Path field, matching broker.Service's wire shape.
func (s Service) MarshalJSON() ([]byte, error) {
	type alias Service
	a := alias(s)
	a.Host = s.MatcherPattern()
	a.Path = ""
	return json.Marshal(a)
}

// CredentialSlot declares a credential operation in a proposal.
// For "set": value is optional, if provided, it will be encrypted at creation time.
// If omitted, the human must supply it during approval.
// For "delete": only key is required.
type CredentialSlot struct {
	Action             Action  `json:"action"`
	Key                string  `json:"key"`
	Description        string  `json:"description,omitempty"`
	Obtain             string  `json:"obtain,omitempty"`
	ObtainInstructions string  `json:"obtain_instructions,omitempty"` // short step-by-step text (e.g. "Developers → API Keys → Reveal test key")
	Value              *string `json:"value,omitempty"`
	HasValue           bool    `json:"has_value,omitempty"`
}
