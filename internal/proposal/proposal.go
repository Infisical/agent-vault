package proposal

import (
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
// For "set" actions, at least one of Auth or Enabled must be specified.
// When Enabled is provided without Auth and a service with that Name
// already exists, the merge preserves the existing service's
// Auth/Description and overlays only the Enabled flag — this is the
// enable/disable flow. Substitutions must accompany Auth (Validate
// rejects set+Substitutions without Auth) since the merge only carries
// them on full replacements.
type Service struct {
	Action        Action                `json:"action"`
	Name          string                `json:"name,omitempty"`
	Host          string                `json:"host"`
	Path          string                `json:"path,omitempty"`
	Description   string                `json:"description,omitempty"`
	Enabled       *bool                 `json:"enabled,omitempty"`
	Auth          *broker.Auth          `json:"auth,omitempty"`
	Substitutions []broker.Substitution `json:"substitutions,omitempty"`
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
