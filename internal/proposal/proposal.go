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

// Service is a proposed broker service change.
type Service struct {
	Action      Action       `json:"action"`
	Host        string       `json:"host"`
	Description string       `json:"description,omitempty"`
	Auth        *broker.Auth `json:"auth,omitempty"`
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
