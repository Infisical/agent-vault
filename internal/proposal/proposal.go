package proposal

import (
	"encoding/json"
	"net"
	"strconv"

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

// Service is a proposed broker service change. Identity is Name; it is
// required for ActionSet and validated upstream. ActionDelete may omit
// Name to fall back to host-based resolution: server resolves against
// existing services by Host (and Path, when scoped via inline form) —
// unique match fills Name; 2+ matches return 409 with a candidate list;
// 0 matches return 404 (or 409 at apply time).
//
// Host accepts bare, wildcard, or inline path-scoped (`slack.com/api/*`)
// forms; ingest splits the inline form before validation and MarshalJSON
// re-joins on read.
//
// For set actions, at least one of Auth or Enabled must be specified.
// Enabled-only on an existing Name overlays just the flag (enable/disable
// flow); Substitutions require Auth since merge only carries them on
// full replacements.
type Service struct {
	Action        Action                `json:"action"`
	Name          string                `json:"name,omitempty"`
	Host          string                `json:"host"`
	Path          string                `json:"path,omitempty"`
	Port          *int                  `json:"-"`
	Enabled       *bool                 `json:"enabled,omitempty"`
	Auth          *broker.Auth          `json:"auth,omitempty"`
	Substitutions []broker.Substitution `json:"substitutions,omitempty"`
}

// MatcherPattern returns the joined inline form (`slack.com/api/*`),
// or just Host when Path is empty. Mirrors broker.Service.MatcherPattern.
func (s Service) MatcherPattern() string {
	host := s.Host
	if s.Port != nil {
		host = net.JoinHostPort(s.Host, strconv.Itoa(*s.Port))
	}
	if s.Path == "" {
		return host
	}
	return host + s.Path
}

func (s Service) MarshalJSON() ([]byte, error) {
	type alias Service
	a := alias(s)
	a.Host = s.MatcherPattern()
	a.Path = ""
	a.Port = nil
	return json.Marshal(a)
}

// CredentialSlot declares a credential operation in a proposal.
// For "set": value is optional, if provided, it will be encrypted at creation time.
// If omitted, the human must supply it during approval.
// For "delete": only key is required.
type CredentialSlot struct {
	Action             Action       `json:"action"`
	Key                string       `json:"key"`
	Type               string       `json:"type,omitempty"`
	Description        string       `json:"description,omitempty"`
	Obtain             string       `json:"obtain,omitempty"`
	ObtainInstructions string       `json:"obtain_instructions,omitempty"`
	Value              *string      `json:"value,omitempty"`
	HasValue           bool         `json:"has_value,omitempty"`
	OAuth              *OAuthConfig `json:"oauth,omitempty"`
}

// OAuthConfig holds the OAuth parameters in a credential slot proposal.
type OAuthConfig struct {
	AuthorizationURL string `json:"authorization_url,omitempty"`
	TokenURL         string `json:"token_url"`
	ClientID         string `json:"client_id,omitempty"`
	Scopes           string `json:"scopes,omitempty"`
	ScopeSeparator   string `json:"scope_separator,omitempty"`
	DisablePKCE      bool   `json:"disable_pkce,omitempty"`
	TokenAuthMethod  string `json:"token_auth_method,omitempty"`
}
