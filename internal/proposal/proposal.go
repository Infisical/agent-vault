package proposal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
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
	Action             Action          `json:"action"`
	Key                string          `json:"key"`
	Type               string          `json:"type,omitempty"`
	Description        string          `json:"description,omitempty"`
	Obtain             string          `json:"obtain,omitempty"`
	ObtainInstructions string          `json:"obtain_instructions,omitempty"`
	Value              *string         `json:"value,omitempty"`
	HasValue           bool            `json:"has_value,omitempty"`
	OAuth              *OAuthConfig    `json:"oauth,omitempty"`
	Acquisition        *AcquisitionRef `json:"acquisition,omitempty"`
}

// AcquisitionMode identifies a closed V1 credential-acquisition flow.
type AcquisitionMode string

const (
	AcquisitionModeNative            AcquisitionMode = "native"
	AcquisitionModeGuided            AcquisitionMode = "guided"
	AcquisitionModeOAuth             AcquisitionMode = "oauth"
	AcquisitionModeDevice            AcquisitionMode = "device"
	AcquisitionModeServerPassthrough AcquisitionMode = "server_passthrough"
)

var acquisitionIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// AcquisitionRef contains proposal-controlled identifiers only. Executables,
// arguments, environment variables, selectors, and provider configuration are
// resolved from the server-owned handler registry.
type AcquisitionRef struct {
	Handler string          `json:"handler"`
	Profile string          `json:"profile"`
	Mode    AcquisitionMode `json:"mode"`
}

// UnmarshalJSON rejects fields outside the closed acquisition reference.
func (a *AcquisitionRef) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode acquisition: %w", err)
	}
	if opening != json.Delim('{') {
		return fmt.Errorf("decode acquisition: expected JSON object")
	}

	var decoded AcquisitionRef
	seen := make(map[string]struct{}, 3)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("decode acquisition: %w", err)
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("decode acquisition: expected object key")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("decode acquisition: duplicate field %q", key)
		}
		seen[key] = struct{}{}

		switch key {
		case "handler":
			err = decoder.Decode(&decoded.Handler)
		case "profile":
			err = decoder.Decode(&decoded.Profile)
		case "mode":
			err = decoder.Decode(&decoded.Mode)
		default:
			return fmt.Errorf("decode acquisition: unknown field %q", key)
		}
		if err != nil {
			return fmt.Errorf("decode acquisition field %q: %w", key, err)
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode acquisition: %w", err)
	}
	if closing != json.Delim('}') {
		return fmt.Errorf("decode acquisition: expected end of JSON object")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode acquisition: unexpected trailing JSON value")
		}
		return fmt.Errorf("decode acquisition: %w", err)
	}
	*a = decoded
	return nil
}

func (a AcquisitionRef) validate() error {
	if !acquisitionIDPattern.MatchString(a.Handler) {
		return fmt.Errorf("handler must match %s", acquisitionIDPattern)
	}
	if !acquisitionIDPattern.MatchString(a.Profile) {
		return fmt.Errorf("profile must match %s", acquisitionIDPattern)
	}
	switch a.Mode {
	case AcquisitionModeNative, AcquisitionModeGuided, AcquisitionModeOAuth, AcquisitionModeDevice, AcquisitionModeServerPassthrough:
		return nil
	default:
		return fmt.Errorf("unsupported acquisition mode %q", a.Mode)
	}
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
