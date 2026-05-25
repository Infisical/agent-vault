package infisical

import (
	"encoding/json"
	"fmt"
	"strings"
)

// KindInfisical is persisted in vault_credential_stores.kind.
const KindInfisical = "infisical"

// KindBuiltin is the wire sentinel for "no external store" (never persisted).
const KindBuiltin = "builtin"

// Sync-status values persisted in vault_credential_stores.last_sync_status.
const (
	StatusOK      = "ok"
	StatusError   = "error"
	StatusPending = "pending"
)

// DefaultPollIntervalSeconds applies when the create call omits the field.
const DefaultPollIntervalSeconds = 60

// MinPollIntervalSeconds mirrors the DB CHECK constraint.
const MinPollIntervalSeconds = 10

// VaultConfig is the JSON shape persisted in vault_credential_stores.config_json.
type VaultConfig struct {
	ProjectID   string `json:"project_id"`
	Environment string `json:"environment"`
	SecretPath  string `json:"secret_path"`
}

// Validate enforces the structural invariants the SDK and the broker both
// rely on. Returns a flat error message safe to surface to API callers.
func (c VaultConfig) Validate() error {
	if strings.TrimSpace(c.ProjectID) == "" {
		return fmt.Errorf("project_id is required")
	}
	if strings.TrimSpace(c.Environment) == "" {
		return fmt.Errorf("environment is required")
	}
	if c.SecretPath == "" {
		return fmt.Errorf("secret_path is required (use \"/\" for the root)")
	}
	if !strings.HasPrefix(c.SecretPath, "/") {
		return fmt.Errorf("secret_path must start with /")
	}
	return nil
}

// MarshalConfigJSON returns the canonical JSON form persisted in the DB.
func MarshalConfigJSON(c VaultConfig) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ParseConfigJSON inverts MarshalConfigJSON. Trims whitespace so a value
// the Web UI would strip never reaches ListSecrets verbatim and 404s
// against the scrubbed "see server logs" response.
func ParseConfigJSON(raw string) (VaultConfig, error) {
	var c VaultConfig
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return VaultConfig{}, err
	}
	c.ProjectID = strings.TrimSpace(c.ProjectID)
	c.Environment = strings.TrimSpace(c.Environment)
	c.SecretPath = strings.TrimSpace(c.SecretPath)
	return c, nil
}

// Secret is the broker-facing key/value pair pulled from Infisical.
type Secret struct {
	Key   string
	Value string
}
