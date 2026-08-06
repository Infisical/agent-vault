package hashicorp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// DefaultPollIntervalSeconds applies when the create call omits the field.
const DefaultPollIntervalSeconds = 60

// MinPollIntervalSeconds mirrors the DB CHECK constraint.
const MinPollIntervalSeconds = 10

// DefaultKVVersion is assumed when the create call omits kv_version. KV v2 is
// the default secrets engine on a modern Vault (`secret/`).
const DefaultKVVersion = 2

// VaultConfig is the JSON shape persisted in vault_credential_stores.config_json
// for hashicorp-backed vaults. Mount is the KV secrets-engine mount path
// (e.g. "secret"); SecretPath is the path to a single KV item within that mount
// whose key/value pairs become the vault's credentials.
type VaultConfig struct {
	Mount      string `json:"mount"`
	SecretPath string `json:"secret_path"`
	KVVersion  int    `json:"kv_version"`
}

// Validate enforces the structural invariants the client and the broker both
// rely on. Returns a flat error message safe to surface to API callers.
func (c VaultConfig) Validate() error {
	if strings.TrimSpace(c.Mount) == "" {
		return fmt.Errorf("mount is required (e.g. \"secret\")")
	}
	if strings.TrimSpace(c.SecretPath) == "" {
		return fmt.Errorf("secret_path is required")
	}
	if c.KVVersion != 1 && c.KVVersion != 2 {
		return fmt.Errorf("kv_version must be 1 or 2")
	}
	return nil
}

// withDefaults returns a copy with zero-value fields filled in, so a config
// JSON that omits kv_version (e.g. a direct API POST) resolves to the default
// KV v2 rather than failing Validate. The CLI defaults the flag to 2, so both
// entry points land on the same value.
func (c VaultConfig) withDefaults() VaultConfig {
	if c.KVVersion == 0 {
		c.KVVersion = DefaultKVVersion
	}
	return c
}

// MarshalConfigJSON returns the canonical JSON form persisted in the DB.
func MarshalConfigJSON(c VaultConfig) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ParseConfigJSON inverts MarshalConfigJSON. Trims whitespace and applies
// defaults so a row written before kv_version existed still resolves.
func ParseConfigJSON(raw string) (VaultConfig, error) {
	var c VaultConfig
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return VaultConfig{}, err
	}
	c.Mount = strings.TrimSpace(c.Mount)
	c.SecretPath = strings.TrimPrefix(strings.TrimSpace(c.SecretPath), "/")
	return c.withDefaults(), nil
}

// Secret is the broker-facing key/value pair pulled from HashiCorp Vault.
type Secret struct {
	Key   string
	Value string
}
