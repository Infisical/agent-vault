package store

import (
	"os"
	"strconv"
)

// envCredentialHistoryMaxVersions names the environment variable that caps
// how many archived CredentialVersion rows are kept per (vault, key).
const envCredentialHistoryMaxVersions = "AGENT_VAULT_CREDENTIAL_HISTORY_MAX_VERSIONS"

// DefaultCredentialHistoryMaxVersions is used when the env var is unset or
// invalid. Small on purpose — history is for "undo the last few mistakes",
// not a full audit log (request logs already serve that role, with their
// own retention knobs).
const DefaultCredentialHistoryMaxVersions = 10

// CredentialHistoryMaxVersionsFromEnv reads AGENT_VAULT_CREDENTIAL_HISTORY_MAX_VERSIONS.
// Returns DefaultCredentialHistoryMaxVersions if unset or not a valid
// non-negative integer. 0 disables pruning (unbounded retention).
func CredentialHistoryMaxVersionsFromEnv() int {
	raw := os.Getenv(envCredentialHistoryMaxVersions)
	if raw == "" {
		return DefaultCredentialHistoryMaxVersions
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		return DefaultCredentialHistoryMaxVersions
	}
	return v
}
