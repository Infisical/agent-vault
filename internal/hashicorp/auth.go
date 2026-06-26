// Package hashicorp wraps the HashiCorp Vault API: auth-method detection,
// client construction, and the per-vault sync worker. It mirrors the
// internal/infisical package so an Agent Vault instance can back read-only
// vaults with secrets pulled from a HashiCorp Vault instance.
//
// Design note — deliberate duplication of the sync worker:
// sync.go is intentionally a near-copy of internal/infisical/sync.go rather
// than a shared "credstore engine" with a provider interface. The trade-off:
// per-provider packages keep each store fully self-contained (the repo's
// existing convention) and avoid touching the shipped Infisical path, at the
// cost of duplicated tick/in-flight/backoff logic. This is acceptable at two
// providers. If a THIRD external store is added, prefer extracting a shared
// engine at that point — the SecretsFetcher interface, the Kind constant, and
// the sentinel errors (ErrSyncerDisabled/ErrNotExternal/ErrSyncInFlight/
// ErrInvalidKey) are the seams to generalize. Don't blindly copy a third time.
package hashicorp

import (
	"fmt"
	"log/slog"
)

// AuthMethod identifies which HashiCorp Vault auth flow the client uses.
// Token and AppRole are supported today; additional methods can be added to
// authProbes without touching callers.
type AuthMethod string

const (
	// AuthToken authenticates with a pre-issued Vault token from VAULT_TOKEN.
	AuthToken AuthMethod = "token"
	// AuthAppRole authenticates with a RoleID/SecretID pair.
	AuthAppRole AuthMethod = "approle"
)

// authProbe is one row in the priority-ordered detection table.
type authProbe struct {
	method   AuthMethod
	required []string // all required to consider this method "configured"
}

// authProbes is the priority order; first complete row wins. AppRole ranks
// first so its RoleID/SecretID pair tips selection over a bare token when
// both are present.
var authProbes = []authProbe{
	{AuthAppRole, []string{"VAULT_ROLE_ID", "VAULT_SECRET_ID"}},
	{AuthToken, []string{"VAULT_TOKEN"}},
}

// DetectAuthMethod returns the first complete auth method per authProbes,
// or "" when none is configured (HashiCorp store disabled).
func DetectAuthMethod(getenv func(string) string, logger *slog.Logger) (AuthMethod, error) {
	var matches []AuthMethod
	for _, probe := range authProbes {
		complete := true
		for _, key := range probe.required {
			if getenv(key) == "" {
				complete = false
				break
			}
		}
		if complete {
			matches = append(matches, probe.method)
		}
	}
	if len(matches) == 0 {
		return "", nil
	}
	if len(matches) > 1 && logger != nil {
		logger.Warn("multiple HashiCorp Vault auth methods configured; using highest-priority",
			slog.String("using", string(matches[0])),
			slog.Any("ignoring", matches[1:]))
	}
	return matches[0], nil
}

// ErrNotConfigured signals that VAULT_ADDR is unset; the server should keep
// running with builtin-only (and any Infisical-backed) vaults.
var ErrNotConfigured = fmt.Errorf("hashicorp: VAULT_ADDR not set")

// ErrNoAuthMethod signals that VAULT_ADDR is set but no auth-method env vars
// are configured; surfaced as an operator-facing error.
var ErrNoAuthMethod = fmt.Errorf("hashicorp: VAULT_ADDR is set but no auth-method env vars are configured (set VAULT_TOKEN, or VAULT_ROLE_ID + VAULT_SECRET_ID)")
