// Package infisical wraps the Infisical Go SDK so the rest of the broker
// can fetch secrets without depending on the SDK's surface directly. The
// package owns auth-method detection (from env vars), client construction,
// and the per-vault sync worker.
package infisical

import (
	"fmt"
	"log/slog"
	"slices"
)

// AuthMethod identifies which Infisical machine-identity flow the SDK
// should use. The SDK does not auto-detect; the caller selects.
type AuthMethod string

const (
	AuthUniversal  AuthMethod = "universal"
	AuthKubernetes AuthMethod = "kubernetes"
	AuthAWSIAM     AuthMethod = "aws-iam"
	AuthGCPIAM     AuthMethod = "gcp-iam"
	AuthGCPIDToken AuthMethod = "gcp-id-token"
	AuthLDAP       AuthMethod = "ldap"
)

// authProbe is one row in the priority-ordered detection table.
type authProbe struct {
	method   AuthMethod
	required []string // all required to consider this method "configured"
}

// authProbes is the priority order; first complete row wins. GCP IAM and
// GCP ID Token share INFISICAL_GCP_AUTH_IDENTITY_ID — IAM ranks first so
// its IAM-only key-file path tips selection.
var authProbes = []authProbe{
	{AuthUniversal, []string{"INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET"}},
	{AuthKubernetes, []string{"INFISICAL_KUBERNETES_IDENTITY_ID"}},
	{AuthAWSIAM, []string{"INFISICAL_AWS_IAM_AUTH_IDENTITY_ID"}},
	{AuthGCPIAM, []string{"INFISICAL_GCP_AUTH_IDENTITY_ID", "INFISICAL_GCP_IAM_SERVICE_ACCOUNT_KEY_FILE_PATH"}},
	{AuthGCPIDToken, []string{"INFISICAL_GCP_AUTH_IDENTITY_ID"}},
	{AuthLDAP, []string{"INFISICAL_LDAP_AUTH_IDENTITY_ID", "INFISICAL_LDAP_AUTH_USERNAME", "INFISICAL_LDAP_AUTH_PASSWORD"}},
}

// DetectAuthMethod returns the first complete auth method per authProbes.
// ("", nil) means no method configured (Infisical disabled). Warns when
// multiple methods are complete and falls back to highest priority.
func DetectAuthMethod(getenv func(string) string, logger *slog.Logger) (AuthMethod, error) {
	var matches []AuthMethod
	for _, probe := range authProbes {
		// GCP IAM and GCP ID Token share INFISICAL_GCP_AUTH_IDENTITY_ID;
		// skip ID Token when IAM already matched so we don't warn spuriously.
		if probe.method == AuthGCPIDToken && slices.Contains(matches, AuthGCPIAM) {
			continue
		}
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
		others := matches[1:]
		logger.Warn("multiple Infisical auth methods configured; using highest-priority",
			slog.String("using", string(matches[0])),
			slog.Any("ignoring", others))
	}
	return matches[0], nil
}

// ErrNotConfigured signals that INFISICAL_URL is unset; the server should
// keep running with builtin-only vaults.
var ErrNotConfigured = fmt.Errorf("infisical: INFISICAL_URL not set")

// ErrNoAuthMethod signals that INFISICAL_URL is set but no machine-identity
// env vars are configured; surfaced as an operator-facing error.
var ErrNoAuthMethod = fmt.Errorf("infisical: INFISICAL_URL is set but no auth-method env vars are configured")
