package infisical

import (
	"io"
	"log/slog"
	"testing"
)

// envFunc builds a getenv closure backed by a map.
func envFunc(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func newDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestDetectAuthMethod_None(t *testing.T) {
	got, err := DetectAuthMethod(envFunc(nil), newDiscardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty method, got %q", got)
	}
}

func TestDetectAuthMethod_Universal(t *testing.T) {
	got, _ := DetectAuthMethod(envFunc(map[string]string{
		"INFISICAL_UNIVERSAL_AUTH_CLIENT_ID":     "id",
		"INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "secret",
	}), newDiscardLogger())
	if got != AuthUniversal {
		t.Fatalf("expected universal, got %q", got)
	}
}

func TestDetectAuthMethod_PartialUniversalIgnored(t *testing.T) {
	// CLIENT_ID alone is incomplete; expect no detection.
	got, _ := DetectAuthMethod(envFunc(map[string]string{
		"INFISICAL_UNIVERSAL_AUTH_CLIENT_ID": "id",
	}), newDiscardLogger())
	if got != "" {
		t.Fatalf("expected empty method, got %q", got)
	}
}

func TestDetectAuthMethod_PriorityOrder(t *testing.T) {
	// Universal and Kubernetes both complete; universal wins (higher priority).
	got, _ := DetectAuthMethod(envFunc(map[string]string{
		"INFISICAL_UNIVERSAL_AUTH_CLIENT_ID":     "id",
		"INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "secret",
		"INFISICAL_KUBERNETES_IDENTITY_ID":       "k8s-id",
	}), newDiscardLogger())
	if got != AuthUniversal {
		t.Fatalf("expected universal to win, got %q", got)
	}
}

func TestDetectAuthMethod_Kubernetes(t *testing.T) {
	got, _ := DetectAuthMethod(envFunc(map[string]string{
		"INFISICAL_KUBERNETES_IDENTITY_ID": "k8s-id",
	}), newDiscardLogger())
	if got != AuthKubernetes {
		t.Fatalf("expected kubernetes, got %q", got)
	}
}

func TestDetectAuthMethod_GCPIAMRequiresKeyFile(t *testing.T) {
	// Identity ID alone matches GCP ID Token (the same env var the SDK reads
	// for both GCP methods). Adding the IAM-only key-file path tips the
	// selection to GCP IAM.
	got, _ := DetectAuthMethod(envFunc(map[string]string{
		"INFISICAL_GCP_AUTH_IDENTITY_ID": "id",
	}), newDiscardLogger())
	if got != AuthGCPIDToken {
		t.Fatalf("expected gcp-id-token, got %q", got)
	}
	got, _ = DetectAuthMethod(envFunc(map[string]string{
		"INFISICAL_GCP_AUTH_IDENTITY_ID":                  "id",
		"INFISICAL_GCP_IAM_SERVICE_ACCOUNT_KEY_FILE_PATH": "/tmp/k.json",
	}), newDiscardLogger())
	if got != AuthGCPIAM {
		t.Fatalf("expected gcp-iam, got %q", got)
	}
}

func TestDetectAuthMethod_LDAPRequiresAllThree(t *testing.T) {
	// LDAP needs identity + username + password — the SDK only env-reads the
	// identity, so the loginWithMethod path consumes all three.
	got, _ := DetectAuthMethod(envFunc(map[string]string{
		"INFISICAL_LDAP_AUTH_IDENTITY_ID": "id",
	}), newDiscardLogger())
	if got == AuthLDAP {
		t.Fatalf("incomplete ldap should not match")
	}
	got, _ = DetectAuthMethod(envFunc(map[string]string{
		"INFISICAL_LDAP_AUTH_IDENTITY_ID": "id",
		"INFISICAL_LDAP_AUTH_USERNAME":    "bob",
		"INFISICAL_LDAP_AUTH_PASSWORD":    "s3cret",
	}), newDiscardLogger())
	if got != AuthLDAP {
		t.Fatalf("expected ldap, got %q", got)
	}
}
