package cmd

import (
	"testing"

	"github.com/Infisical/agent-vault/internal/inspect"
)

func TestValidateStatusBucket(t *testing.T) {
	for _, status := range []string{"2xx", "3xx", "4xx", "5xx", "err"} {
		if err := validateStatusBucket(status); err != nil {
			t.Fatalf("expected %q to be valid: %v", status, err)
		}
	}
	if err := validateStatusBucket("401"); err == nil {
		t.Fatal("expected exact status code to be rejected")
	}
}

func TestValidateIngress(t *testing.T) {
	for _, ingress := range []string{"explicit", "mitm"} {
		if err := validateIngress(ingress); err != nil {
			t.Fatalf("expected %q to be valid: %v", ingress, err)
		}
	}
	if err := validateIngress("http"); err == nil {
		t.Fatal("expected unsupported ingress to be rejected")
	}
}

func TestFormatStatus(t *testing.T) {
	if got := formatStatus(requestLogForTest(401, "")); got != "401" {
		t.Fatalf("expected 401, got %q", got)
	}
	if got := formatStatus(requestLogForTest(0, "upstream_timeout")); got != "err:upstream_timeout" {
		t.Fatalf("expected error code status, got %q", got)
	}
}

func TestValueOrDashStripsControlCharacters(t *testing.T) {
	if got := valueOrDash("api.example.com/\x1b[31m"); got != "api.example.com/?[31m" {
		t.Fatalf("expected control character to be replaced, got %q", got)
	}
}

func requestLogForTest(status int, errCode string) inspect.RequestLog {
	return inspect.RequestLog{Status: status, ErrorCode: errCode}
}
