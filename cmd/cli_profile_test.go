package cmd

import (
	"strings"
	"testing"
)

func TestResolveCLIProfileProjectionsAzureDevOps(t *testing.T) {
	projections, err := resolveCLIProfileProjections([]string{"azure-devops"})
	if err != nil {
		t.Fatal(err)
	}
	if len(projections) != 1 {
		t.Fatalf("expected 1 projection, got %d", len(projections))
	}
	got := projections[0]
	if got.Env != "AZURE_DEVOPS_EXT_PAT" || got.CredentialKey != "AZURE_DEVOPS_PASSWORD" {
		t.Fatalf("unexpected azure-devops projection: %+v", got)
	}
}

func TestResolveCLIProfileProjectionsRejectsUnknownProfile(t *testing.T) {
	_, err := resolveCLIProfileProjections([]string{"unknown-cli"})
	if err == nil || !strings.Contains(err.Error(), "unknown CLI profile") {
		t.Fatalf("expected unknown profile error, got %v", err)
	}
}

func TestApplyCLIProfileProjectionsStripsParentEnvAndDoesNotLeakInLogs(t *testing.T) {
	fetch := func(key string) (string, error) {
		if key != "AZURE_DEVOPS_PASSWORD" {
			t.Fatalf("unexpected credential key %q", key)
		}
		return "real-test-secret-value", nil
	}
	env, summaries, err := applyCLIProfileProjections([]string{
		"AZURE_DEVOPS_EXT_PAT=stale-parent-value",
		"OTHER=ok",
	}, []cliProfileProjection{{Profile: "azure-devops", Env: "AZURE_DEVOPS_EXT_PAT", CredentialKey: "AZURE_DEVOPS_PASSWORD"}}, fetch)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "stale-parent-value") {
		t.Fatalf("stale parent env value was not stripped: %s", joined)
	}
	if !strings.Contains(joined, "AZURE_DEVOPS_EXT_PAT=real-test-secret-value") {
		t.Fatalf("projected env missing expected process-local credential")
	}
	if len(summaries) != 1 || summaries[0] != "azure-devops: AZURE_DEVOPS_PASSWORD -> AZURE_DEVOPS_EXT_PAT" {
		t.Fatalf("unexpected summaries: %#v", summaries)
	}
	if strings.Contains(strings.Join(summaries, "\n"), "real-test-secret-value") {
		t.Fatalf("summary leaked secret value: %#v", summaries)
	}
}
