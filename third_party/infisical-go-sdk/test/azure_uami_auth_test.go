package test

// Azure User-Assigned Managed Identity (UAMI) auth test.
//
// This file is meant to be RUN ON AN AZURE VM (or AKS pod) that has a
// User-Assigned Managed Identity attached. It will not work on your laptop
// because it talks to the Azure IMDS endpoint (169.254.169.254), which only
// exists inside Azure compute.
//
// Required env vars (all must be set, otherwise the test is skipped):
//
//	INFISICAL_SITE_URL          e.g. "https://app.infisical.com"
//	INFISICAL_IDENTITY_ID       the machine identity ID configured in Infisical
//	                            with Azure Auth (the "Identity ID" field in the UI)
//	AZURE_UAMI_CLIENT_ID        the Application (client) ID of the UAMI assigned
//	                            to this VM. Looks like: 11111111-2222-3333-4444-555555555555
//
// Optional env vars:
//
//	AZURE_RESOURCE              custom resource URI; defaults to management.azure.com
//	INFISICAL_PROJECT_ID        if set, the test will also list secrets to verify
//	                            the full auth-then-call flow end-to-end
//	INFISICAL_ENV_SLUG          environment slug for the list (default: "dev")
//
// Run:  go test ./test/ -run TestAzureUAMIAuthLogin -v

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	infisical "github.com/infisical/go-sdk"
	"github.com/infisical/go-sdk/packages/util"
)

func requireEnv(t *testing.T, keys ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	missing := []string{}
	for _, k := range keys {
		v := os.Getenv(k)
		if v == "" {
			missing = append(missing, k)
			continue
		}
		out[k] = v
	}
	if len(missing) > 0 {
		t.Skipf("Skipping Azure UAMI test; missing env: %s", strings.Join(missing, ", "))
	}
	return out
}

// TestAzureIMDSReachable is a sanity test: confirms we can reach the Azure
// Instance Metadata Service at all. If this fails, you are not on an Azure VM.
func TestAzureIMDSReachable(t *testing.T) {
	if os.Getenv("AZURE_UAMI_CLIENT_ID") == "" {
		t.Skip("Skipping; not running on Azure (set AZURE_UAMI_CLIENT_ID to enable)")
	}
	httpClient := resty.New().SetTimeout(5 * time.Second)
	resp, err := httpClient.R().
		SetHeader("Metadata", "true").
		Get("http://169.254.169.254/metadata/instance?api-version=2021-02-01")
	if err != nil {
		t.Fatalf("IMDS unreachable, this machine is probably not on Azure: %v", err)
	}
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("IMDS responded with non-200: %d, body=%s", resp.StatusCode(), resp.String())
	}
	t.Logf("IMDS reachable, this is an Azure compute instance")
}

// TestAzureUAMITokenFetch confirms the URL builder produces a request shape
// that Azure IMDS accepts for a User-Assigned Managed Identity. This is the
// core regression test for the original bug where client_id was URL-encoded
// into the resource value instead of being a separate query parameter.
//
// No Infisical involved — just SDK util -> Azure IMDS.
func TestAzureUAMITokenFetch(t *testing.T) {
	env := requireEnv(t, "AZURE_UAMI_CLIENT_ID")
	clientID := env["AZURE_UAMI_CLIENT_ID"]
	resource := os.Getenv("AZURE_RESOURCE") // empty = use SDK default

	httpClient := resty.New().SetTimeout(10 * time.Second)
	token, err := util.GetAzureMetadataToken(httpClient, resource, clientID)
	if err != nil {
		t.Fatalf("GetAzureMetadataToken failed for UAMI %s: %v", clientID, err)
	}
	if token == "" {
		t.Fatal("got empty access token from IMDS")
	}
	// JWTs are dot-separated triples. Cheap sanity check that we got a JWT,
	// not an error string the server lobbed back with a 200.
	if strings.Count(token, ".") != 2 {
		t.Fatalf("token does not look like a JWT: %q", token)
	}
	t.Logf("Successfully fetched UAMI token (len=%d, head=%s...)", len(token), token[:16])
}

// TestAzureUAMITokenFetch_SystemAssignedRegression confirms System-Assigned
// Managed Identity still works (UAMI client ID omitted). Only runs if
// AZURE_TEST_SYSTEM_ASSIGNED=1 — set this only on a VM that has a
// System-Assigned identity enabled.
func TestAzureUAMITokenFetch_SystemAssignedRegression(t *testing.T) {
	if os.Getenv("AZURE_TEST_SYSTEM_ASSIGNED") != "1" {
		t.Skip("Skipping system-assigned regression; set AZURE_TEST_SYSTEM_ASSIGNED=1 to enable")
	}
	httpClient := resty.New().SetTimeout(10 * time.Second)
	token, err := util.GetAzureMetadataToken(httpClient, "", "")
	if err != nil {
		t.Fatalf("system-assigned IMDS fetch failed: %v", err)
	}
	if strings.Count(token, ".") != 2 {
		t.Fatalf("token does not look like a JWT: %q", token)
	}
	t.Log("System-assigned token fetch still works")
}

// TestAzureUAMIAuthLogin exercises the full chain through the SDK against a
// real Infisical instance. This is the end-to-end test.
func TestAzureUAMIAuthLogin(t *testing.T) {
	env := requireEnv(t, "INFISICAL_SITE_URL", "INFISICAL_IDENTITY_ID", "AZURE_UAMI_CLIENT_ID")

	client := infisical.NewInfisicalClient(context.Background(), infisical.Config{
		SiteUrl: env["INFISICAL_SITE_URL"],
	})

	resource := os.Getenv("AZURE_RESOURCE")

	credential, err := client.Auth().
		WithAzureClientID(env["AZURE_UAMI_CLIENT_ID"]).
		AzureAuthLogin(env["INFISICAL_IDENTITY_ID"], resource)
	if err != nil {
		t.Fatalf("AzureAuthLogin (UAMI) failed: %v", err)
	}
	if credential.AccessToken == "" {
		t.Fatal("got empty access token from Infisical")
	}
	t.Logf("Infisical access token obtained via UAMI (expires in %ds)", credential.ExpiresIn)

	// Optional: fetch secrets to prove the access token actually works.
	projectID := os.Getenv("INFISICAL_PROJECT_ID")
	if projectID == "" {
		t.Log("INFISICAL_PROJECT_ID not set; skipping secret fetch")
		return
	}
	envSlug := os.Getenv("INFISICAL_ENV_SLUG")
	if envSlug == "" {
		envSlug = "dev"
	}
	result, err := client.Secrets().ListSecrets(infisical.ListSecretsOptions{
		ProjectID:   projectID,
		Environment: envSlug,
	})
	if err != nil {
		t.Fatalf("listing secrets with UAMI-issued token failed: %v", err)
	}
	t.Logf("Listed %d secrets from project %s/%s", len(result.Secrets), projectID, envSlug)
}

// TestAzureAuthLogin_BackwardsCompat exercises the original 2-arg
// AzureAuthLogin(identityID, resource) signature with NO WithAzureClientID
// chain. This is the System-Assigned Managed Identity path that existed
// before UAMI support was added. It must continue to work unchanged.
//
// Run this on an Azure VM that has a *System-Assigned* Managed Identity
// enabled (not user-assigned). Required env:
//
//	INFISICAL_SITE_URL
//	INFISICAL_IDENTITY_ID         (an identity configured against the VM's
//	                              system-assigned principal)
//	AZURE_TEST_SYSTEM_ASSIGNED=1  to opt in
func TestAzureAuthLogin_BackwardsCompat(t *testing.T) {
	if os.Getenv("AZURE_TEST_SYSTEM_ASSIGNED") != "1" {
		t.Skip("Skipping backwards-compat test; set AZURE_TEST_SYSTEM_ASSIGNED=1 to enable")
	}
	env := requireEnv(t, "INFISICAL_SITE_URL", "INFISICAL_IDENTITY_ID")

	client := infisical.NewInfisicalClient(context.Background(), infisical.Config{
		SiteUrl: env["INFISICAL_SITE_URL"],
	})

	// Original call shape — exactly how callers invoked this before UAMI support.
	// No WithAzureClientID chain, no new parameters.
	credential, err := client.Auth().AzureAuthLogin(env["INFISICAL_IDENTITY_ID"], "")
	if err != nil {
		t.Fatalf("AzureAuthLogin (system-assigned, original signature) failed: %v", err)
	}
	if credential.AccessToken == "" {
		t.Fatal("got empty access token from Infisical")
	}
	t.Logf("System-assigned auth still works via original 2-arg signature (expires in %ds)", credential.ExpiresIn)
}
