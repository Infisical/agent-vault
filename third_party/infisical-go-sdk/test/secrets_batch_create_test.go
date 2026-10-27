package test

import (
	"context"
	"testing"

	infisical "github.com/infisical/go-sdk"
)

func TestBatchCreateSecrets(t *testing.T) {
	client := infisical.NewInfisicalClient(context.Background(), infisical.Config{
		SiteUrl:          "http://localhost:8080",
		AutoTokenRefresh: infisical.BoolPtr(false),
	})

	client.Auth().SetAccessToken("<token>")

	secs, err := client.Secrets().Batch().Create(infisical.BatchCreateSecretsOptions{
		Environment: "dev",
		SecretPath:  "/",
		ProjectID:   "06c4d805-ac8a-456f-906f-1319554d15ec",
		Secrets: []infisical.BatchCreateSecret{
			{
				SecretKey:   "test3",
				SecretValue: "test1",
			},
			{
				SecretKey:   "test4",
				SecretValue: "test2",
			},
		},
	})

	if err != nil {
		t.Fatalf("Failed to create secrets: %v", err)
	}

	t.Logf("Secrets: %v", secs)
}
