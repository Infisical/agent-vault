package test

// import (
// 	"os"
// 	"testing"

// 	infisical "github.com/infisical/go-sdk"
// )

// func TestUniversalAuthLogin(t *testing.T) {

// 	client, err := infisical.NewInfisicalClient(infisical.Config{
// 		Auth: infisical.Authentication{
// 			UniversalAuth: infisical.UniversalAuth{
// 				ClientID:     os.Getenv("GO_SDK_TEST_UNIVERSAL_AUTH_CLIENT_ID"),
// 				ClientSecret: os.Getenv("GO_SDK_TEST_UNIVERSAL_AUTH_CLIENT_SECRET"),
// 			},
// 		},
// 	})

// 	if err != nil {
// 		t.Fatalf("Failed to create Infisical client: %v", err)
// 	}

// 	secrets, err := client.Secrets().List(infisical.ListSecretsOptions{
// 		ProjectID:   os.Getenv("GO_SDK_TEST_PROJECT_ID"),
// 		Environment: "dev",
// 	})

// 	if err != nil {
// 		t.Fatalf("Failed to list secrets: %v", err)
// 	}

// 	if len(secrets) == 0 {
// 		t.Fatalf("No secrets found")
// 	}

// 	t.Logf("Secrets: %v", secrets)

// }
