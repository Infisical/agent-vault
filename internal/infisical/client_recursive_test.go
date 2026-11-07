package infisical

import (
	"errors"
	"strings"
	"testing"

	"github.com/infisical/go-sdk/packages/models"
)

func TestListSecretsOptions_NonRecursiveUnchanged(t *testing.T) {
	opts := listSecretsOptions(VaultConfig{ProjectID: "p", Environment: "dev", SecretPath: "/app"})
	if opts.ProjectID != "p" || opts.Environment != "dev" || opts.SecretPath != "/app" {
		t.Fatalf("config fields not passed through: %+v", opts)
	}
	if !opts.ExpandSecretReferences {
		t.Fatalf("ExpandSecretReferences must stay enabled")
	}
	if opts.Recursive || opts.SkipUniqueValidation {
		t.Fatalf("non-recursive config must not set Recursive/SkipUniqueValidation: %+v", opts)
	}
}

// TestListSecretsOptions_RecursiveSetsSkipUniqueValidation: SkipUniqueValidation
// must accompany Recursive — without it the SDK dedups cross-folder duplicates
// by key with an arbitrary winner before we can detect and reject them.
func TestListSecretsOptions_RecursiveSetsSkipUniqueValidation(t *testing.T) {
	opts := listSecretsOptions(VaultConfig{ProjectID: "p", Environment: "dev", SecretPath: "/", Recursive: true})
	if !opts.Recursive {
		t.Fatalf("Recursive not set")
	}
	if !opts.SkipUniqueValidation {
		t.Fatalf("SkipUniqueValidation must be set when Recursive is")
	}
}

func TestSecretsFromList_MapsKeysAndValues(t *testing.T) {
	raw := []models.Secret{
		{SecretKey: "ALPHA", SecretValue: "a", SecretPath: "/"},
		{SecretKey: "BETA", SecretValue: "b", SecretPath: "/sub"},
	}
	secs, err := secretsFromList(raw, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secs) != 2 || secs[0] != (Secret{Key: "ALPHA", Value: "a"}) || secs[1] != (Secret{Key: "BETA", Value: "b"}) {
		t.Fatalf("bad mapping: %+v", secs)
	}
}

func TestSecretsFromList_DuplicateAcrossFolders(t *testing.T) {
	raw := []models.Secret{
		{SecretKey: "TOKEN", SecretValue: "1", SecretPath: "/stripe"},
		{SecretKey: "TOKEN", SecretValue: "2", SecretPath: "/github"},
		{SecretKey: "OTHER", SecretValue: "3", SecretPath: "/"},
	}
	_, err := secretsFromList(raw, true)
	if !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("expected ErrDuplicateKey, got %v", err)
	}
	for _, want := range []string{`"TOKEN"`, "/github", "/stripe"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}

	// The SDK refills its result slice from a map, so input order is
	// nondeterministic — the formatted error must not depend on it.
	reversed := []models.Secret{raw[2], raw[1], raw[0]}
	_, err2 := secretsFromList(reversed, true)
	if err2 == nil || err2.Error() != err.Error() {
		t.Fatalf("error text must be deterministic:\n%v\n%v", err, err2)
	}
}

// Defensive: in non-recursive mode the SDK already dedups by key, so the
// collision check must not run (and must not reject) there.
func TestSecretsFromList_NonRecursiveSkipsDuplicateCheck(t *testing.T) {
	raw := []models.Secret{
		{SecretKey: "TOKEN", SecretValue: "1"},
		{SecretKey: "TOKEN", SecretValue: "2"},
	}
	secs, err := secretsFromList(raw, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secs) != 2 {
		t.Fatalf("expected passthrough of 2 secrets, got %d", len(secs))
	}
}
