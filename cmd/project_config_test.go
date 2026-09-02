package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withWorkingDirectory(t *testing.T, dir string) {
	t.Helper()
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
}

func writeProjectConfig(t *testing.T, root, contents string) string {
	t.Helper()
	path := filepath.Join(root, ProjectConfigFile)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFindProjectConfigWalksToRepositoryRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	want := writeProjectConfig(t, root, `{"vault":"root-vault"}`)
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	withWorkingDirectory(t, nested)

	got, found, err := findProjectConfig()
	if err != nil {
		t.Fatalf("findProjectConfig: %v", err)
	}
	if !found || got != want {
		t.Fatalf("got path=%q found=%v, want path=%q found=true", got, found, want)
	}
}

func TestFindProjectConfigDoesNotCrossRepositoryRoot(t *testing.T) {
	parent := t.TempDir()
	writeProjectConfig(t, parent, `{"vault":"parent-vault"}`)
	root := filepath.Join(parent, "repo")
	nested := filepath.Join(root, "nested")
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	withWorkingDirectory(t, nested)

	path, found, err := findProjectConfig()
	if err != nil {
		t.Fatalf("findProjectConfig: %v", err)
	}
	if found || path != "" {
		t.Fatalf("got path=%q found=%v, want no config", path, found)
	}
}

func TestResolveRunProfile(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeProjectConfig(t, root, `{
  "version": 1,
  "address": "https://vault.example.test/",
  "profiles": {
    "development": {
      "vault": "app-dev",
      "env": {"API_KEY": "__api_key__", "PUBLIC_URL": "https://app.example.test"}
    }
  }
}`)
	nested := filepath.Join(root, "cmd", "worker")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	withWorkingDirectory(t, nested)

	cmd := newRunCmdForTest()
	if err := cmd.Flags().Set("profile", "development"); err != nil {
		t.Fatal(err)
	}
	profile, err := resolveRunProfile(cmd)
	if err != nil {
		t.Fatalf("resolveRunProfile: %v", err)
	}
	if profile.Vault != "app-dev" {
		t.Fatalf("unexpected profile: %#v", profile)
	}
	if profile.Address != "https://vault.example.test" {
		t.Errorf("address=%q, want normalized address", profile.Address)
	}
	if profile.Env["API_KEY"] != "__api_key__" {
		t.Errorf("profile env was not loaded")
	}
}

func TestResolveRunProfileRejectsVaultFlag(t *testing.T) {
	cmd := newRunCmdForTest()
	if err := cmd.Flags().Set("profile", "development"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("vault", "explicit"); err != nil {
		t.Fatal(err)
	}
	_, err := resolveRunProfile(cmd)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("got err=%v, want mutually-exclusive error", err)
	}
}

func TestResolveRunProfileUnknownListsAvailableNames(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeProjectConfig(t, root, `{"version":1,"profiles":{"prod":{"vault":"prod"},"dev":{"vault":"dev"}}}`)
	withWorkingDirectory(t, root)

	cmd := newRunCmdForTest()
	if err := cmd.Flags().Set("profile", "missing"); err != nil {
		t.Fatal(err)
	}
	_, err := resolveRunProfile(cmd)
	if err == nil || !strings.Contains(err.Error(), "available: dev, prod") {
		t.Fatalf("got err=%v, want sorted available profiles", err)
	}
}

func TestLoadProjectConfigRejectsReservedEnvWithoutLeakingValue(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	const sensitiveValue = "must-not-appear-in-errors"
	writeProjectConfig(t, root, `{"version":1,"profiles":{"dev":{"vault":"dev","env":{"HTTPS_PROXY":"`+sensitiveValue+`"}}}}`)
	withWorkingDirectory(t, root)

	_, _, _, err := loadProjectConfig()
	if err == nil || !strings.Contains(err.Error(), "HTTPS_PROXY") {
		t.Fatalf("got err=%v, want reserved-key error", err)
	}
	if strings.Contains(err.Error(), sensitiveValue) {
		t.Fatal("validation error leaked an environment value")
	}
}

func TestValidateProjectConfigRejectsNULWithoutLeakingValue(t *testing.T) {
	cfg := projectConfig{
		Version: 1,
		Profiles: map[string]projectProfile{
			"dev": {Vault: "dev", Env: map[string]string{"API_KEY": "prefix\x00sensitive-suffix"}},
		},
	}
	err := validateProjectConfig(&cfg)
	if err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("got err=%v, want NUL error", err)
	}
	if strings.Contains(err.Error(), "sensitive-suffix") {
		t.Fatal("validation error leaked an environment value")
	}
}

func TestValidateProfileEnvKey(t *testing.T) {
	for _, key := range []string{
		"AGENT_VAULT_TOKEN",
		"https_proxy",
		"ALL_PROXY",
		"SSL_CERT_FILE",
		"PATH",
		"HOME",
		"LD_PRELOAD",
		"DYLD_INSERT_LIBRARIES",
	} {
		t.Run(key, func(t *testing.T) {
			if err := validateProfileEnvKey(key); err == nil {
				t.Fatalf("expected %s to be reserved", key)
			}
		})
	}
	for _, key := range []string{"API_KEY", "APP_API_URL", "CLOUDFLARE_ZONE_ID"} {
		t.Run(key, func(t *testing.T) {
			if err := validateProfileEnvKey(key); err != nil {
				t.Fatalf("expected %s to be allowed: %v", key, err)
			}
		})
	}
}

func TestValidateProjectConfigVersionsAndAddress(t *testing.T) {
	tests := []struct {
		name string
		cfg  projectConfig
		want string
	}{
		{"legacy vault is valid", projectConfig{Vault: "legacy"}, ""},
		{"profiles require version", projectConfig{Profiles: map[string]projectProfile{"dev": {Vault: "dev"}}}, "require version 1"},
		{"future version rejected", projectConfig{Version: 2}, "unsupported version"},
		{"address path rejected", projectConfig{Version: 1, Address: "https://vault.example.test/control"}, "must not contain a path"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateProjectConfig(&tc.cfg)
			if tc.want == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("got err=%v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestBuildHostRunEnvProfileAndGeneratedPrecedence(t *testing.T) {
	parent := []string{
		"API_KEY=parent-value",
		"PUBLIC_URL=https://old.example.test",
		"AGENT_VAULT_TOKEN=stale-token",
		"UNRELATED=preserved",
	}
	profileEnv := map[string]string{
		"API_KEY":    "__api_key__",
		"PUBLIC_URL": "https://new.example.test",
	}
	env := envMap(buildHostRunEnv(parent, profileEnv, "fresh-token", "https://vault.example.test", "dev"))

	if env["API_KEY"] != "__api_key__" || env["PUBLIC_URL"] != "https://new.example.test" {
		t.Errorf("profile values did not override parent values: %#v", env)
	}
	if env["AGENT_VAULT_TOKEN"] != "fresh-token" || env["AGENT_VAULT_VAULT"] != "dev" {
		t.Errorf("generated Agent Vault values did not win: %#v", env)
	}
	if env["UNRELATED"] != "preserved" {
		t.Error("unrelated inherited environment value was dropped")
	}
}

func TestBuildContainerRunEnvIncludesProfileAndGeneratedValues(t *testing.T) {
	env := envMap(buildContainerRunEnv(
		map[string]string{"API_KEY": "__api_key__"},
		"fresh-token",
		"dev",
		14321,
		14322,
	))
	if env["API_KEY"] != "__api_key__" {
		t.Error("profile environment value was not passed to the container")
	}
	if env["AGENT_VAULT_TOKEN"] != "fresh-token" || env["AGENT_VAULT_VAULT"] != "dev" {
		t.Errorf("generated Agent Vault values are missing: %#v", env)
	}
	if env["HTTPS_PROXY"] == "" || env["SSL_CERT_FILE"] == "" {
		t.Error("generated proxy environment values are missing")
	}
}

func TestResolveSessionWithAddressSupportsAgentModeOverride(t *testing.T) {
	t.Setenv("AGENT_VAULT_TOKEN", "test-token")
	t.Setenv("AGENT_VAULT_ADDR", "")

	sess, source, err := resolveSessionWithAddress("https://vault.example.test/")
	if err != nil {
		t.Fatalf("resolveSessionWithAddress: %v", err)
	}
	if source != "AGENT_VAULT_TOKEN" || sess.Address != "https://vault.example.test" {
		t.Fatalf("unexpected session=%#v source=%q", sess, source)
	}
}

func TestResolveRunAddressPrecedence(t *testing.T) {
	t.Setenv("AGENT_VAULT_ADDR", "https://env.example.test")

	cmd := newRunCmdForTest()
	if got := resolveRunAddress(cmd, "https://profile.example.test"); got != "https://env.example.test" {
		t.Fatalf("env address=%q, want env address", got)
	}
	if err := cmd.Flags().Set("address", "https://flag.example.test"); err != nil {
		t.Fatal(err)
	}
	if got := resolveRunAddress(cmd, "https://profile.example.test"); got != "https://flag.example.test" {
		t.Fatalf("flag address=%q, want flag address", got)
	}

	t.Setenv("AGENT_VAULT_ADDR", "")
	cmd = newRunCmdForTest()
	if got := resolveRunAddress(cmd, "https://profile.example.test"); got != "https://profile.example.test" {
		t.Fatalf("profile address=%q, want profile address", got)
	}
}
