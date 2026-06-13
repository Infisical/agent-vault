package cmd

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/pidfile"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/spf13/cobra"
)

// executeCommand runs the root command with the given args and captures output.
func executeCommand(args ...string) (string, error) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	return buf.String(), err
}

func TestCommandsRegistered(t *testing.T) {
	registered := make(map[string]bool)
	for _, c := range rootCmd.Commands() {
		registered[c.Name()] = true
	}

	expected := []string{"server", "auth", "vault", "owner", "account", "catalog", "user", "agent", "ca"}
	for _, name := range expected {
		if !registered[name] {
			t.Errorf("expected command %q to be registered, but it was not", name)
		}
	}
}

func TestCASubcommandsRegistered(t *testing.T) {
	caCmd := findSubcommand(rootCmd, "ca")
	if caCmd == nil {
		t.Fatal("ca command not found")
	}

	registered := make(map[string]bool)
	for _, c := range caCmd.Commands() {
		registered[c.Name()] = true
	}

	expected := []string{"fetch"}
	for _, name := range expected {
		if !registered[name] {
			t.Errorf("expected ca subcommand %q to be registered, but it was not", name)
		}
	}
}

func TestCAFetchFlags(t *testing.T) {
	caCmd := findSubcommand(rootCmd, "ca")
	if caCmd == nil {
		t.Fatal("ca command not found")
	}
	fetchCmd := findSubcommand(caCmd, "fetch")
	if fetchCmd == nil {
		t.Fatal("ca fetch subcommand not found")
	}

	for _, name := range []string{"output", "address"} {
		if fetchCmd.Flags().Lookup(name) == nil {
			t.Errorf("expected ca fetch flag --%s to be registered", name)
		}
	}
	if f := fetchCmd.Flags().ShorthandLookup("o"); f == nil {
		t.Error("expected ca fetch flag -o shorthand to be registered")
	}
}

func TestAuthSubcommandsRegistered(t *testing.T) {
	authCmd := findSubcommand(rootCmd, "auth")
	if authCmd == nil {
		t.Fatal("auth command not found")
	}

	registered := make(map[string]bool)
	for _, c := range authCmd.Commands() {
		registered[c.Name()] = true
	}

	expected := []string{"login", "register"}
	for _, name := range expected {
		if !registered[name] {
			t.Errorf("expected auth subcommand %q to be registered, but it was not", name)
		}
	}
}

func TestAccountSubcommandsRegistered(t *testing.T) {
	acctCmd := findSubcommand(rootCmd, "account")
	if acctCmd == nil {
		t.Fatal("account command not found")
	}

	registered := make(map[string]bool)
	for _, c := range acctCmd.Commands() {
		registered[c.Name()] = true
	}

	expected := []string{"whoami", "change-password", "delete"}
	for _, name := range expected {
		if !registered[name] {
			t.Errorf("expected account subcommand %q to be registered, but it was not", name)
		}
	}
}

func findSubcommand(parent *cobra.Command, name string) *cobra.Command {
	for _, c := range parent.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

func TestVaultSubcommandsRegistered(t *testing.T) {
	var vCmd *cobra.Command
	for _, c := range rootCmd.Commands() {
		if c.Name() == "vault" {
			vCmd = c
			break
		}
	}
	if vCmd == nil {
		t.Fatal("vault command not found")
	}

	registered := make(map[string]bool)
	for _, c := range vCmd.Commands() {
		registered[c.Name()] = true
	}

	expected := []string{"create", "list", "rename", "use", "current", "init", "user", "credential", "service", "proposal", "agent", "discover", "delete"}
	for _, name := range expected {
		if !registered[name] {
			t.Errorf("expected vault subcommand %q to be registered, but it was not", name)
		}
	}
}

func TestVaultCredentialStoreSubcommandsRegistered(t *testing.T) {
	vCmd := findSubcommand(rootCmd, "vault")
	if vCmd == nil {
		t.Fatal("vault command not found")
	}
	csCmd := findSubcommand(vCmd, "credential-store")
	if csCmd == nil {
		t.Fatal("credential-store command not found under vault")
	}

	registered := make(map[string]bool)
	for _, c := range csCmd.Commands() {
		registered[c.Name()] = true
	}
	for _, name := range []string{"show", "sync", "set"} {
		if !registered[name] {
			t.Errorf("expected credential-store subcommand %q to be registered", name)
		}
	}

	setCmd := findSubcommand(csCmd, "set")
	if setCmd == nil {
		t.Fatal("set command not found under credential-store")
	}
	for _, flag := range []string{"kind", "infisical-project-id", "infisical-environment", "infisical-path", "poll-interval-seconds", "yes"} {
		if setCmd.Flags().Lookup(flag) == nil {
			t.Errorf("expected credential-store set to define --%s flag", flag)
		}
	}
}

func TestVaultCredentialStoreSetRequiresKind(t *testing.T) {
	// Missing --kind should fail before any network call.
	_, err := executeCommand("vault", "credential-store", "set", "my-app", "--yes")
	if err == nil {
		t.Fatal("expected error when --kind is omitted")
	}
}

func TestOwnerVaultSubcommandsRegistered(t *testing.T) {
	oCmd := findSubcommand(rootCmd, "owner")
	if oCmd == nil {
		t.Fatal("owner command not found")
	}
	vCmd := findSubcommand(oCmd, "vault")
	if vCmd == nil {
		t.Fatal("vault command not found under owner")
	}

	registered := make(map[string]bool)
	for _, c := range vCmd.Commands() {
		registered[c.Name()] = true
	}

	expected := []string{"list", "delete"}
	for _, name := range expected {
		if !registered[name] {
			t.Errorf("expected owner vault subcommand %q to be registered, but it was not", name)
		}
	}
}

func TestServiceSubcommandsRegistered(t *testing.T) {
	var vCmd *cobra.Command
	for _, c := range rootCmd.Commands() {
		if c.Name() == "vault" {
			vCmd = c
			break
		}
	}
	if vCmd == nil {
		t.Fatal("vault command not found")
	}

	svcCmd := findSubcommand(vCmd, "service")
	if svcCmd == nil {
		t.Fatal("service command not found under vault")
	}

	registered := make(map[string]bool)
	for _, c := range svcCmd.Commands() {
		registered[c.Name()] = true
	}

	expected := []string{"list", "set", "add", "enable", "disable", "remove", "clear"}
	for _, name := range expected {
		if !registered[name] {
			t.Errorf("expected service subcommand %q to be registered, but it was not", name)
		}
	}
}

func TestVaultNoBrokerSubcommand(t *testing.T) {
	// Verify that the vault command no longer has a broker subcommand.
	var nsCmd *cobra.Command
	for _, c := range rootCmd.Commands() {
		if c.Name() == "vault" {
			nsCmd = c
			break
		}
	}
	if nsCmd == nil {
		t.Fatal("vault command not found")
	}

	for _, c := range nsCmd.Commands() {
		if c.Name() == "broker" {
			t.Error("vault command should no longer have a broker subcommand")
		}
	}
}

func TestServerSubcommandsRegistered(t *testing.T) {
	var srvCmd *cobra.Command
	for _, c := range rootCmd.Commands() {
		if c.Name() == "server" {
			srvCmd = c
			break
		}
	}
	if srvCmd == nil {
		t.Fatal("server command not found")
	}

	registered := make(map[string]bool)
	for _, c := range srvCmd.Commands() {
		registered[c.Name()] = true
	}

	expected := []string{"stop"}
	for _, name := range expected {
		if !registered[name] {
			t.Errorf("expected server subcommand %q to be registered, but it was not", name)
		}
	}
}

// TestServerCmd_RefusesWhenPIDFileLive ensures the server command bails out
// at the pre-flight stage when another live server already owns the PID file,
// without prompting for a password and without touching the file.
func TestServerCmd_RefusesWhenPIDFileLive(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	if err := os.MkdirAll(filepath.Join(tmp, ".agent-vault"), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	ownerProcess := exec.Command("sleep", "30")
	if err := ownerProcess.Start(); err != nil {
		t.Fatalf("start pid owner: %v", err)
	}
	defer func() {
		_ = ownerProcess.Process.Kill()
		_, _ = ownerProcess.Process.Wait()
	}()
	owner := ownerProcess.Process.Pid
	if err := pidfile.Write(owner); err != nil {
		t.Fatalf("seed pidfile: %v", err)
	}

	// Set a master password env var that would normally drive setup; the
	// pre-flight check must fire before we ever reach unlockOrSetup, so this
	// value should be irrelevant.
	t.Setenv("AGENT_VAULT_MASTER_PASSWORD", "irrelevant-because-we-bail-first")

	_, err := executeCommand("server", "--port", "0", "--mitm-port", "0")
	if err == nil {
		t.Fatal("expected error when another live server holds the PID file, got nil")
	}
	wantSubstr := fmt.Sprintf("server is already running (PID %d)", owner)
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Errorf("error %q does not name the live PID — want substring %q", err.Error(), wantSubstr)
	}

	// PID file must be untouched.
	got, err := pidfile.Read()
	if err != nil {
		t.Fatalf("Read after refusal: %v", err)
	}
	if got != owner {
		t.Errorf("pidfile contents = %d, want %d (file should not have been overwritten)", got, owner)
	}
}

func TestServerPasswordStdinFlag(t *testing.T) {
	var srvCmd *cobra.Command
	for _, c := range rootCmd.Commands() {
		if c.Name() == "server" {
			srvCmd = c
			break
		}
	}
	if srvCmd == nil {
		t.Fatal("server command not found")
	}

	f := srvCmd.Flags().Lookup("password-stdin")
	if f == nil {
		t.Fatal("expected --password-stdin flag on server command")
	}
	if f.DefValue != "false" {
		t.Errorf("expected --password-stdin default to be false, got %q", f.DefValue)
	}
}

func openTestDB(t *testing.T) *store.SQLiteStore {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Open(:memory:): %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestUnlockOrSetupWithPassword_Setup(t *testing.T) {
	db := openTestDB(t)
	password := []byte("test-master-password")

	mk, err := unlockOrSetupWithPassword(db, password)
	if err != nil {
		t.Fatalf("unlockOrSetupWithPassword (setup): %v", err)
	}
	defer mk.Wipe()

	if len(mk.Key()) != 32 {
		t.Errorf("expected 32-byte key, got %d bytes", len(mk.Key()))
	}
}

func TestUnlockOrSetupWithPassword_Unlock(t *testing.T) {
	db := openTestDB(t)

	// First call sets up the master key.
	mk1, err := unlockOrSetupWithPassword(db, []byte("my-password"))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	mk1.Wipe()

	// Second call unlocks with the same password.
	mk2, err := unlockOrSetupWithPassword(db, []byte("my-password"))
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	defer mk2.Wipe()

	if len(mk2.Key()) != 32 {
		t.Errorf("expected 32-byte key, got %d bytes", len(mk2.Key()))
	}
}

func TestUnlockOrSetupWithPassword_WrongPassword(t *testing.T) {
	db := openTestDB(t)

	// Setup with one password.
	mk, err := unlockOrSetupWithPassword(db, []byte("correct-password"))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	mk.Wipe()

	// Attempt unlock with wrong password.
	_, err = unlockOrSetupWithPassword(db, []byte("wrong-password"))
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
}

func TestEnvvarPasswordSetup(t *testing.T) {
	db := openTestDB(t)

	os.Setenv("AGENT_VAULT_MASTER_PASSWORD", "envvar-password")

	// Simulate what unlockOrSetup does for envvar path.
	envPw := os.Getenv("AGENT_VAULT_MASTER_PASSWORD")
	os.Unsetenv("AGENT_VAULT_MASTER_PASSWORD")

	mk, err := unlockOrSetupWithPassword(db, []byte(envPw))
	if err != nil {
		t.Fatalf("envvar setup: %v", err)
	}
	defer mk.Wipe()

	// Verify envvar was unset.
	if val := os.Getenv("AGENT_VAULT_MASTER_PASSWORD"); val != "" {
		t.Errorf("AGENT_VAULT_MASTER_PASSWORD should be unset after reading, got %q", val)
	}

	// Verify we can unlock with the same password.
	mk2, err := unlockOrSetupWithPassword(db, []byte("envvar-password"))
	if err != nil {
		t.Fatalf("unlock after envvar setup: %v", err)
	}
	mk2.Wipe()
}

func TestProposalSubcommandsRegistered(t *testing.T) {
	var vCmd *cobra.Command
	for _, c := range rootCmd.Commands() {
		if c.Name() == "vault" {
			vCmd = c
			break
		}
	}
	if vCmd == nil {
		t.Fatal("vault command not found")
	}

	csCmd := findSubcommand(vCmd, "proposal")
	if csCmd == nil {
		t.Fatal("proposal command not found under vault")
	}

	registered := make(map[string]bool)
	for _, c := range csCmd.Commands() {
		registered[c.Name()] = true
	}

	expected := []string{"list", "show", "approve", "reject", "create"}
	for _, name := range expected {
		if !registered[name] {
			t.Errorf("expected proposal subcommand %q to be registered, but it was not", name)
		}
	}
}

func TestAgentSubcommandsRegistered(t *testing.T) {
	// Vault-level agent commands: list, add, remove, set-role
	vCmd := findSubcommand(rootCmd, "vault")
	if vCmd == nil {
		t.Fatal("vault command not found")
	}
	agCmd := findSubcommand(vCmd, "agent")
	if agCmd == nil {
		t.Fatal("agent command not found under vault")
	}

	registered := make(map[string]bool)
	for _, c := range agCmd.Commands() {
		registered[c.Name()] = true
	}

	expected := []string{"list", "add", "remove", "set-role"}
	for _, name := range expected {
		if !registered[name] {
			t.Errorf("expected vault agent subcommand %q to be registered, but it was not", name)
		}
	}
}

func TestTopAgentSubcommandsRegistered(t *testing.T) {
	// Instance-level agent commands: list, info, revoke, delete, rotate, rename, create, set-role
	agCmd := findSubcommand(rootCmd, "agent")
	if agCmd == nil {
		t.Fatal("agent command not found")
	}

	registered := make(map[string]bool)
	for _, c := range agCmd.Commands() {
		registered[c.Name()] = true
	}

	expected := []string{"list", "info", "revoke", "delete", "rotate", "rename", "create", "set-role"}
	for _, name := range expected {
		if !registered[name] {
			t.Errorf("expected agent subcommand %q to be registered, but it was not", name)
		}
	}
}

func TestAgentCreateFlags(t *testing.T) {
	agCmd := findSubcommand(rootCmd, "agent")
	if agCmd == nil {
		t.Fatal("agent command not found")
	}
	createCmd := findSubcommand(agCmd, "create")
	if createCmd == nil {
		t.Fatal("create command not found under agent")
	}

	for _, name := range []string{"vault", "role", "token-only"} {
		if createCmd.Flags().Lookup(name) == nil {
			t.Errorf("expected agent create flag --%s to be registered", name)
		}
	}
}

func TestLoadProjectVault(t *testing.T) {
	// Run in a temp directory so we don't affect the real working directory.
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	t.Run("missing file returns empty", func(t *testing.T) {
		dir := t.TempDir()
		os.Chdir(dir)
		if got := loadProjectVault(); got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})

	t.Run("valid file returns vault name", func(t *testing.T) {
		dir := t.TempDir()
		os.Chdir(dir)
		os.WriteFile(ProjectConfigFile, []byte(`{"vault": "staging"}`), 0o600)
		if got := loadProjectVault(); got != "staging" {
			t.Errorf("expected %q, got %q", "staging", got)
		}
	})

	t.Run("malformed JSON returns empty", func(t *testing.T) {
		dir := t.TempDir()
		os.Chdir(dir)
		os.WriteFile(ProjectConfigFile, []byte(`not json`), 0o600)
		if got := loadProjectVault(); got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})

	t.Run("empty vault field returns empty", func(t *testing.T) {
		dir := t.TempDir()
		os.Chdir(dir)
		os.WriteFile(ProjectConfigFile, []byte(`{"vault": ""}`), 0o600)
		if got := loadProjectVault(); got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})
}

func TestResolveVaultWithProjectFile(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	t.Run("project file used when no flag", func(t *testing.T) {
		dir := t.TempDir()
		os.Chdir(dir)
		os.WriteFile(ProjectConfigFile, []byte(`{"vault": "team-vault"}`), 0o600)

		cmd := &cobra.Command{}
		cmd.Flags().String("vault", "", "")
		got := resolveVault(cmd)
		if got != "team-vault" {
			t.Errorf("expected %q, got %q", "team-vault", got)
		}
	})

	t.Run("flag takes priority over project file", func(t *testing.T) {
		dir := t.TempDir()
		os.Chdir(dir)
		os.WriteFile(ProjectConfigFile, []byte(`{"vault": "team-vault"}`), 0o600)

		cmd := &cobra.Command{}
		cmd.Flags().String("vault", "", "")
		cmd.Flags().Set("vault", "explicit")
		got := resolveVault(cmd)
		if got != "explicit" {
			t.Errorf("expected %q, got %q", "explicit", got)
		}
	})

	t.Run("falls back to default when no file", func(t *testing.T) {
		dir := t.TempDir()
		os.Chdir(dir)

		cmd := &cobra.Command{}
		cmd.Flags().String("vault", "", "")
		got := resolveVault(cmd)
		if got != store.DefaultVault {
			t.Errorf("expected %q, got %q", store.DefaultVault, got)
		}
	})
}

func TestResolveVaultWithEnvVar(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	t.Run("env var used when no flag", func(t *testing.T) {
		dir := t.TempDir()
		os.Chdir(dir)
		t.Setenv("AGENT_VAULT_VAULT", "env-vault")

		cmd := &cobra.Command{}
		cmd.Flags().String("vault", "", "")
		got := resolveVault(cmd)
		if got != "env-vault" {
			t.Errorf("expected %q, got %q", "env-vault", got)
		}
	})

	t.Run("flag takes priority over env var", func(t *testing.T) {
		dir := t.TempDir()
		os.Chdir(dir)
		t.Setenv("AGENT_VAULT_VAULT", "env-vault")

		cmd := &cobra.Command{}
		cmd.Flags().String("vault", "", "")
		cmd.Flags().Set("vault", "flag-vault")
		got := resolveVault(cmd)
		if got != "flag-vault" {
			t.Errorf("expected %q, got %q", "flag-vault", got)
		}
	})

	t.Run("env var takes priority over project file", func(t *testing.T) {
		dir := t.TempDir()
		os.Chdir(dir)
		os.WriteFile(ProjectConfigFile, []byte(`{"vault": "project-vault"}`), 0o600)
		t.Setenv("AGENT_VAULT_VAULT", "env-vault")

		cmd := &cobra.Command{}
		cmd.Flags().String("vault", "", "")
		got := resolveVault(cmd)
		if got != "env-vault" {
			t.Errorf("expected %q, got %q", "env-vault", got)
		}
	})
}

func TestResolveSessionFromEnvVars(t *testing.T) {
	t.Run("returns session from new env var name", func(t *testing.T) {
		t.Setenv("AGENT_VAULT_TOKEN", "test-token-123")
		t.Setenv("AGENT_VAULT_ADDR", "http://localhost:9999")

		sess, tokenSource, err := resolveSession()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tokenSource != "AGENT_VAULT_TOKEN" {
			t.Errorf("expected tokenSource=AGENT_VAULT_TOKEN, got %q", tokenSource)
		}
		if sess.Token != "test-token-123" {
			t.Errorf("expected token %q, got %q", "test-token-123", sess.Token)
		}
		if sess.Address != "http://localhost:9999" {
			t.Errorf("expected address %q, got %q", "http://localhost:9999", sess.Address)
		}
	})

	t.Run("token without addr is a clear error", func(t *testing.T) {
		t.Setenv("AGENT_VAULT_TOKEN", "test-token")
		t.Setenv("AGENT_VAULT_ADDR", "")

		_, _, err := resolveSession()
		if err == nil {
			t.Fatal("expected error when token is set but addr is missing")
		}
		if !strings.Contains(err.Error(), "AGENT_VAULT_ADDR") {
			t.Errorf("error should mention AGENT_VAULT_ADDR; got: %v", err)
		}
	})

	t.Run("trims trailing slash from address", func(t *testing.T) {
		t.Setenv("AGENT_VAULT_TOKEN", "test-token")
		t.Setenv("AGENT_VAULT_ADDR", "http://localhost:9999/")

		sess, _, err := resolveSession()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sess.Address != "http://localhost:9999" {
			t.Errorf("expected address without trailing slash, got %q", sess.Address)
		}
	})
}

func TestValidateEnvToken(t *testing.T) {
	t.Run("happy path: 200 OK with matching vault", func(t *testing.T) {
		var gotAuth, gotVault string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			gotVault = r.Header.Get("X-Vault")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"vault":"myvault"}`))
		}))
		defer srv.Close()

		if err := validateEnvToken(srv.URL, "tok123", "myvault", "AGENT_VAULT_TOKEN"); err != nil {
			t.Fatalf("expected nil err, got %v", err)
		}
		if gotAuth != "Bearer tok123" {
			t.Errorf("Authorization header = %q, want Bearer tok123", gotAuth)
		}
		if gotVault != "myvault" {
			t.Errorf("X-Vault header = %q, want myvault", gotVault)
		}
	})

	t.Run("401 produces friendly error naming the env var", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()

		err := validateEnvToken(srv.URL, "bad", "v", "AGENT_VAULT_TOKEN")
		if err == nil {
			t.Fatal("expected error on 401")
		}
		if !strings.Contains(err.Error(), "rejected by broker") {
			t.Errorf("expected friendly 'rejected by broker' message; got: %v", err)
		}
		if !strings.Contains(err.Error(), "AGENT_VAULT_TOKEN") {
			t.Errorf("expected error to name the env var; got: %v", err)
		}
	})

	t.Run("vault mismatch is rejected", func(t *testing.T) {
		// Broker returns the session's baked-in vault, ignoring the
		// X-Vault header on a vault-scoped session token.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"vault":"actual-vault","services":[],"available_credentials":[]}`))
		}))
		defer srv.Close()

		err := validateEnvToken(srv.URL, "tok", "requested-vault", "AGENT_VAULT_TOKEN")
		if err == nil {
			t.Fatal("expected mismatch error")
		}
		if !strings.Contains(err.Error(), "vault mismatch") {
			t.Errorf("expected 'vault mismatch' wording; got: %v", err)
		}
		if !strings.Contains(err.Error(), "actual-vault") || !strings.Contains(err.Error(), "requested-vault") {
			t.Errorf("expected both vault names in error; got: %v", err)
		}
	})

}

func TestProposalCreateFlagsRegistered(t *testing.T) {
	vCmd := findSubcommand(rootCmd, "vault")
	if vCmd == nil {
		t.Fatal("vault command not found")
	}
	pCmd := findSubcommand(vCmd, "proposal")
	if pCmd == nil {
		t.Fatal("proposal command not found")
	}
	createCmd := findSubcommand(pCmd, "create")
	if createCmd == nil {
		t.Fatal("create command not found under proposal")
	}

	expectedFlags := []string{"file", "name", "host", "auth-type", "token-key", "credential", "message", "user-message", "json", "username-key", "password-key", "api-key-key", "api-key-header", "api-key-prefix"}
	for _, name := range expectedFlags {
		if createCmd.Flags().Lookup(name) == nil {
			t.Errorf("expected flag --%s on proposal create command", name)
		}
	}
}

func TestDiscoverFlagsRegistered(t *testing.T) {
	vCmd := findSubcommand(rootCmd, "vault")
	if vCmd == nil {
		t.Fatal("vault command not found")
	}
	dCmd := findSubcommand(vCmd, "discover")
	if dCmd == nil {
		t.Fatal("discover command not found under vault")
	}

	if dCmd.Flags().Lookup("json") == nil {
		t.Error("expected --json flag on discover command")
	}
}

func TestUserInviteSubcommandsRegistered(t *testing.T) {
	uCmd := findSubcommand(rootCmd, "user")
	if uCmd == nil {
		t.Fatal("user command not found")
	}
	invCmd := findSubcommand(uCmd, "invite")
	if invCmd == nil {
		t.Fatal("invite command not found under user")
	}

	registered := make(map[string]bool)
	for _, c := range invCmd.Commands() {
		registered[c.Name()] = true
	}

	expected := []string{"list", "revoke"}
	for _, name := range expected {
		if !registered[name] {
			t.Errorf("expected user invite subcommand %q to be registered, but it was not", name)
		}
	}

	// Verify --vault flag on invite command
	f := invCmd.Flags().Lookup("vault")
	if f == nil {
		t.Fatal("expected --vault flag on user invite command")
	}
}

func TestVaultUserAddSubcommandRegistered(t *testing.T) {
	vCmd := findSubcommand(rootCmd, "vault")
	if vCmd == nil {
		t.Fatal("vault command not found")
	}
	userCmd := findSubcommand(vCmd, "user")
	if userCmd == nil {
		t.Fatal("user command not found under vault")
	}

	registered := make(map[string]bool)
	for _, c := range userCmd.Commands() {
		registered[c.Name()] = true
	}

	if !registered["add"] {
		t.Error("expected vault user subcommand \"add\" to be registered, but it was not")
	}
	if !registered["list"] {
		t.Error("expected vault user subcommand \"list\" to be registered, but it was not")
	}
}

func TestCatalogFlagsRegistered(t *testing.T) {
	catCmd := findSubcommand(rootCmd, "catalog")
	if catCmd == nil {
		t.Fatal("catalog command not found")
	}

	if catCmd.Flags().Lookup("json") == nil {
		t.Error("expected --json flag on catalog command")
	}
	if catCmd.Flags().Lookup("address") == nil {
		t.Error("expected --address flag on catalog command")
	}
}

func TestServerLogLevelFlag(t *testing.T) {
	srvCmd := findSubcommand(rootCmd, "server")
	if srvCmd == nil {
		t.Fatal("server command not found")
	}
	f := srvCmd.Flags().Lookup("log-level")
	if f == nil {
		t.Fatal("expected --log-level flag on server command")
	}
	if f.DefValue != "info" {
		t.Errorf("expected --log-level default to be info, got %q", f.DefValue)
	}
	if f.Shorthand != "" {
		t.Errorf("expected no shorthand for --log-level, got %q", f.Shorthand)
	}
}

func TestResolveLogLevel(t *testing.T) {
	// Isolate from any ambient env var in the developer's shell.
	t.Setenv("AGENT_VAULT_LOG_LEVEL", "")

	cases := []struct {
		name      string
		flag      string
		changed   bool
		env       string
		wantLevel string // "info" | "debug"
		wantErr   bool
	}{
		{name: "default", flag: "info", changed: false, wantLevel: "info"},
		{name: "flag_debug", flag: "debug", changed: true, wantLevel: "debug"},
		{name: "flag_info_explicit", flag: "info", changed: true, wantLevel: "info"},
		{name: "env_debug_no_flag", flag: "info", changed: false, env: "debug", wantLevel: "debug"},
		{name: "env_info_no_flag", flag: "info", changed: false, env: "info", wantLevel: "info"},
		{name: "flag_wins_over_env", flag: "info", changed: true, env: "debug", wantLevel: "info"},
		{name: "case_insensitive", flag: "info", changed: false, env: "DEBUG", wantLevel: "debug"},
		{name: "invalid_flag", flag: "verbose", changed: true, wantErr: true},
		{name: "invalid_env", flag: "info", changed: false, env: "trace", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AGENT_VAULT_LOG_LEVEL", tc.env)
			got, err := resolveLogLevel(tc.flag, tc.changed)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got level=%v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			gotName := "info"
			if got.String() == "DEBUG" {
				gotName = "debug"
			}
			if gotName != tc.wantLevel {
				t.Errorf("got level %s, want %s", gotName, tc.wantLevel)
			}
		})
	}
}

// Verify the cobra-level --log-level validation surfaces the error before
// the command tries to open the DB or touch the master key.
func TestServerLogLevelInvalidSurface(t *testing.T) {
	_, err := executeCommand("server", "--log-level", "verbose")
	if err == nil {
		t.Fatal("expected error for invalid --log-level")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("log level")) {
		t.Errorf("expected error to mention log level, got %v", err)
	}
	// Reset cobra state for the next test; the rootCmd retains flag values.
	if sc := findSubcommand(rootCmd, "server"); sc != nil {
		_ = sc.Flags().Set("log-level", "info")
	}
}
