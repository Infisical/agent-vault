package cmd

import (
	"bytes"
	"os"
	"testing"

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

	expected := []string{"server", "login", "register", "vault", "owner", "account"}
	for _, name := range expected {
		if !registered[name] {
			t.Errorf("expected command %q to be registered, but it was not", name)
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

	expected := []string{"create", "list", "rename", "use", "current", "user", "credentials", "policy", "proposal", "agent"}
	for _, name := range expected {
		if !registered[name] {
			t.Errorf("expected vault subcommand %q to be registered, but it was not", name)
		}
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

	expected := []string{"list", "remove"}
	for _, name := range expected {
		if !registered[name] {
			t.Errorf("expected owner vault subcommand %q to be registered, but it was not", name)
		}
	}
}

func TestPolicySubcommandsRegistered(t *testing.T) {
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

	polCmd := findSubcommand(vCmd, "policy")
	if polCmd == nil {
		t.Fatal("policy command not found under vault")
	}

	registered := make(map[string]bool)
	for _, c := range polCmd.Commands() {
		registered[c.Name()] = true
	}

	expected := []string{"get", "set", "clear"}
	for _, name := range expected {
		if !registered[name] {
			t.Errorf("expected policy subcommand %q to be registered, but it was not", name)
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

	expected := []string{"list", "show", "approve", "reject"}
	for _, name := range expected {
		if !registered[name] {
			t.Errorf("expected proposal subcommand %q to be registered, but it was not", name)
		}
	}
}

func TestAgentSubcommandsRegistered(t *testing.T) {
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

	expected := []string{"invite", "list", "info", "revoke", "rotate", "rename"}
	for _, name := range expected {
		if !registered[name] {
			t.Errorf("expected agent subcommand %q to be registered, but it was not", name)
		}
	}
}

func TestInviteCreatePersistentFlags(t *testing.T) {
	// Find vault > agent > invite > create command.
	vCmd := findSubcommand(rootCmd, "vault")
	if vCmd == nil {
		t.Fatal("vault command not found")
	}
	agCmd := findSubcommand(vCmd, "agent")
	if agCmd == nil {
		t.Fatal("agent command not found under vault")
	}

	var invCmd *cobra.Command
	for _, c := range agCmd.Commands() {
		if c.Name() == "invite" {
			invCmd = c
			break
		}
	}
	if invCmd == nil {
		t.Fatal("invite command not found under agent")
	}

	var createCmd *cobra.Command
	for _, c := range invCmd.Commands() {
		if c.Name() == "create" {
			createCmd = c
			break
		}
	}
	if createCmd == nil {
		t.Fatal("create command not found under invite")
	}

	// Verify --persistent flag exists.
	f := createCmd.Flags().Lookup("persistent")
	if f == nil {
		t.Fatal("expected --persistent flag on invite create command")
	}
	if f.DefValue != "false" {
		t.Errorf("expected --persistent default to be false, got %q", f.DefValue)
	}

	// Verify --name flag exists.
	f = createCmd.Flags().Lookup("name")
	if f == nil {
		t.Fatal("expected --name flag on invite create command")
	}
	if f.DefValue != "" {
		t.Errorf("expected --name default to be empty, got %q", f.DefValue)
	}
}

func TestInviteCreateDirectFlags(t *testing.T) {
	// Find vault > agent > invite > create command.
	vCmd := findSubcommand(rootCmd, "vault")
	if vCmd == nil {
		t.Fatal("vault command not found")
	}
	agCmd := findSubcommand(vCmd, "agent")
	if agCmd == nil {
		t.Fatal("agent command not found under vault")
	}

	var invCmd *cobra.Command
	for _, c := range agCmd.Commands() {
		if c.Name() == "invite" {
			invCmd = c
			break
		}
	}
	if invCmd == nil {
		t.Fatal("invite command not found under agent")
	}

	var createCmd *cobra.Command
	for _, c := range invCmd.Commands() {
		if c.Name() == "create" {
			createCmd = c
			break
		}
	}
	if createCmd == nil {
		t.Fatal("create command not found under invite")
	}

	// Verify --direct flag exists.
	f := createCmd.Flags().Lookup("direct")
	if f == nil {
		t.Fatal("expected --direct flag on invite create command")
	}
	if f.DefValue != "false" {
		t.Errorf("expected --direct default to be false, got %q", f.DefValue)
	}

	// Verify --label flag exists.
	f = createCmd.Flags().Lookup("label")
	if f == nil {
		t.Fatal("expected --label flag on invite create command")
	}
	if f.DefValue != "" {
		t.Errorf("expected --label default to be empty, got %q", f.DefValue)
	}
}
