package cmd

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Infisical/agent-vault/internal/session"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
)

//go:embed skill_claude_code.md
var skillClaudeCode string

var runCmd = &cobra.Command{
	Use:   "run [flags] -- <command> [args...]",
	Short: "Wrap an agent process with Agent Vault access",
	Long: `Start an agent process (e.g. claude, agent, codex) with an Agent Vault session.
Everything after -- is treated as the command to execute.

The following environment variables are set on the child process:
  AGENT_VAULT_SESSION_TOKEN  — vault-scoped bearer token for the Agent Vault server
  AGENT_VAULT_ADDR           — base URL of the Agent Vault proxy endpoint
  AGENT_VAULT_VAULT          — vault the session is scoped to

Example:
  agent-vault vault run -- claude
  agent-vault vault run --vault myproject -- claude`,
	Args:                  cobra.MinimumNArgs(1),
	DisableFlagsInUseLine: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1. Load the admin session from agent-vault login.
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		addr, _ := cmd.Flags().GetString("address")
		if addr == "" {
			addr = sess.Address
		}

		// 2. Resolve the target vault: --vault flag > context > interactive select > "default".
		vault, err := resolveVaultForRun(cmd, addr, sess.Token)
		if err != nil {
			return err
		}

		// 3. Request a vault-scoped session token from the server.
		scopedToken, err := requestScopedSession(addr, sess.Token, vault)
		if err != nil {
			return err
		}

		// 4. Resolve the target binary.
		binary, err := exec.LookPath(args[0])
		if err != nil {
			return fmt.Errorf("command not found: %s", args[0])
		}

		// 5. Build env: inherit current env + inject Agent Vault vars.
		env := os.Environ()
		env = append(env,
			"AGENT_VAULT_SESSION_TOKEN="+scopedToken,
			"AGENT_VAULT_ADDR="+addr,
			"AGENT_VAULT_VAULT="+vault,
		)
		// 6. If the target command is a supported agent, offer to install the
		//    Agent Vault skill (only when not already present).
		if isClaudeCommand(args[0]) {
			maybeInstallSkill("Claude Code", filepath.Join(".claude", "skills", "agent-vault", "SKILL.md"))
		} else if isCursorCommand(args[0]) {
			maybeInstallSkill("Cursor", filepath.Join(".cursor", "skills", "agent-vault", "SKILL.md"))
		} else if isCodexCommand(args[0]) {
			maybeInstallSkill("Codex", filepath.Join(".agents", "skills", "agent-vault", "SKILL.md"))
		}

		// 7. Confirm, then exec — replaces this process entirely so the child
		//    (e.g. Claude Code) gets direct terminal control.
		fmt.Fprintf(os.Stderr, "%s agent-vault connected. Starting %s...\n\n", successText("agent-vault:"), boldText(args[0]))
		return syscall.Exec(binary, args, env)
	},
}

// isClaudeCommand returns true if the command name is "claude"
// (ignoring any path prefix). args[0] is always the base command;
// flags like --dangerously-skip-permissions are separate args.
func isClaudeCommand(cmd string) bool {
	return filepath.Base(cmd) == "claude"
}

// isCursorCommand returns true if the command name is "cursor" or "agent"
// (Cursor's CLI binary).
func isCursorCommand(cmd string) bool {
	base := filepath.Base(cmd)
	return base == "cursor" || base == "agent"
}

// isCodexCommand returns true if the command name is "codex".
func isCodexCommand(cmd string) bool {
	return filepath.Base(cmd) == "codex"
}

// maybeInstallSkill installs the Agent Vault skill to ~/{relPath} if it
// doesn't already exist, prompting the user for confirmation first.
// agentName is used in user-facing messages (e.g. "Claude Code", "Cursor").
func maybeInstallSkill(agentName, relPath string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	skillPath := filepath.Join(home, relPath)

	// Already installed — nothing to do.
	if _, err := os.Stat(skillPath); err == nil {
		return
	}

	fmt.Fprintf(os.Stderr, "Install Agent Vault skill for %s at %s? [Y/n] ", agentName, skillPath)
	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer != "" && answer != "y" && answer != "yes" {
		return
	}

	dir := filepath.Dir(skillPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not create skill directory: %v\n", err)
		return
	}
	if err := os.WriteFile(skillPath, []byte(skillClaudeCode), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not write skill file: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "%s Installed Agent Vault skill for %s.\n", successText("agent-vault:"), agentName)
}

// resolveVaultForRun picks the vault for a run session. Priority:
// --vault flag > vault context > interactive select (if multiple) > "default".
func resolveVaultForRun(cmd *cobra.Command, addr, token string) (string, error) {
	// Explicit --vault flag takes priority.
	if name, _ := cmd.Flags().GetString("vault"); name != "" {
		return name, nil
	}
	// Vault context (set by a previous command) is next.
	if ctx := session.LoadVaultContext(); ctx != "" {
		return ctx, nil
	}

	// Fetch vaults from the server to decide.
	vaults, err := fetchUserVaults(addr, token)
	if err != nil {
		// If we can't list vaults, fall back to "default".
		return store.DefaultVault, nil
	}

	switch len(vaults) {
	case 0:
		return store.DefaultVault, nil
	case 1:
		return vaults[0], nil
	default:
		var choice string
		opts := make([]huh.Option[string], len(vaults))
		for i, v := range vaults {
			opts[i] = huh.NewOption(v, v)
		}
		err := huh.NewSelect[string]().
			Title("Which vault?").
			Options(opts...).
			Value(&choice).
			Run()
		if err != nil {
			return "", fmt.Errorf("vault selection: %w", err)
		}
		return choice, nil
	}
}

// fetchUserVaults returns the names of vaults the current user has access to.
func fetchUserVaults(addr, token string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, addr+"/v1/vaults", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var result struct {
		Vaults []struct {
			Name string `json:"name"`
		} `json:"vaults"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	names := make([]string, len(result.Vaults))
	for i, v := range result.Vaults {
		names[i] = v.Name
	}
	return names, nil
}

// requestScopedSession calls the server to create a vault-scoped session
// and returns the scoped token.
func requestScopedSession(addr, adminToken, vault string) (string, error) {
	reqBody, err := json.Marshal(map[string]string{"vault": vault})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, addr+"/v1/sessions/scoped", bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not reach server at %s: %w", addr, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error != "" {
			return "", fmt.Errorf("failed to create scoped session: %s", errResp.Error)
		}
		return "", fmt.Errorf("failed to create scoped session (status %d)", resp.StatusCode)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("parsing scoped session response: %w", err)
	}
	return result.Token, nil
}

func init() {
	runCmd.Flags().String("address", "", "Agent Vault server address (defaults to session address)")

	vaultCmd.AddCommand(runCmd)
}
