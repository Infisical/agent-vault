package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"syscall"

	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run [flags] -- <command> [args...]",
	Short: "Wrap an agent process with Agent Vault access",
	Long: `Start an agent process (e.g. claude, cursor) with an Agent Vault session.
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
		sess, err := loadSession()
		if err != nil {
			return err
		}

		vault := resolveVault(cmd)
		addr, _ := cmd.Flags().GetString("address")
		if addr == "" {
			addr = sess.Address
		}

		// 2. Request a vault-scoped session token from the server.
		scopedToken, err := requestScopedSession(addr, sess.Token, vault)
		if err != nil {
			return err
		}

		// 3. Resolve the target binary.
		binary, err := exec.LookPath(args[0])
		if err != nil {
			return fmt.Errorf("command not found: %s", args[0])
		}

		// 4. Build env: inherit current env + inject Agent Vault vars.
		env := os.Environ()
		env = append(env,
			"AGENT_VAULT_SESSION_TOKEN="+scopedToken,
			"AGENT_VAULT_ADDR="+addr,
			"AGENT_VAULT_VAULT="+vault,
		)
		// 5. Confirm, then exec — replaces this process entirely so the child
		//    (e.g. Claude Code) gets direct terminal control.
		fmt.Fprintf(os.Stderr, "%s agent-vault connected. Starting %s...\n\n", successText("agent-vault:"), boldText(args[0]))
		return syscall.Exec(binary, args, env)
	},
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
