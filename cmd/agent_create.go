package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var agentCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new agent and print its token",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName := args[0]
		vaultFlags, _ := cmd.Flags().GetStringArray("vault")
		tokenOnly, _ := cmd.Flags().GetBool("token-only")
		agentRole, _ := cmd.Flags().GetString("role")
		if !validInstanceRole(agentRole) {
			return fmt.Errorf("role must be one of: %s", instanceRoleHelp)
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		type vaultEntry struct {
			VaultName string `json:"vault_name"`
			VaultRole string `json:"vault_role"`
		}

		var vaults []vaultEntry
		for _, v := range vaultFlags {
			name, role, _ := strings.Cut(v, ":")
			vaults = append(vaults, vaultEntry{VaultName: name, VaultRole: role})
		}

		payload := map[string]any{
			"name": agentName,
			"role": agentRole,
		}
		if len(vaults) > 0 {
			payload["vaults"] = vaults
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}

		reqURL := sess.Address + "/v1/agents"
		respBody, err := doAdminRequestWithBody("POST", reqURL, sess.Token, body)
		if err != nil {
			return err
		}

		var resp struct {
			AvAgentToken string `json:"av_agent_token"`
			Name         string `json:"name"`
			Role         string `json:"role"`
			Vaults       []struct {
				VaultName string `json:"vault_name"`
				VaultRole string `json:"vault_role"`
			} `json:"vaults"`
			CreatedAt string `json:"created_at"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if tokenOnly {
			fmt.Fprint(cmd.OutOrStdout(), resp.AvAgentToken)
			return nil
		}

		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "%s Agent %q created (role %s).\n", successText("✓"), resp.Name, resp.Role)
		if len(resp.Vaults) > 0 {
			fmt.Fprintf(w, "%s\n", fieldLabel("Vaults:"))
			for _, v := range resp.Vaults {
				fmt.Fprintf(w, "  - %s (%s)\n", v.VaultName, v.VaultRole)
			}
		}
		fmt.Fprintf(w, "\n%s %s\n", fieldLabel("Agent token:"), resp.AvAgentToken)
		vaultHint := "<vault>"
		if len(resp.Vaults) > 0 {
			vaultHint = resp.Vaults[0].VaultName
		}
		fmt.Fprintf(w, "\nSet AGENT_VAULT_TOKEN, AGENT_VAULT_ADDR, and AGENT_VAULT_VAULT in the agent's environment, or run:\n")
		fmt.Fprintf(w, "  AGENT_VAULT_TOKEN=%q AGENT_VAULT_VAULT=%q agent-vault run -- <command>\n", resp.AvAgentToken, vaultHint)
		if len(resp.Vaults) > 1 {
			fmt.Fprintf(w, "\n(Multiple vaults were pre-assigned; pick the vault this run should use for AGENT_VAULT_VAULT or pass --vault.)\n")
		}

		if err := copyToClipboard(resp.AvAgentToken); err == nil {
			fmt.Fprintf(w, "\n(Token copied to clipboard)\n")
		}
		return nil
	},
}

func init() {
	agentCreateCmd.Flags().StringArray("vault", nil, "vault pre-assignment (format: name:role, role defaults to proxy)")
	agentCreateCmd.Flags().Bool("token-only", false, "output only the raw agent token (for programmatic use)")
	agentCreateCmd.Flags().String("role", "member", "instance-level role for the agent (owner, member, or no-access)")
	topAgentCmd.AddCommand(agentCreateCmd)
}
