package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

// topAgentCmd is the top-level "agent" command for instance-level agent management.
var topAgentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Manage agents (instance-level)",
}

var agentListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all agents",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		type agentListResult struct {
			Agents []struct {
				Name      string `json:"name"`
				Status    string `json:"status"`
				CreatedAt string `json:"created_at"`
				Vaults    []struct {
					VaultName string `json:"vault_name"`
					VaultRole string `json:"vault_role"`
				} `json:"vaults"`
			} `json:"agents"`
		}
		result, err := fetchAndDecode[agentListResult]("GET", "/v1/agents")
		if err != nil {
			return err
		}

		if len(result.Agents) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No agents found.")
			return nil
		}

		t := newTable(cmd.OutOrStdout())
		t.AppendHeader(table.Row{"NAME", "STATUS", "VAULTS", "CREATED"})
		for _, ag := range result.Agents {
			var vaultParts []string
			for _, v := range ag.Vaults {
				vaultParts = append(vaultParts, fmt.Sprintf("%s:%s", v.VaultName, v.VaultRole))
			}
			vaults := strings.Join(vaultParts, ", ")
			if vaults == "" {
				vaults = "-"
			}
			t.AppendRow(table.Row{ag.Name, statusBadge(ag.Status), vaults, ag.CreatedAt})
		}
		t.Render()
		return nil
	},
}

var agentInfoCmd = &cobra.Command{
	Use:   "info <name>",
	Short: "Show details of a registered agent",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		reqURL := sess.Address + "/v1/agents/" + url.PathEscape(name)
		respBody, err := doAdminRequestWithBody("GET", reqURL, sess.Token, nil)
		if err != nil {
			return err
		}

		var info struct {
			Name           string `json:"name"`
			Status         string `json:"status"`
			CreatedBy      string `json:"created_by"`
			CreatedAt      string `json:"created_at"`
			UpdatedAt      string `json:"updated_at"`
			RevokedAt      *string `json:"revoked_at,omitempty"`
			ActiveSessions int     `json:"active_sessions"`
			Vaults         []struct {
				VaultName string `json:"vault_name"`
				VaultRole string `json:"vault_role"`
			} `json:"vaults"`
		}
		if err := json.Unmarshal(respBody, &info); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		w := cmd.OutOrStdout()
		_, _ = fmt.Fprintf(w, "%s\n", boldText("Agent: "+info.Name))
		_, _ = fmt.Fprintf(w, "%s %s\n", fieldLabel("Status:"), statusBadge(info.Status))
		_, _ = fmt.Fprintf(w, "%s %s\n", fieldLabel("Created:"), info.CreatedAt)
		_, _ = fmt.Fprintf(w, "%s %s\n", fieldLabel("Updated:"), info.UpdatedAt)
		if info.RevokedAt != nil {
			_, _ = fmt.Fprintf(w, "%s %s\n", fieldLabel("Revoked:"), *info.RevokedAt)
		}
		_, _ = fmt.Fprintf(w, "%s %d\n", fieldLabel("Active sessions:"), info.ActiveSessions)
		if len(info.Vaults) > 0 {
			_, _ = fmt.Fprintf(w, "%s\n", fieldLabel("Vaults:"))
			for _, v := range info.Vaults {
				_, _ = fmt.Fprintf(w, "  - %s (%s)\n", v.VaultName, v.VaultRole)
			}
		} else {
			_, _ = fmt.Fprintf(w, "%s none\n", fieldLabel("Vaults:"))
		}
		return nil
	},
}

var agentRevokeCmd = &cobra.Command{
	Use:   "revoke <name>",
	Short: "Revoke an agent (deletes all sessions)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		reqURL := sess.Address + "/v1/agents/" + url.PathEscape(name)
		if err := doAdminRequest("DELETE", reqURL, sess.Token, nil); err != nil {
			return err
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s Agent %q revoked.\n", successText("✓"), name)
		return nil
	},
}

var agentRotateCmd = &cobra.Command{
	Use:   "rotate <name>",
	Short: "Create a rotation invite to re-issue an agent's session",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		reqURL := sess.Address + "/v1/agents/" + url.PathEscape(name) + "/rotate"
		respBody, err := doAdminRequestWithBody("POST", reqURL, sess.Token, []byte("{}"))
		if err != nil {
			return err
		}

		var result struct {
			InviteURL string `json:"invite_url"`
			Prompt    string `json:"prompt"`
			ExpiresIn string `json:"expires_in"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		w := cmd.OutOrStdout()
		_, _ = fmt.Fprintf(w, "Rotation invite created for agent %q (expires in %s).\n", name, result.ExpiresIn)
		_, _ = fmt.Fprintf(w, "Paste the following into the agent's chat:\n\n")
		_, _ = fmt.Fprintf(w, "---\n\n%s\n---\n", result.Prompt)

		if err := copyToClipboard(result.Prompt); err == nil {
			_, _ = fmt.Fprintf(w, "\n(Copied to clipboard)\n")
		}
		return nil
	},
}

var agentRenameCmd = &cobra.Command{
	Use:   "rename <name> <new-name>",
	Short: "Rename an agent",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		newName := args[1]
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		body, err := json.Marshal(map[string]string{"name": newName})
		if err != nil {
			return err
		}

		reqURL := sess.Address + "/v1/agents/" + url.PathEscape(name) + "/rename"
		if err := doAdminRequest("POST", reqURL, sess.Token, body); err != nil {
			return err
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s Agent renamed from %q to %q.\n", successText("✓"), name, newName)
		return nil
	},
}

// --- Vault-level agent commands (under "vault agent") ---

var vaultAgentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Manage vault agent access",
}

var vaultAgentListCmd = &cobra.Command{
	Use:   "list",
	Short: "List agents in a vault",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		reqURL := sess.Address + "/v1/vaults/" + url.PathEscape(vault) + "/agents"
		respBody, err := doAdminRequestWithBody("GET", reqURL, sess.Token, nil)
		if err != nil {
			return err
		}

		var result struct {
			Agents []struct {
				Name      string `json:"name"`
				VaultRole string `json:"vault_role"`
				Status    string `json:"status"`
			} `json:"agents"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if len(result.Agents) == 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No agents in vault %q.\n", vault)
			return nil
		}

		t := newTable(cmd.OutOrStdout())
		t.AppendHeader(table.Row{"NAME", "ROLE", "STATUS"})
		for _, ag := range result.Agents {
			t.AppendRow(table.Row{ag.Name, ag.VaultRole, statusBadge(ag.Status)})
		}
		t.Render()
		return nil
	},
}

var vaultAgentAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add an existing agent to this vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName := args[0]
		vault := resolveVault(cmd)
		role, _ := cmd.Flags().GetString("role")
		if role == "" {
			role = "proxy"
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		body, err := json.Marshal(map[string]string{"name": agentName, "role": role})
		if err != nil {
			return err
		}

		reqURL := sess.Address + "/v1/vaults/" + url.PathEscape(vault) + "/agents"
		if err := doAdminRequest("POST", reqURL, sess.Token, body); err != nil {
			return err
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s Agent %q added to vault %q with role %q.\n", successText("✓"), agentName, vault, role)
		return nil
	},
}

var vaultAgentRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove an agent from this vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName := args[0]
		vault := resolveVault(cmd)

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		reqURL := sess.Address + "/v1/vaults/" + url.PathEscape(vault) + "/agents/" + url.PathEscape(agentName)
		if err := doAdminRequest("DELETE", reqURL, sess.Token, nil); err != nil {
			return err
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s Agent %q removed from vault %q.\n", successText("✓"), agentName, vault)
		return nil
	},
}

var vaultAgentSetRoleCmd = &cobra.Command{
	Use:   "set-role <name>",
	Short: "Change an agent's vault role",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName := args[0]
		vault := resolveVault(cmd)
		role, _ := cmd.Flags().GetString("role")
		if role == "" {
			return fmt.Errorf("--role is required (proxy, member, admin)")
		}
		if role != "proxy" && role != "member" && role != "admin" {
			return fmt.Errorf("--role must be one of: proxy, member, admin")
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		body, err := json.Marshal(map[string]string{"role": role})
		if err != nil {
			return err
		}

		reqURL := sess.Address + "/v1/vaults/" + url.PathEscape(vault) + "/agents/" + url.PathEscape(agentName) + "/role"
		if err := doAdminRequest("POST", reqURL, sess.Token, body); err != nil {
			return err
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s Agent %q role in vault %q set to %q.\n", successText("✓"), agentName, vault, role)
		return nil
	},
}

func init() {
	vaultAgentAddCmd.Flags().String("role", "proxy", "vault role (proxy, member, admin)")
	vaultAgentSetRoleCmd.Flags().String("role", "", "vault role (proxy, member, admin)")

	// Instance-level agent commands: agent-vault agent [list|info|revoke|rotate|rename]
	topAgentCmd.AddCommand(agentListCmd)
	topAgentCmd.AddCommand(agentInfoCmd)
	topAgentCmd.AddCommand(agentRevokeCmd)
	topAgentCmd.AddCommand(agentRotateCmd)
	topAgentCmd.AddCommand(agentRenameCmd)
	rootCmd.AddCommand(topAgentCmd)

	// Vault-level agent commands: agent-vault vault agent [list|add|remove|set-role]
	vaultAgentCmd.AddCommand(vaultAgentListCmd)
	vaultAgentCmd.AddCommand(vaultAgentAddCmd)
	vaultAgentCmd.AddCommand(vaultAgentRemoveCmd)
	vaultAgentCmd.AddCommand(vaultAgentSetRoleCmd)
	vaultCmd.AddCommand(vaultAgentCmd)
}
