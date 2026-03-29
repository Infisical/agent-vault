package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Manage agents",
}

var agentListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered agents",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, err := loadSession()
		if err != nil {
			return err
		}

		vault := resolveVault(cmd)
		url := sess.Address + "/v1/admin/agents?vault=" + vault

		respBody, err := doAdminRequestWithBody("GET", url, sess.Token, nil)
		if err != nil {
			return err
		}

		var result struct {
			Agents []struct {
				Name      string  `json:"name"`
				VaultID   string  `json:"vault_id"`
				VaultRole string  `json:"vault_role"`
				Status    string  `json:"status"`
				CreatedAt string  `json:"created_at"`
				RevokedAt *string `json:"revoked_at,omitempty"`
			} `json:"agents"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if len(result.Agents) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No agents found.")
			return nil
		}

		t := newTable(cmd.OutOrStdout())
		t.AppendHeader(table.Row{"NAME", "ROLE", "STATUS", "VAULT", "CREATED"})
		for _, ag := range result.Agents {
			t.AppendRow(table.Row{ag.Name, ag.VaultRole, statusBadge(ag.Status), ag.VaultID, ag.CreatedAt})
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
		sess, err := loadSession()
		if err != nil {
			return err
		}

		url := sess.Address + "/v1/admin/agents/" + name
		respBody, err := doAdminRequestWithBody("GET", url, sess.Token, nil)
		if err != nil {
			return err
		}

		var info struct {
			Name           string  `json:"name"`
			Vault          string  `json:"vault"`
			VaultRole      string  `json:"vault_role"`
			Status         string  `json:"status"`
			CreatedBy      string  `json:"created_by"`
			CreatedAt      string  `json:"created_at"`
			UpdatedAt      string  `json:"updated_at"`
			RevokedAt      *string `json:"revoked_at,omitempty"`
			ActiveSessions int     `json:"active_sessions"`
		}
		if err := json.Unmarshal(respBody, &info); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		w := cmd.OutOrStdout()
		_, _ = fmt.Fprintf(w, "%s\n", boldText("Agent: "+info.Name))
		_, _ = fmt.Fprintf(w, "%s %s\n", fieldLabel("Vault:"), info.Vault)
		_, _ = fmt.Fprintf(w, "%s %s\n", fieldLabel("Role:"), info.VaultRole)
		_, _ = fmt.Fprintf(w, "%s %s\n", fieldLabel("Status:"), statusBadge(info.Status))
		_, _ = fmt.Fprintf(w, "%s %s\n", fieldLabel("Created:"), info.CreatedAt)
		_, _ = fmt.Fprintf(w, "%s %s\n", fieldLabel("Updated:"), info.UpdatedAt)
		if info.RevokedAt != nil {
			_, _ = fmt.Fprintf(w, "%s %s\n", fieldLabel("Revoked:"), *info.RevokedAt)
		}
		_, _ = fmt.Fprintf(w, "%s %d\n", fieldLabel("Active sessions:"), info.ActiveSessions)
		return nil
	},
}

var agentRevokeCmd = &cobra.Command{
	Use:   "revoke <name>",
	Short: "Revoke an agent (invalidates service token and deletes sessions)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		sess, err := loadSession()
		if err != nil {
			return err
		}

		url := sess.Address + "/v1/admin/agents/" + name
		if err := doAdminRequest("DELETE", url, sess.Token, nil); err != nil {
			return err
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s Agent %q revoked.\n", successText("✓"), name)
		return nil
	},
}

var agentRotateCmd = &cobra.Command{
	Use:   "rotate <name>",
	Short: "Create a rotation invite to re-issue an agent's service token",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		sess, err := loadSession()
		if err != nil {
			return err
		}

		url := sess.Address + "/v1/admin/agents/" + name + "/rotate"
		respBody, err := doAdminRequestWithBody("POST", url, sess.Token, []byte("{}"))
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
		sess, err := loadSession()
		if err != nil {
			return err
		}

		body, err := json.Marshal(map[string]string{"name": newName})
		if err != nil {
			return err
		}

		url := sess.Address + "/v1/admin/agents/" + name + "/rename"
		if err := doAdminRequest("POST", url, sess.Token, body); err != nil {
			return err
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s Agent renamed from %q to %q.\n", successText("✓"), name, newName)
		return nil
	},
}

var agentSetRoleCmd = &cobra.Command{
	Use:   "set-role <name>",
	Short: "Set an agent's vault role",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		role, _ := cmd.Flags().GetString("role")
		if role == "" {
			return fmt.Errorf("--role is required (consumer, member, admin)")
		}
		if role != "consumer" && role != "member" && role != "admin" {
			return fmt.Errorf("--role must be one of: consumer, member, admin")
		}

		sess, err := loadSession()
		if err != nil {
			return err
		}

		body, err := json.Marshal(map[string]string{"role": role})
		if err != nil {
			return err
		}

		url := sess.Address + "/v1/admin/agents/" + name + "/vault-role"
		if err := doAdminRequest("POST", url, sess.Token, body); err != nil {
			return err
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s Agent %q role set to %q.\n", successText("✓"), name, role)
		return nil
	},
}

func init() {
	agentSetRoleCmd.Flags().String("role", "", "vault role (consumer, member, admin)")

	agentCmd.AddCommand(agentListCmd)
	agentCmd.AddCommand(agentInfoCmd)
	agentCmd.AddCommand(agentRevokeCmd)
	agentCmd.AddCommand(agentRotateCmd)
	agentCmd.AddCommand(agentRenameCmd)
	agentCmd.AddCommand(agentSetRoleCmd)
	vaultCmd.AddCommand(agentCmd)
}
