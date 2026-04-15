package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

var agentInviteCmd = &cobra.Command{
	Use:   "invite <name>",
	Short: "Invite an agent to the instance",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName := args[0]
		inviteTTL, _ := cmd.Flags().GetDuration("invite-ttl")
		vaultFlags, _ := cmd.Flags().GetStringArray("vault")
		tokenOnly, _ := cmd.Flags().GetBool("token-only")

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		addr := sess.Address
		if flagAddr, _ := cmd.Flags().GetString("address"); flagAddr != "" {
			addr = flagAddr
		}

		type vaultEntry struct {
			VaultName string `json:"vault_name"`
			VaultRole string `json:"vault_role"`
		}

		var vaults []vaultEntry
		for _, v := range vaultFlags {
			name, role, _ := strings.Cut(v, ":")
			if role == "" {
				role = "proxy"
			}
			vaults = append(vaults, vaultEntry{VaultName: name, VaultRole: role})
		}

		payload := map[string]any{
			"name":        agentName,
			"ttl_seconds": int(inviteTTL.Seconds()),
		}
		if len(vaults) > 0 {
			payload["vaults"] = vaults
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}

		reqURL := fmt.Sprintf("%s/v1/agents/invites", sess.Address)
		respBody, err := doAdminRequestWithBody("POST", reqURL, sess.Token, body)
		if err != nil {
			return err
		}

		var resp struct {
			Token     string `json:"token"`
			ExpiresAt string `json:"expires_at"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		inviteURL := addr + "/invite/" + resp.Token

		if tokenOnly {
			fmt.Fprint(cmd.OutOrStdout(), resp.Token)
			return nil
		}

		prompt := buildAgentInvitePrompt(inviteURL, inviteTTL)

		fmt.Fprintf(cmd.OutOrStdout(), "Agent invite created for %q (expires in %s).\n", agentName, formatDuration(inviteTTL))
		fmt.Fprintf(cmd.OutOrStdout(), "Paste the following into your agent:\n\n")
		fmt.Fprintf(cmd.OutOrStdout(), "---\n\n%s\n---\n", prompt)
		if err := copyToClipboard(prompt); err == nil {
			fmt.Fprintf(cmd.OutOrStdout(), "\n(Copied to clipboard)\n")
		}
		return nil
	},
}

var agentInviteListCmd = &cobra.Command{
	Use:   "list",
	Short: "List agent invites",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		status, _ := cmd.Flags().GetString("status")
		reqURL := fmt.Sprintf("%s/v1/agents/invites", sess.Address)
		if status != "" {
			reqURL += "?status=" + status
		}

		respBody, err := doAdminRequestWithBody("GET", reqURL, sess.Token, nil)
		if err != nil {
			return err
		}

		var resp struct {
			Invites []struct {
				AgentName string `json:"agent_name"`
				Status    string `json:"status"`
				CreatedBy string `json:"created_by"`
				CreatedAt string `json:"created_at"`
				ExpiresAt string `json:"expires_at"`
				Vaults    []struct {
					VaultName string `json:"vault_name"`
					VaultRole string `json:"vault_role"`
				} `json:"vaults"`
			} `json:"invites"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if len(resp.Invites) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "No agent invites found.")
			return nil
		}

		t := newTable(cmd.OutOrStdout())
		t.AppendHeader(table.Row{"NAME", "STATUS", "VAULTS", "INVITED BY", "CREATED", "EXPIRES"})
		for _, inv := range resp.Invites {
			var vaultParts []string
			for _, v := range inv.Vaults {
				vaultParts = append(vaultParts, fmt.Sprintf("%s:%s", v.VaultName, v.VaultRole))
			}
			vaults := strings.Join(vaultParts, ", ")
			if vaults == "" {
				vaults = "-"
			}
			created := inv.CreatedAt
			if parsed, err := time.Parse(time.RFC3339, inv.CreatedAt); err == nil {
				created = parsed.Format("2006-01-02 15:04")
			}
			expires := inv.ExpiresAt
			if parsed, err := time.Parse(time.RFC3339, inv.ExpiresAt); err == nil {
				expires = parsed.Format("2006-01-02 15:04")
			}
			t.AppendRow(table.Row{inv.AgentName, inv.Status, vaults, inv.CreatedBy, created, expires})
		}
		t.Render()
		return nil
	},
}

var agentInviteRevokeCmd = &cobra.Command{
	Use:   "revoke <token_suffix>",
	Short: "Revoke a pending agent invite",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		tokenSuffix := args[0]

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		reqURL := fmt.Sprintf("%s/v1/agents/invites/%s", sess.Address, tokenSuffix)
		if err := doAdminRequest("DELETE", reqURL, sess.Token, nil); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Agent invite revoked\n", successText("✓"))
		return nil
	},
}

func init() {
	agentInviteCmd.Flags().Duration("invite-ttl", 15*time.Minute, "invite link expiration time")
	agentInviteCmd.Flags().StringArray("vault", nil, "vault pre-assignment (format: name:role, role defaults to proxy)")
	agentInviteCmd.Flags().String("address", "", "Agent Vault server address (default: from session)")
	agentInviteCmd.Flags().Bool("token-only", false, "output only the raw invite token (for programmatic use)")
	agentInviteListCmd.Flags().String("status", "", "filter by status (pending, redeemed, expired, revoked)")

	agentInviteCmd.AddCommand(agentInviteListCmd, agentInviteRevokeCmd)
	topAgentCmd.AddCommand(agentInviteCmd)
}
