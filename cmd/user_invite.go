package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

// topUserCmd is the top-level "user" command (distinct from the owner-scoped userCmd).
var topUserCmd = &cobra.Command{
	Use:   "user",
	Short: "User commands (invites)",
}

var userInviteCmd = &cobra.Command{
	Use:   "invite <email>",
	Short: "Invite a user to the instance",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		vaultFlags, _ := cmd.Flags().GetStringArray("vault")

		type vaultEntry struct {
			VaultName string `json:"vault_name"`
			VaultRole string `json:"vault_role"`
		}

		var vaults []vaultEntry
		for _, v := range vaultFlags {
			name, role, _ := strings.Cut(v, ":")
			if role == "" {
				role = "member"
			}
			vaults = append(vaults, vaultEntry{VaultName: name, VaultRole: role})
		}

		payload := map[string]any{
			"email": email,
		}
		if len(vaults) > 0 {
			payload["vaults"] = vaults
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}

		reqURL := fmt.Sprintf("%s/v1/users/invites", sess.Address)
		respBody, err := doAdminRequestWithBody("POST", reqURL, sess.Token, body)
		if err != nil {
			return err
		}

		var resp struct {
			Email     string `json:"email"`
			EmailSent bool   `json:"email_sent"`
			InviteLink string `json:"invite_link"`
		}
		_ = json.Unmarshal(respBody, &resp)

		if resp.EmailSent {
			fmt.Fprintf(cmd.OutOrStdout(), "%s Invitation sent to %s\n", successText("✓"), resp.Email)
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "%s Invite created for %s\n", successText("✓"), resp.Email)
			fmt.Fprintf(cmd.OutOrStdout(), "  Share this link: %s\n", resp.InviteLink)
		}
		return nil
	},
}

var userInviteListCmd = &cobra.Command{
	Use:   "list",
	Short: "List user invites",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		status, _ := cmd.Flags().GetString("status")
		reqURL := fmt.Sprintf("%s/v1/users/invites", sess.Address)
		if status != "" {
			reqURL += "?status=" + status
		}

		respBody, err := doAdminRequestWithBody("GET", reqURL, sess.Token, nil)
		if err != nil {
			return err
		}

		var resp struct {
			Invites []struct {
				Email     string `json:"email"`
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
			fmt.Fprintln(cmd.OutOrStdout(), "No invites found.")
			return nil
		}

		t := newTable(cmd.OutOrStdout())
		t.AppendHeader(table.Row{"EMAIL", "STATUS", "VAULTS", "INVITED BY", "CREATED", "EXPIRES"})
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
			t.AppendRow(table.Row{inv.Email, inv.Status, vaults, inv.CreatedBy, created, expires})
		}
		t.Render()
		return nil
	},
}

var userInviteRevokeCmd = &cobra.Command{
	Use:   "revoke <token_suffix>",
	Short: "Revoke a pending invite",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		tokenSuffix := args[0]

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		reqURL := fmt.Sprintf("%s/v1/users/invites/%s", sess.Address, tokenSuffix)
		if err := doAdminRequest("DELETE", reqURL, sess.Token, nil); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Invite revoked\n", successText("✓"))
		return nil
	},
}

func init() {
	userInviteCmd.Flags().StringArray("vault", nil, "vault pre-assignment (format: name:role, role defaults to member)")
	userInviteListCmd.Flags().String("status", "", "filter by status (pending, accepted, expired, revoked)")

	userInviteCmd.AddCommand(userInviteListCmd, userInviteRevokeCmd)
	topUserCmd.AddCommand(userInviteCmd)
	rootCmd.AddCommand(topUserCmd)
}
