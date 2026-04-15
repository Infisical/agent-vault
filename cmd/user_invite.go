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
	Short: "Manage users and invites",
}

var topUserListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all users in the instance",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		type vaultGrant struct {
			VaultName string `json:"vault_name"`
			VaultRole string `json:"vault_role"`
		}
		type usersListResult struct {
			Users []struct {
				Email     string       `json:"email"`
				Role      string       `json:"role"`
				Vaults    []vaultGrant `json:"vaults"`
				CreatedAt string       `json:"created_at"`
			} `json:"users"`
		}
		result, err := fetchAndDecode[usersListResult]("GET", "/v1/users")
		if err != nil {
			return err
		}

		if len(result.Users) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "No users found.")
			return nil
		}

		// Check if the response includes vault data (owner view).
		hasVaults := false
		for _, u := range result.Users {
			if len(u.Vaults) > 0 {
				hasVaults = true
				break
			}
		}

		t := newTable(cmd.OutOrStdout())
		if hasVaults {
			t.AppendHeader(table.Row{"EMAIL", "ROLE", "VAULTS", "CREATED"})
			for _, u := range result.Users {
				var parts []string
				for _, v := range u.Vaults {
					parts = append(parts, v.VaultName+"("+v.VaultRole+")")
				}
				ns := strings.Join(parts, ", ")
				if ns == "" {
					ns = "-"
				}
				t.AppendRow(table.Row{u.Email, u.Role, ns, u.CreatedAt})
			}
		} else {
			t.AppendHeader(table.Row{"EMAIL", "ROLE", "CREATED"})
			for _, u := range result.Users {
				t.AppendRow(table.Row{u.Email, u.Role, u.CreatedAt})
			}
		}
		t.Render()
		return nil
	},
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

		role, _ := cmd.Flags().GetString("role")
		if role != "" && role != "member" && role != "owner" {
			return fmt.Errorf("role must be 'owner' or 'member'")
		}

		payload := map[string]any{
			"email": email,
		}
		if role != "" && role != "member" {
			payload["role"] = role
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
				Role      string `json:"role"`
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
		t.AppendHeader(table.Row{"EMAIL", "ROLE", "STATUS", "VAULTS", "INVITED BY", "CREATED", "EXPIRES"})
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
			t.AppendRow(table.Row{inv.Email, inv.Role, inv.Status, vaults, inv.CreatedBy, created, expires})
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
	userInviteCmd.Flags().String("role", "", "instance role for the invited user (owner or member, default member)")
	userInviteCmd.Flags().StringArray("vault", nil, "vault pre-assignment (format: name:role, role defaults to member)")
	userInviteListCmd.Flags().String("status", "", "filter by status (pending, accepted, expired, revoked)")

	userInviteCmd.AddCommand(userInviteListCmd, userInviteRevokeCmd)
	topUserCmd.AddCommand(topUserListCmd, userInviteCmd)
	rootCmd.AddCommand(topUserCmd)
}
