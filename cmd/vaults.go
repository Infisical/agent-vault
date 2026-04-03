package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/session"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Interact with vaults",
}

var vaultCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		body, err := json.Marshal(map[string]string{
			"name": name,
		})
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/vaults", sess.Address)
		respBody, err := doAdminRequestWithBody("POST", url, sess.Token, body)
		if err != nil {
			return err
		}

		var resp struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		_ = json.Unmarshal(respBody, &resp)

		fmt.Fprintf(cmd.OutOrStdout(), "%s Created vault %q (id: %s)\n", successText("✓"), resp.Name, mutedText(resp.ID))
		return nil
	},
}

var vaultListCmd = &cobra.Command{
	Use:   "list",
	Short: "List vaults",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/vaults", sess.Address)
		respBody, err := doAdminRequestWithBody("GET", url, sess.Token, nil)
		if err != nil {
			return err
		}

		var resp struct {
			Vaults []struct {
				ID        string `json:"id"`
				Name      string `json:"name"`
				Role      string `json:"role"`
				CreatedAt string `json:"created_at"`
			} `json:"vaults"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if len(resp.Vaults) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "No vaults found.")
			return nil
		}

		t := newTable(cmd.OutOrStdout())
		t.AppendHeader(table.Row{"ID", "NAME", "ROLE", "CREATED"})
		for _, ns := range resp.Vaults {
			created := ns.CreatedAt
			if parsed, err := time.Parse(time.RFC3339, ns.CreatedAt); err == nil {
				created = parsed.Format("2006-01-02 15:04:05")
			}
			role := ns.Role
			if role == "" {
				role = "-"
			}
			t.AppendRow(table.Row{ns.ID, ns.Name, role, created})
		}
		t.Render()
		return nil
	},
}

// --- Vault context commands ---

var vaultUseCmd = &cobra.Command{
	Use:   "use <name>",
	Short: "Set the active vault for subsequent commands",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if err := session.SaveVaultContext(name); err != nil {
			return fmt.Errorf("saving vault context: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s Now using vault %q\n", successText("✓"), name)
		return nil
	},
}

var vaultCurrentCmd = &cobra.Command{
	Use:   "current",
	Short: "Show the active vault",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)
		fmt.Fprintln(cmd.OutOrStdout(), vault)
		return nil
	},
}

// --- Vault user subcommands ---

var vaultUserCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage vault users",
}

var vaultUserInviteCmd = &cobra.Command{
	Use:   "invite <email>",
	Short: "Invite a user to this vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		vaultName := resolveVault(cmd)
		role, _ := cmd.Flags().GetString("role")

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		body, err := json.Marshal(map[string]string{
			"email": email,
			"role":  role,
		})
		if err != nil {
			return err
		}

		reqURL := fmt.Sprintf("%s/v1/vaults/%s/invites", sess.Address, vaultName)
		respBody, err := doAdminRequestWithBody("POST", reqURL, sess.Token, body)
		if err != nil {
			return err
		}

		var result struct {
			EmailSent  bool   `json:"email_sent"`
			InviteLink string `json:"invite_link"`
		}
		_ = json.Unmarshal(respBody, &result)

		if result.EmailSent {
			fmt.Fprintf(cmd.OutOrStdout(), "%s Invitation sent to %s (vault: %s, role: %s)\n", successText("✓"), email, vaultName, role)
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "%s Invitation created. Share this link:\n  %s\n", successText("✓"), result.InviteLink)
		}
		return nil
	},
}

var vaultUserListCmd = &cobra.Command{
	Use:   "list",
	Short: "List vault users",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultName := resolveVault(cmd)

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/vaults/%s/users", sess.Address, vaultName)
		respBody, err := doAdminRequestWithBody("GET", url, sess.Token, nil)
		if err != nil {
			return err
		}

		var resp struct {
			Users []struct {
				Email string `json:"email"`
				Role  string `json:"role"`
			} `json:"users"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if len(resp.Users) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "No users found.")
			return nil
		}

		t := newTable(cmd.OutOrStdout())
		t.AppendHeader(table.Row{"EMAIL", "ROLE"})
		for _, m := range resp.Users {
			t.AppendRow(table.Row{m.Email, m.Role})
		}
		t.Render()
		return nil
	},
}

var vaultUserRemoveCmd = &cobra.Command{
	Use:   "remove <email>",
	Short: "Remove a user from the vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		vaultName := resolveVault(cmd)

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		reqURL := fmt.Sprintf("%s/v1/vaults/%s/users/%s", sess.Address, vaultName, url.PathEscape(email))
		if err := doAdminRequest("DELETE", reqURL, sess.Token, nil); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Removed %s from vault %s\n", successText("✓"), email, vaultName)
		return nil
	},
}

var vaultUserSetRoleCmd = &cobra.Command{
	Use:   "set-role <email>",
	Short: "Change a user's vault role",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		vaultName := resolveVault(cmd)
		role, _ := cmd.Flags().GetString("role")
		if role == "" {
			return fmt.Errorf("--role is required (admin or member)")
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		body, _ := json.Marshal(map[string]string{"role": role})
		reqURL := fmt.Sprintf("%s/v1/vaults/%s/users/%s/role", sess.Address, vaultName, url.PathEscape(email))
		if err := doAdminRequest("POST", reqURL, sess.Token, body); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s Set role %s for %s in vault %s\n", successText("✓"), role, email, vaultName)
		return nil
	},
}

var vaultRenameCmd = &cobra.Command{
	Use:   "rename <old-name> <new-name>",
	Short: "Rename a vault",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		oldName := args[0]
		newName := args[1]

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		body, err := json.Marshal(map[string]string{"name": newName})
		if err != nil {
			return err
		}

		reqURL := fmt.Sprintf("%s/v1/vaults/%s/rename", sess.Address, url.PathEscape(oldName))
		if err := doAdminRequest("POST", reqURL, sess.Token, body); err != nil {
			return err
		}

		// Update vault context if the renamed vault was the active one.
		if ctx := session.LoadVaultContext(); ctx == oldName {
			_ = session.SaveVaultContext(newName)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Vault renamed from %q to %q.\n", successText("✓"), oldName, newName)
		return nil
	},
}

var vaultDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a vault (vault admin or instance owner)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		yes, _ := cmd.Flags().GetBool("yes")
		if !yes {
			fmt.Fprintf(cmd.OutOrStderr(), "%s This will permanently delete vault %q and all its credentials, policies, and proposals.\n", warningText("WARNING"), name)
			fmt.Fprintf(cmd.OutOrStderr(), "Type %q to confirm: ", name)
			reader := bufio.NewReader(os.Stdin)
			answer, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("reading input: %w", err)
			}
			if strings.TrimSpace(answer) != name {
				fmt.Fprintln(cmd.OutOrStdout(), mutedText("Aborted."))
				return nil
			}
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		reqURL := fmt.Sprintf("%s/v1/vaults/%s", sess.Address, url.PathEscape(name))
		if err := doAdminRequest("DELETE", reqURL, sess.Token, nil); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Deleted vault %q\n", successText("✓"), name)
		return nil
	},
}

func init() {
	vaultCmd.PersistentFlags().String("vault", "", "target vault (overrides active context)")

	vaultDeleteCmd.Flags().Bool("yes", false, "Skip confirmation prompt")

	vaultCmd.AddCommand(vaultCreateCmd)
	vaultCmd.AddCommand(vaultListCmd)
	vaultCmd.AddCommand(vaultDeleteCmd)
	vaultCmd.AddCommand(vaultRenameCmd)
	vaultCmd.AddCommand(vaultUseCmd)
	vaultCmd.AddCommand(vaultCurrentCmd)

	vaultUserInviteCmd.Flags().String("role", "member", "role to grant (admin or member)")
	vaultUserSetRoleCmd.Flags().String("role", "", "role to set (admin or member)")

	vaultUserCmd.AddCommand(vaultUserInviteCmd, vaultUserListCmd, vaultUserRemoveCmd, vaultUserSetRoleCmd)
	vaultCmd.AddCommand(vaultUserCmd)

	rootCmd.AddCommand(vaultCmd)
}
