package cmd

import (
	"encoding/json"
	"fmt"
	neturl "net/url"
	"strings"

	"github.com/spf13/cobra"
)

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage users (owner only)",
}

var userInfoCmd = &cobra.Command{
	Use:   "info <email>",
	Short: "View user info (owner or self)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		email := args[0]

		url := sess.Address + "/v1/admin/users/" + neturl.PathEscape(email)
		respBody, err := doAdminRequestWithBody("GET", url, sess.Token, nil)
		if err != nil {
			return err
		}

		type vaultGrant struct {
			VaultName string `json:"vault_name"`
			VaultRole string `json:"vault_role"`
		}
		var result struct {
			Email     string       `json:"email"`
			Role      string       `json:"role"`
			Vaults    []vaultGrant `json:"vaults"`
			CreatedAt string       `json:"created_at"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Email:      %s\n", result.Email)
		fmt.Fprintf(cmd.OutOrStdout(), "Role:       %s\n", result.Role)
		var parts []string
		for _, v := range result.Vaults {
			parts = append(parts, v.VaultName+"("+v.VaultRole+")")
		}
		ns := strings.Join(parts, ", ")
		if ns == "" {
			ns = "(none)"
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Vaults: %s\n", ns)
		fmt.Fprintf(cmd.OutOrStdout(), "Created:    %s\n", result.CreatedAt)
		return nil
	},
}

var userRemoveCmd = &cobra.Command{
	Use:   "remove <email>",
	Short: "Remove a user (owner only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/admin/users/%s", sess.Address, neturl.PathEscape(email))
		if err := doAdminRequest("DELETE", url, sess.Token, nil); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s User %q removed.\n", successText("✓"), email)
		return nil
	},
}

var userSetRoleCmd = &cobra.Command{
	Use:   "set-role <email>",
	Short: "Set user role (owner only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		role, _ := cmd.Flags().GetString("role")
		if role == "" {
			return fmt.Errorf("--role is required (owner or member)")
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		body, err := json.Marshal(map[string]string{"role": role})
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/admin/users/%s/role", sess.Address, neturl.PathEscape(email))
		return doAdminRequest("POST", url, sess.Token, body)
	},
}

func init() {
	userSetRoleCmd.Flags().String("role", "", "role to set (owner or member)")

	userCmd.AddCommand(userInfoCmd, userRemoveCmd, userSetRoleCmd)
	ownerCmd.AddCommand(userCmd)
}
