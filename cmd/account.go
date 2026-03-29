package cmd

import (
	"fmt"

	"github.com/Infisical/agent-vault/internal/session"
	"github.com/spf13/cobra"
)

var accountCmd = &cobra.Command{
	Use:   "account",
	Short: "Manage your account (whoami, change password, delete)",
}

var accountDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Permanently delete your account",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, err := loadSession()
		if err != nil {
			return err
		}

		_, err = doAdminRequestWithBody("DELETE", sess.Address+"/v1/auth/account", sess.Token, nil)
		if err != nil {
			return fmt.Errorf("account deletion failed: %w", err)
		}

		// Clear local session since the account no longer exists.
		_ = session.Clear()

		_, _ = fmt.Fprintln(cmd.OutOrStdout(), successText("✓")+" Account deleted.")
		return nil
	},
}

func init() {
	accountCmd.AddCommand(whoamiCmd)
	accountCmd.AddCommand(changePasswordCmd)
	accountCmd.AddCommand(accountDeleteCmd)
	rootCmd.AddCommand(accountCmd)
}
