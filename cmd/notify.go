package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var notifyCmd = &cobra.Command{
	Use:   "notify",
	Short: "Outbound notification commands (owner only)",
}

var notifyWebhookTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Send a test webhook notification to verify webhook configuration",
	Long:  `Send a synthetic proposal.created event to the configured AGENT_VAULT_NOTIFY_WEBHOOK_URL to verify it's set up correctly. Only owners can use this command.`,
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		addr := sess.Address
		if flagAddr, _ := cmd.Flags().GetString("address"); flagAddr != "" {
			addr = flagAddr
		}

		url := fmt.Sprintf("%s/v1/admin/notify/webhook/test", addr)
		if _, err := doAdminRequestWithBody("POST", url, sess.Token, nil); err != nil {
			return err
		}

		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Test webhook sent")
		return nil
	},
}

func init() {
	notifyWebhookTestCmd.Flags().String("address", "", "server address override")
	webhookCmd := &cobra.Command{
		Use:   "webhook",
		Short: "Outbound webhook notification commands",
	}
	webhookCmd.AddCommand(notifyWebhookTestCmd)
	notifyCmd.AddCommand(webhookCmd)
	ownerCmd.AddCommand(notifyCmd)
}
