package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

var emailCmd = &cobra.Command{
	Use:   "email",
	Short: "Email utilities",
}

var emailTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Send a test email to verify SMTP configuration",
	Long:  `Send a test email to verify that SMTP is configured correctly on the server. Only owners can use this command.`,
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, err := loadSession()
		if err != nil {
			return err
		}

		addr := sess.Address
		if flagAddr, _ := cmd.Flags().GetString("address"); flagAddr != "" {
			addr = flagAddr
		}

		to, _ := cmd.Flags().GetString("to")

		var reqBody []byte
		if to != "" {
			reqBody, _ = json.Marshal(map[string]string{"to": to})
		}

		url := fmt.Sprintf("%s/v1/admin/email/test", addr)
		respBody, err := doAdminRequestWithBody("POST", url, sess.Token, reqBody)
		if err != nil {
			return err
		}

		var result struct {
			Message string `json:"message"`
			To      string `json:"to"`
		}
		if json.Unmarshal(respBody, &result) == nil {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Test email sent to %s\n", result.To)
		}

		return nil
	},
}

func init() {
	emailTestCmd.Flags().String("to", "", "recipient email address (defaults to your own)")
	emailTestCmd.Flags().String("address", "", "server address override")
	emailCmd.AddCommand(emailTestCmd)
	ownerCmd.AddCommand(emailCmd)
}
