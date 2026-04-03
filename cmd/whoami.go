package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show current user and session info",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		url := sess.Address + "/v1/admin/users/me"
		respBody, err := doAdminRequestWithBody("GET", url, sess.Token, nil)
		if err != nil {
			return err
		}

		var result struct {
			Email     string   `json:"email"`
			Role      string   `json:"role"`
			Vaults    []string `json:"vaults"`
			CreatedAt string   `json:"created_at"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Email:      %s\n", result.Email)
		fmt.Fprintf(cmd.OutOrStdout(), "Role:       %s\n", result.Role)
		vaults := strings.Join(result.Vaults, ", ")
		if vaults == "" {
			vaults = "(none)"
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Vaults:     %s\n", vaults)
		fmt.Fprintf(cmd.OutOrStdout(), "Server:     %s\n", sess.Address)
		fmt.Fprintf(cmd.OutOrStdout(), "Created:    %s\n", result.CreatedAt)
		return nil
	},
}

