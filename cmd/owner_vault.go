package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

var ownerVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Manage vaults (owner only)",
}

var ownerVaultListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all vaults across the instance (owner only)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		url := sess.Address + "/v1/admin/vaults"
		respBody, err := doAdminRequestWithBody("GET", url, sess.Token, nil)
		if err != nil {
			return err
		}

		var resp struct {
			Vaults []struct {
				ID        string `json:"id"`
				Name      string `json:"name"`
				CreatedAt string `json:"created_at"`
			} `json:"vaults"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if len(resp.Vaults) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No vaults found.")
			return nil
		}

		t := newTable(cmd.OutOrStdout())
		t.AppendHeader(table.Row{"ID", "NAME", "CREATED"})
		for _, v := range resp.Vaults {
			created := v.CreatedAt
			if parsed, err := time.Parse(time.RFC3339, v.CreatedAt); err == nil {
				created = parsed.Format("2006-01-02 15:04:05")
			}
			t.AppendRow(table.Row{v.ID, v.Name, created})
		}
		t.Render()
		return nil
	},
}

var ownerVaultRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a vault (owner only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/vaults/%s", sess.Address, name)
		if err := doAdminRequest("DELETE", url, sess.Token, nil); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Removed vault %q\n", successText("✓"), name)
		return nil
	},
}

var ownerVaultJoinCmd = &cobra.Command{
	Use:   "join <name>",
	Short: "Join a vault as admin (owner only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/vaults/%s/join", sess.Address, name)
		if err := doAdminRequest("POST", url, sess.Token, nil); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Joined vault %q as admin\n", successText("✓"), name)
		return nil
	},
}

func init() {
	ownerVaultCmd.AddCommand(ownerVaultListCmd, ownerVaultRemoveCmd, ownerVaultJoinCmd)
	ownerCmd.AddCommand(ownerVaultCmd)
}
