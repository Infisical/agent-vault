package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/Infisical/agent-vault/internal/session"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

var authSessionsCmd = &cobra.Command{
	Use:   "sessions",
	Short: "Manage your active CLI/web logins (parity with `gh auth status`)",
}

var authSessionsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active sessions for the logged-in user",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		out, err := fetchAndDecode[authSessionsListResponse]("GET", "/v1/auth/sessions")
		if err != nil {
			return err
		}
		if len(out.Sessions) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "No active sessions.")
			return nil
		}
		t := newTable(cmd.OutOrStdout())
		t.AppendHeader(table.Row{"ID", "DEVICE", "LAST IP", "LAST USED", "EXPIRES", "CURRENT"})
		for _, s := range out.Sessions {
			marker := ""
			if s.Current {
				marker = "✓"
			}
			t.AppendRow(table.Row{s.ID, s.DeviceLabel, s.LastIP, shortTime(s.LastUsedAt), shortTime(s.ExpiresAt), marker})
		}
		t.Render()
		return nil
	},
}

type authSessionsListResponse struct {
	Sessions []struct {
		ID          string `json:"id"`
		DeviceLabel string `json:"device_label,omitempty"`
		LastIP      string `json:"last_ip,omitempty"`
		CreatedAt   string `json:"created_at"`
		LastUsedAt  string `json:"last_used_at,omitempty"`
		ExpiresAt   string `json:"expires_at,omitempty"`
		Current     bool   `json:"current"`
	} `json:"sessions"`
}

var authSessionsRevokeCmd = &cobra.Command{
	Use:   "revoke <id>",
	Short: "Revoke a session by id (from `auth sessions list`)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := fetchAndDecode[struct {
			Status  string `json:"status"`
			Current bool   `json:"current"`
		}]("DELETE", "/v1/auth/sessions/"+args[0])
		if err != nil {
			return err
		}
		// Self-revoke: drop the on-disk token immediately so the next
		// CLI call doesn't 401 against a session we just killed.
		if resp.Current {
			if err := session.Clear(); err != nil {
				return fmt.Errorf("session revoked but local clear failed: %w", err)
			}
			fmt.Fprintln(os.Stderr, successText("✓")+" Session revoked. Run `agent-vault auth login` to log in again.")
			return nil
		}
		fmt.Fprintln(os.Stderr, successText("✓")+" Session revoked.")
		return nil
	},
}

// shortTime renders an RFC3339 timestamp as "2006-01-02 15:04" for table
// readability, matching cmd/user_invite.go and cmd/vaults.go. Falls back
// to the raw string if it doesn't parse.
func shortTime(rfc3339 string) string {
	if rfc3339 == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return rfc3339
	}
	return t.Local().Format("2006-01-02 15:04")
}

func init() {
	authSessionsCmd.AddCommand(authSessionsListCmd)
	authSessionsCmd.AddCommand(authSessionsRevokeCmd)
	authCmd.AddCommand(authSessionsCmd)
}
