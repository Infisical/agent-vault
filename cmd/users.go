package cmd

import (
	"fmt"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

var usersCmd = &cobra.Command{
	Use:   "users",
	Short: "List all users in the instance",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		type usersListResult struct {
			Users []struct {
				Email     string   `json:"email"`
				Role      string   `json:"role"`
				Vaults    []string `json:"vaults"`
				CreatedAt string   `json:"created_at"`
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
				ns := strings.Join(u.Vaults, ", ")
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

func init() {
	rootCmd.AddCommand(usersCmd)
}
