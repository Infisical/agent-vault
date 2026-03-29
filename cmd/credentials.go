package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

var credentialsCmd = &cobra.Command{
	Use:     "credentials",
	Aliases: []string{"creds"},
	Short:   "Manage credentials",
}

var credentialsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List credential keys in a vault",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, err := loadSession()
		if err != nil {
			return err
		}

		vault := resolveVault(cmd)

		url := sess.Address + "/v1/credentials?vault=" + vault
		respBody, err := doAdminRequestWithBody("GET", url, sess.Token, nil)
		if err != nil {
			return err
		}

		var result struct {
			Keys []string `json:"keys"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if len(result.Keys) == 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No credentials found in vault %q.\n", vault)
			return nil
		}

		t := newTable(cmd.OutOrStdout())
		t.AppendHeader(table.Row{"KEY"})
		for _, key := range result.Keys {
			t.AppendRow(table.Row{key})
		}
		t.Render()
		return nil
	},
}

var credentialsSetCmd = &cobra.Command{
	Use:   "set <key=value> [key2=value2 ...]",
	Short: "Set one or more credentials",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, err := loadSession()
		if err != nil {
			return err
		}

		vault := resolveVault(cmd)

		creds := make(map[string]string, len(args))
		for _, arg := range args {
			idx := strings.IndexByte(arg, '=')
			if idx < 1 {
				return fmt.Errorf("invalid format %q, expected KEY=VALUE", arg)
			}
			creds[arg[:idx]] = arg[idx+1:]
		}

		body, err := json.Marshal(map[string]interface{}{
			"vault":       vault,
			"credentials": creds,
		})
		if err != nil {
			return err
		}

		url := sess.Address + "/v1/credentials"
		respBody, err := doAdminRequestWithBody("POST", url, sess.Token, body)
		if err != nil {
			return err
		}

		var result struct {
			Set []string `json:"set"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		for _, key := range result.Set {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s Set credential %q in vault %q\n", successText("✓"), key, vault)
		}
		return nil
	},
}

var credentialsDeleteCmd = &cobra.Command{
	Use:   "delete <key> [key2 ...]",
	Short: "Delete one or more credentials",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, err := loadSession()
		if err != nil {
			return err
		}

		vault := resolveVault(cmd)

		body, err := json.Marshal(map[string]interface{}{
			"vault": vault,
			"keys":  args,
		})
		if err != nil {
			return err
		}

		url := sess.Address + "/v1/credentials"
		respBody, err := doAdminRequestWithBody("DELETE", url, sess.Token, body)
		if err != nil {
			return err
		}

		var result struct {
			Deleted []string `json:"deleted"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		for _, key := range result.Deleted {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s Deleted credential %q from vault %q\n", successText("✓"), key, vault)
		}
		return nil
	},
}

func init() {
	credentialsCmd.AddCommand(credentialsListCmd)
	credentialsCmd.AddCommand(credentialsSetCmd)
	credentialsCmd.AddCommand(credentialsDeleteCmd)
	vaultCmd.AddCommand(credentialsCmd)
}
