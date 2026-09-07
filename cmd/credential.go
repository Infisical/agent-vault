package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

var credentialCmd = &cobra.Command{
	Use:     "credential",
	Aliases: []string{"creds"},
	Short:   "Manage credentials in a vault",
}

// credTypeLabel renders the credential type column; an empty type means a
// plain static credential.
func credTypeLabel(t string) string {
	if t == "" {
		return "static"
	}
	return t
}

var credentialListCmd = &cobra.Command{
	Use:   "list",
	Short: "List credential keys in a vault",
	Long: `List credential keys in a vault.

In agent mode (AGENT_VAULT_TOKEN set), AGENT_VAULT_VAULT (or --vault) is
required — there is no project-file or interactive-picker fallback.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, tokenSource, err := resolveSession()
		if err != nil {
			return err
		}

		vault, err := resolveVaultForCommand(cmd, tokenSource)
		if err != nil {
			return err
		}
		reveal, _ := cmd.Flags().GetBool("reveal")

		reqURL := sess.Address + "/v1/credentials?vault=" + url.QueryEscape(vault)
		if reveal {
			reqURL += "&reveal=true"
		}
		respBody, err := doAdminRequestWithBody("GET", reqURL, sess.Token, nil)
		if err != nil {
			return err
		}

		var result struct {
			Keys        []string `json:"keys"`
			Credentials []struct {
				Key         string `json:"key"`
				Type        string `json:"type"`
				Value       string `json:"value"`
				Unavailable bool   `json:"unavailable"`
			} `json:"credentials"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if len(result.Keys) == 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No credentials found in vault %q.\n", vault)
			return nil
		}

		t := newTable(cmd.OutOrStdout())
		// Type (static/oauth/dynamic) is only present with the credentials list,
		// which the server returns to members+; key-only listings omit it.
		switch {
		case len(result.Credentials) == 0:
			t.AppendHeader(table.Row{"KEY"})
			for _, key := range result.Keys {
				t.AppendRow(table.Row{key})
			}
		case reveal:
			t.AppendHeader(table.Row{"KEY", "TYPE", "VALUE"})
			for _, cred := range result.Credentials {
				val := cred.Value
				if cred.Unavailable {
					val = "(unavailable: check lease permissions)"
				}
				t.AppendRow(table.Row{cred.Key, credTypeLabel(cred.Type), val})
			}
		default:
			t.AppendHeader(table.Row{"KEY", "TYPE"})
			for _, cred := range result.Credentials {
				t.AppendRow(table.Row{cred.Key, credTypeLabel(cred.Type)})
			}
		}
		t.Render()
		return nil
	},
}

var credentialGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get the decrypted value of a credential",
	Long: `Get the decrypted value of a credential.

In agent mode (AGENT_VAULT_TOKEN set), AGENT_VAULT_VAULT (or --vault) is
required — there is no project-file or interactive-picker fallback.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, tokenSource, err := resolveSession()
		if err != nil {
			return err
		}

		vault, err := resolveVaultForCommand(cmd, tokenSource)
		if err != nil {
			return err
		}
		key := args[0]

		reqURL := sess.Address + "/v1/credentials?vault=" + url.QueryEscape(vault) + "&reveal=true&key=" + url.QueryEscape(key)
		respBody, err := doAdminRequestWithBody("GET", reqURL, sess.Token, nil)
		if err != nil {
			return err
		}

		var result struct {
			Credentials []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"credentials"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if len(result.Credentials) == 0 {
			return fmt.Errorf("credential %q not found in vault %q", key, vault)
		}

		// Print raw value (pipe-friendly).
		fmt.Fprint(cmd.OutOrStdout(), result.Credentials[0].Value)
		return nil
	},
}

var credentialSetCmd = &cobra.Command{
	Use:   "set <key=value> [key2=value2 ...]",
	Short: "Set one or more credentials",
	Long: `Set one or more credentials in a vault.

In agent mode (AGENT_VAULT_TOKEN set), AGENT_VAULT_VAULT (or --vault) is
required — there is no project-file or interactive-picker fallback.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, tokenSource, err := resolveSession()
		if err != nil {
			return err
		}

		vault, err := resolveVaultForCommand(cmd, tokenSource)
		if err != nil {
			return err
		}

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

var credentialDeleteCmd = &cobra.Command{
	Use:   "delete <key> [key2 ...]",
	Short: "Delete one or more credentials",
	Long: `Delete one or more credentials from a vault.

In agent mode (AGENT_VAULT_TOKEN set), AGENT_VAULT_VAULT (or --vault) is
required — there is no project-file or interactive-picker fallback.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, tokenSource, err := resolveSession()
		if err != nil {
			return err
		}

		vault, err := resolveVaultForCommand(cmd, tokenSource)
		if err != nil {
			return err
		}

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

var credentialHistoryCmd = &cobra.Command{
	Use:   "history <key>",
	Short: "List archived versions of a credential",
	Long: `List past values a credential held before being overwritten, most recent
first, with the timestamp and actor (user/agent) responsible for each
overwrite. Requires member+ role — the same rule as "credential get"/--reveal.

Values are not shown unless --reveal is also passed. Roll one back with
"agent-vault vault credential rollback <key> --version N".

In agent mode (AGENT_VAULT_TOKEN set), AGENT_VAULT_VAULT (or --vault) is
required — there is no project-file or interactive-picker fallback.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, tokenSource, err := resolveSession()
		if err != nil {
			return err
		}

		vault, err := resolveVaultForCommand(cmd, tokenSource)
		if err != nil {
			return err
		}
		key := args[0]
		reveal, _ := cmd.Flags().GetBool("reveal")

		reqURL := sess.Address + "/v1/credentials/history?vault=" + url.QueryEscape(vault) + "&key=" + url.QueryEscape(key)
		if reveal {
			reqURL += "&reveal=true"
		}
		respBody, err := doAdminRequestWithBody("GET", reqURL, sess.Token, nil)
		if err != nil {
			return err
		}

		var result struct {
			Versions []struct {
				Version   int    `json:"version"`
				ActorType string `json:"actor_type"`
				ActorID   string `json:"actor_id"`
				CreatedAt string `json:"created_at"`
				Value     string `json:"value"`
			} `json:"versions"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if len(result.Versions) == 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No archived versions for credential %q in vault %q.\n", key, vault)
			return nil
		}

		t := newTable(cmd.OutOrStdout())
		header := table.Row{"VERSION", "REPLACED AT", "ACTOR"}
		if reveal {
			header = append(header, "VALUE")
		}
		t.AppendHeader(header)
		for _, v := range result.Versions {
			actor := "unknown"
			if v.ActorType != "" || v.ActorID != "" {
				actor = fmt.Sprintf("%s:%s", v.ActorType, v.ActorID)
			}
			row := table.Row{v.Version, v.CreatedAt, actor}
			if reveal {
				row = append(row, v.Value)
			}
			t.AppendRow(row)
		}
		t.Render()
		return nil
	},
}

var credentialRollbackCmd = &cobra.Command{
	Use:   "rollback <key>",
	Short: "Restore an archived version of a credential as its current value",
	Long: `Restore a prior version of a credential (see "credential history") as its
current value. The value being replaced is itself archived as a new version
first, so a rollback is never destructive — you can always roll back a
rollback. Requires member+ role, same as "credential set".

In agent mode (AGENT_VAULT_TOKEN set), AGENT_VAULT_VAULT (or --vault) is
required — there is no project-file or interactive-picker fallback.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, tokenSource, err := resolveSession()
		if err != nil {
			return err
		}

		vault, err := resolveVaultForCommand(cmd, tokenSource)
		if err != nil {
			return err
		}
		key := args[0]

		version, err := cmd.Flags().GetInt("version")
		if err != nil || version <= 0 {
			return fmt.Errorf("--version is required and must be a positive integer (see \"credential history %s\")", key)
		}

		body, err := json.Marshal(map[string]interface{}{
			"vault":   vault,
			"key":     key,
			"version": version,
		})
		if err != nil {
			return err
		}

		reqURL := sess.Address + "/v1/credentials/rollback"
		if _, err := doAdminRequestWithBody("POST", reqURL, sess.Token, body); err != nil {
			return err
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s Rolled back credential %q in vault %q to version %d\n", successText("✓"), key, vault, version)
		return nil
	},
}

func init() {
	credentialListCmd.Flags().Bool("reveal", false, "Show decrypted credential values (requires member+ role)")
	credentialHistoryCmd.Flags().Bool("reveal", false, "Show decrypted values for each version (requires member+ role)")
	credentialRollbackCmd.Flags().Int("version", 0, "Version number to restore (see \"credential history\")")
	credentialCmd.AddCommand(credentialListCmd)
	credentialCmd.AddCommand(credentialGetCmd)
	credentialCmd.AddCommand(credentialSetCmd)
	credentialCmd.AddCommand(credentialDeleteCmd)
	credentialCmd.AddCommand(credentialHistoryCmd)
	credentialCmd.AddCommand(credentialRollbackCmd)
	vaultCmd.AddCommand(credentialCmd)
}
