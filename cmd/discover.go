package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Show available services and credentials for the current vault",
	Long: `Show the services and credentials available in the current vault.

Requires a vault-scoped session token or long-lived agent token (e.g. via
agent-vault vault run or AGENT_VAULT_TOKEN + AGENT_VAULT_ADDR environment
variables; AGENT_VAULT_SESSION_TOKEN is the deprecated alias and still works).
In agent mode (AGENT_VAULT_TOKEN set), AGENT_VAULT_VAULT (or --vault) is
required — there is no project-file or interactive-picker fallback.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		sess, tokenSource, err := resolveSession()
		if err != nil {
			return err
		}

		jsonOut, _ := cmd.Flags().GetBool("json")

		// Resolve the target vault. In agent mode we require an explicit
		// --vault or AGENT_VAULT_VAULT — falling through to "default"
		// would silently route the request at the wrong vault (or produce
		// a confusing 404 referencing a vault the user never named).
		// Mirrors the agent-mode contract `vault run` already enforces.
		vault, err := resolveVaultForCommand(cmd, tokenSource)
		if err != nil {
			return err
		}

		// Pass the resolved vault as X-Vault so instance-level agent tokens
		// (which carry no baked-in vault) can be used here too — the broker
		// rejects agent-token /discover calls without this header.
		url := fmt.Sprintf("%s/discover", sess.Address)
		respBody, err := doVaultScopedRequestWithBody("GET", url, sess.Token, vault, nil)
		if err != nil {
			return err
		}

		if jsonOut {
			fmt.Fprintln(cmd.OutOrStdout(), string(respBody))
			return nil
		}

		var resp struct {
			Vault    string `json:"vault"`
			Services []struct {
				Host        string `json:"host"`
				Description string `json:"description"`
			} `json:"services"`
			AvailableCredentials []string `json:"available_credentials"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "%s %s\n", fieldLabel("Vault:"), resp.Vault)

		if len(resp.Services) > 0 {
			fmt.Fprintln(w)
			fmt.Fprintf(w, "%s\n", boldText("Services"))
			t := newTable(w)
			t.AppendHeader(table.Row{"HOST", "DESCRIPTION"})
			for _, svc := range resp.Services {
				t.AppendRow(table.Row{svc.Host, svc.Description})
			}
			t.Render()
		} else {
			fmt.Fprintf(w, "\n%s\n", mutedText("No services configured."))
		}

		if len(resp.AvailableCredentials) > 0 {
			fmt.Fprintln(w)
			fmt.Fprintf(w, "%s\n", boldText("Available Credentials"))
			for _, key := range resp.AvailableCredentials {
				fmt.Fprintf(w, "  %s\n", key)
			}
		} else {
			fmt.Fprintf(w, "\n%s\n", mutedText("No credentials stored."))
		}

		return nil
	},
}

func init() {
	discoverCmd.Flags().Bool("json", false, "output response as JSON")
	vaultCmd.AddCommand(discoverCmd)
}
