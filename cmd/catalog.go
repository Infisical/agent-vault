package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

var catalogCmd = &cobra.Command{
	Use:   "catalog",
	Short: "Browse built-in service templates",
	Long:  `List the built-in service templates available for use in proposals. No authentication required.`,
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		addr := resolveAddress(cmd)
		jsonOut, _ := cmd.Flags().GetBool("json")

		url := fmt.Sprintf("%s/v1/service-catalog", addr)
		resp, err := http.Get(url)
		if err != nil {
			return fmt.Errorf("could not reach server at %s: %w", addr, err)
		}
		defer func() { _ = resp.Body.Close() }()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
		}

		if jsonOut {
			fmt.Fprintln(cmd.OutOrStdout(), string(respBody))
			return nil
		}

		var data struct {
			Services []struct {
				ID                     string `json:"id"`
				Name                   string `json:"name"`
				Host                   string `json:"host"`
				Description            string `json:"description"`
				AuthType               string `json:"auth_type"`
				SuggestedCredentialKey string `json:"suggested_credential_key"`
			} `json:"services"`
		}
		if err := json.Unmarshal(respBody, &data); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		w := cmd.OutOrStdout()
		if len(data.Services) == 0 {
			fmt.Fprintf(w, "%s\n", mutedText("No service templates available."))
			return nil
		}

		t := newTable(w)
		t.AppendHeader(table.Row{"ID", "NAME", "HOST", "AUTH TYPE", "SUGGESTED KEY"})
		for _, svc := range data.Services {
			t.AppendRow(table.Row{svc.ID, svc.Name, svc.Host, svc.AuthType, svc.SuggestedCredentialKey})
		}
		t.Render()
		return nil
	},
}

func init() {
	catalogCmd.Flags().Bool("json", false, "output response as JSON")
	catalogCmd.Flags().String("address", "", "server address (default: auto-detect)")
	rootCmd.AddCommand(catalogCmd)
}
