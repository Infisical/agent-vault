package cmd

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "Manage the transparent-proxy root CA certificate",
}

var caFetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch the root CA certificate (PEM)",
	Long: `Fetch the root CA certificate used by Agent Vault's transparent MITM
proxy. Install the returned PEM into your client trust store so HTTPS
traffic routed through the proxy validates cleanly.

The transparent proxy is enabled by default. The endpoint is public —
no authentication required. If the server was started with --mitm-port 0,
this command returns an error.

Examples:
  agent-vault ca fetch > ca.pem
  agent-vault ca fetch -o /etc/ssl/certs/agent-vault-ca.pem
  agent-vault ca fetch | sudo security add-trusted-cert -d -r trustRoot \
      -k /Library/Keychains/System.keychain /dev/stdin`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		addr := resolveAddress(cmd)
		output, _ := cmd.Flags().GetString("output")

		url := fmt.Sprintf("%s/v1/mitm/ca.pem", addr)
		resp, err := httpClient.Get(url)
		if err != nil {
			return fmt.Errorf("could not reach server at %s: %w", addr, err)
		}
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading response: %w", err)
		}

		if resp.StatusCode == http.StatusNotFound {
			return errors.New(strings.TrimSpace(string(body)))
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
		}

		if output != "" {
			if err := os.WriteFile(output, body, 0o600); err != nil {
				return fmt.Errorf("writing %s: %w", output, err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "%s Wrote CA cert to %s\n", successText("✓"), output)
			return nil
		}
		_, _ = cmd.OutOrStdout().Write(body)
		return nil
	},
}

func init() {
	caFetchCmd.Flags().StringP("output", "o", "", "write PEM to file instead of stdout")
	caFetchCmd.Flags().String("address", "", "server address (default: auto-detect)")
	caCmd.AddCommand(caFetchCmd)
	rootCmd.AddCommand(caCmd)
}
