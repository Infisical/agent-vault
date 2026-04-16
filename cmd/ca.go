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

// fetchMITMCA requests the transparent-proxy root CA from the local server.
// Returns (pem, true, nil) on 200, (nil, false, nil) on 404 (MITM disabled),
// or an error for any other failure. Body is always drained before returning
// so the underlying connection can be pooled.
func fetchMITMCA(addr string) ([]byte, bool, error) {
	resp, err := httpClient.Get(addr + "/v1/mitm/ca.pem")
	if err != nil {
		return nil, false, fmt.Errorf("could not reach server at %s: %w", addr, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("reading response: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return body, true, nil
	case http.StatusNotFound:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
}

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

		pem, enabled, err := fetchMITMCA(addr)
		if err != nil {
			return err
		}
		if !enabled {
			return errors.New("MITM proxy is not enabled on this server")
		}

		if output != "" {
			if err := os.WriteFile(output, pem, 0o600); err != nil {
				return fmt.Errorf("writing %s: %w", output, err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "%s Wrote CA cert to %s\n", successText("✓"), output)
			return nil
		}
		_, _ = cmd.OutOrStdout().Write(pem)
		return nil
	},
}

func init() {
	caFetchCmd.Flags().StringP("output", "o", "", "write PEM to file instead of stdout")
	caFetchCmd.Flags().String("address", "", "server address (default: auto-detect)")
	caCmd.AddCommand(caFetchCmd)
	rootCmd.AddCommand(caCmd)
}
