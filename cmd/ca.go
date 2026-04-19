package cmd

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// fetchMITMCA requests the transparent-proxy root CA from the local server.
// Returns (pem, port, true, tlsEnabled, nil) on 200 where port is the MITM
// listener port advertised by the server (0 if the server omitted the header,
// e.g. an older build — callers should fall back to DefaultMITMPort in that
// case) and tlsEnabled indicates whether the proxy listener is TLS-wrapped
// (X-MITM-TLS: 1). Returns (nil, 0, false, false, nil) on 404 (MITM
// disabled), or an error for any other failure. Body is always drained
// before returning so the underlying connection can be pooled.
func fetchMITMCA(addr string) (pem []byte, port int, enabled bool, tlsEnabled bool, err error) {
	resp, err := httpClient.Get(addr + "/v1/mitm/ca.pem")
	if err != nil {
		return nil, 0, false, false, fmt.Errorf("could not reach server at %s: %w", addr, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, false, false, fmt.Errorf("reading response: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		port := 0
		if raw := resp.Header.Get("X-MITM-Port"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 && n < 65536 {
				port = n
			}
		}
		hasTLS := resp.Header.Get("X-MITM-TLS") == "1"
		return body, port, true, hasTLS, nil
	case http.StatusNotFound:
		return nil, 0, false, false, nil
	default:
		return nil, 0, false, false, fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
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

		pem, _, enabled, _, err := fetchMITMCA(addr)
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
