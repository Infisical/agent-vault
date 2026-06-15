package cmd

import (
	"net/http"

	"github.com/Infisical/agent-vault/internal/telemetry"
	"github.com/spf13/cobra"
)

var tel *telemetry.Telemetry

func init() {
	rootCmd.PersistentFlags().Bool("telemetry", true, "enable anonymous usage telemetry (also respects AGENT_VAULT_TELEMETRY env var)")
	cobra.OnInitialize(initTelemetry)
}

func initTelemetry() {
	if telemetry.IsDisabled() {
		return
	}
	if ok, _ := rootCmd.PersistentFlags().GetBool("telemetry"); !ok {
		return
	}
	tel = telemetry.New(posthogAPIKey, version)
}

// clientHeaderTransport wraps an http.RoundTripper and injects the
// X-AV-Client header on every outbound request so the server can
// attribute actions to CLI vs. web vs. direct API callers.
type clientHeaderTransport struct {
	base http.RoundTripper
}

func (t *clientHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("X-AV-Client", "cli/"+version)
	return t.base.RoundTrip(req)
}
