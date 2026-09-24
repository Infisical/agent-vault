package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Infisical/agent-vault/internal/session"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

type handlerRecord struct {
	ID               string   `json:"id"`
	Kind             string   `json:"kind"`
	ExecutablePath   string   `json:"executable_path"`
	SHA256           string   `json:"sha256"`
	SigningIdentity  string   `json:"signing_identity,omitempty"`
	AllowedKeys      []string `json:"allowed_keys"`
	AllowedVaults    []string `json:"allowed_vaults"`
	AllowedProfiles  []string `json:"allowed_profiles"`
	TimeoutSeconds   int      `json:"timeout_seconds"`
	OutputLimitBytes int      `json:"output_limit_bytes"`
	Enabled          bool     `json:"enabled"`
	CreatedAt        string   `json:"created_at"`
	UpdatedAt        string   `json:"updated_at"`
}

var handlerCmd = &cobra.Command{
	Use:   "handler",
	Short: "Manage credential-acquisition handlers (owner only)",
}

var handlerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered handlers",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		body, err := handlerAPIRequest(cmd, http.MethodGet, "/v1/admin/handlers", nil)
		if err != nil {
			return err
		}
		var result struct {
			Handlers []handlerRecord `json:"handlers"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}
		if len(result.Handlers) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No credential-acquisition handlers registered.")
			return nil
		}
		t := newTable(cmd.OutOrStdout())
		t.AppendHeader(table.Row{"ID", "KIND", "ENABLED", "PROFILES", "EXECUTABLE"})
		for _, handler := range result.Handlers {
			t.AppendRow(table.Row{handler.ID, handler.Kind, handler.Enabled, strings.Join(handler.AllowedProfiles, ","), handler.ExecutablePath})
		}
		t.Render()
		return nil
	},
}

var handlerShowCmd = &cobra.Command{
	Use:   "show ID",
	Short: "Show a registered handler",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		body, err := handlerAPIRequest(cmd, http.MethodGet, "/v1/admin/handlers/"+url.PathEscape(args[0]), nil)
		if err != nil {
			return err
		}
		var handler handlerRecord
		if err := json.Unmarshal(body, &handler); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}
		writeHandler(cmd, handler)
		return nil
	},
}

var handlerRegisterCmd = &cobra.Command{
	Use:   "register ID",
	Short: "Register a handler in the disabled state",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		kind, _ := cmd.Flags().GetString("kind")
		executablePath, _ := cmd.Flags().GetString("executable")
		digest, _ := cmd.Flags().GetString("sha256")
		signingIdentity, _ := cmd.Flags().GetString("signing-identity")
		allowedKeys, _ := cmd.Flags().GetStringSlice("allow-key")
		allowedVaults, _ := cmd.Flags().GetStringSlice("allow-vault")
		profiles, _ := cmd.Flags().GetStringSlice("profile")
		timeoutSeconds, _ := cmd.Flags().GetInt("timeout")
		outputLimit, _ := cmd.Flags().GetInt("output-limit")
		request := handlerRecord{
			ID:               args[0],
			Kind:             kind,
			ExecutablePath:   executablePath,
			SHA256:           digest,
			SigningIdentity:  signingIdentity,
			AllowedKeys:      allowedKeys,
			AllowedVaults:    allowedVaults,
			AllowedProfiles:  profiles,
			TimeoutSeconds:   timeoutSeconds,
			OutputLimitBytes: outputLimit,
		}
		body, err := json.Marshal(struct {
			ID               string   `json:"id"`
			Kind             string   `json:"kind"`
			ExecutablePath   string   `json:"executable_path"`
			SHA256           string   `json:"sha256"`
			SigningIdentity  string   `json:"signing_identity,omitempty"`
			AllowedKeys      []string `json:"allowed_keys"`
			AllowedVaults    []string `json:"allowed_vaults"`
			AllowedProfiles  []string `json:"allowed_profiles"`
			TimeoutSeconds   int      `json:"timeout_seconds"`
			OutputLimitBytes int      `json:"output_limit_bytes"`
		}{
			ID: request.ID, Kind: request.Kind, ExecutablePath: request.ExecutablePath,
			SHA256: request.SHA256, SigningIdentity: request.SigningIdentity,
			AllowedKeys: request.AllowedKeys, AllowedVaults: request.AllowedVaults,
			AllowedProfiles: request.AllowedProfiles, TimeoutSeconds: request.TimeoutSeconds,
			OutputLimitBytes: request.OutputLimitBytes,
		})
		if err != nil {
			return err
		}
		response, err := handlerAPIRequest(cmd, http.MethodPost, "/v1/admin/handlers", body)
		if err != nil {
			return err
		}
		var created handlerRecord
		if err := json.Unmarshal(response, &created); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s Handler %q registered disabled; run `agent-vault handler verify %s` to enable it.\n", successText("✓"), created.ID, created.ID)
		return nil
	},
}

func handlerStateCommand(use, short, suffix, success string) *cobra.Command {
	return &cobra.Command{
		Use:   use + " ID",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := []byte(`{}`)
			method := http.MethodPost
			if use == "delete" {
				method = http.MethodDelete
				body = nil
			}
			_, err := handlerAPIRequest(cmd, method, "/v1/admin/handlers/"+url.PathEscape(args[0])+suffix, body)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s Handler %q %s.\n", successText("✓"), args[0], success)
			return nil
		},
	}
}

var (
	handlerVerifyCmd  = handlerStateCommand("verify", "Verify and enable a registered handler", "/verify", "verified and enabled")
	handlerDisableCmd = handlerStateCommand("disable", "Disable a registered handler", "/disable", "disabled")
	handlerDeleteCmd  = handlerStateCommand("delete", "Delete a registered handler", "", "deleted")
)

func handlerAPIRequest(cmd *cobra.Command, method, path string, body []byte) ([]byte, error) {
	sess, err := ensureSession()
	if err != nil {
		return nil, err
	}
	address := sess.Address
	if override, _ := cmd.Flags().GetString("address"); override != "" {
		address = strings.TrimRight(override, "/")
	}
	var response []byte
	err = withReauthRetry(sess, address, func(current *session.ClientSession) error {
		var requestErr error
		response, requestErr = doAdminRequestWithBody(method, address+path, current.Token, body)
		return requestErr
	})
	return response, err
}

func writeHandler(cmd *cobra.Command, handler handlerRecord) {
	w := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(w, "%s\n", boldText("Handler: "+handler.ID))
	_, _ = fmt.Fprintf(w, "%s %s\n", fieldLabel("Kind:"), handler.Kind)
	_, _ = fmt.Fprintf(w, "%s %t\n", fieldLabel("Enabled:"), handler.Enabled)
	_, _ = fmt.Fprintf(w, "%s %s\n", fieldLabel("Executable:"), handler.ExecutablePath)
	_, _ = fmt.Fprintf(w, "%s %s\n", fieldLabel("SHA-256:"), handler.SHA256)
	if handler.SigningIdentity != "" {
		_, _ = fmt.Fprintf(w, "%s %s\n", fieldLabel("Signing identity:"), handler.SigningIdentity)
	}
	_, _ = fmt.Fprintf(w, "%s %s\n", fieldLabel("Keys:"), strings.Join(handler.AllowedKeys, ", "))
	_, _ = fmt.Fprintf(w, "%s %s\n", fieldLabel("Vaults:"), strings.Join(handler.AllowedVaults, ", "))
	_, _ = fmt.Fprintf(w, "%s %s\n", fieldLabel("Profiles:"), strings.Join(handler.AllowedProfiles, ", "))
	_, _ = fmt.Fprintf(w, "%s %ds\n", fieldLabel("Timeout:"), handler.TimeoutSeconds)
	_, _ = fmt.Fprintf(w, "%s %d bytes\n", fieldLabel("Output limit:"), handler.OutputLimitBytes)
}

func init() {
	handlerCmd.PersistentFlags().String("address", "", "server address override")
	handlerRegisterCmd.Flags().String("kind", "executable", "handler kind: executable or browser_dom")
	handlerRegisterCmd.Flags().String("executable", "", "absolute provider executable path")
	handlerRegisterCmd.Flags().String("sha256", "", "expected lowercase SHA-256 digest")
	handlerRegisterCmd.Flags().String("signing-identity", "", "optional exact macOS code-signing identity")
	handlerRegisterCmd.Flags().StringSlice("allow-key", nil, "allowed credential key (repeatable)")
	handlerRegisterCmd.Flags().StringSlice("allow-vault", nil, "allowed vault ID (repeatable)")
	handlerRegisterCmd.Flags().StringSlice("profile", nil, "allowed provider profile (repeatable)")
	handlerRegisterCmd.Flags().Int("timeout", 10, "provider timeout in seconds")
	handlerRegisterCmd.Flags().Int("output-limit", 65536, "maximum provider response bytes")
	_ = handlerRegisterCmd.MarkFlagRequired("executable")
	_ = handlerRegisterCmd.MarkFlagRequired("sha256")
	_ = handlerRegisterCmd.MarkFlagRequired("allow-key")
	_ = handlerRegisterCmd.MarkFlagRequired("allow-vault")
	_ = handlerRegisterCmd.MarkFlagRequired("profile")
	handlerCmd.AddCommand(handlerListCmd, handlerShowCmd, handlerRegisterCmd, handlerVerifyCmd, handlerDisableCmd, handlerDeleteCmd)
	rootCmd.AddCommand(handlerCmd)
}
