package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/proposal"
	"github.com/spf13/cobra"
)

// proposalCreateRequest mirrors the server's request shape for POST /v1/proposals.
type proposalCreateRequest struct {
	Services    []proposal.Service        `json:"services,omitempty"`
	Credentials []proposal.CredentialSlot `json:"credentials,omitempty"`
	Message     string                    `json:"message,omitempty"`
	UserMessage string                    `json:"user_message,omitempty"`
}

var proposalCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a proposal to request services or credentials",
	Long: `Create a proposal to request services or credentials for a vault.

Flag-driven mode (common cases):

  # Service + credential
  agent-vault vault proposal create \
    --host api.stripe.com --auth-type bearer --token-key STRIPE_KEY \
    --credential STRIPE_KEY="Stripe API key" --message "Need Stripe access"

  # Credential only (no host/service)
  agent-vault vault proposal create \
    --credential DB_PASSWORD="Database password" --message "Need DB access"

JSON mode (complex/multi-service proposals):

  agent-vault vault proposal create -f proposal.json
  echo '{"services":[...],"credentials":[...]}' | agent-vault vault proposal create -f -`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		sess, err := resolveSession()
		if err != nil {
			return err
		}

		filePath, _ := cmd.Flags().GetString("file")
		host, _ := cmd.Flags().GetString("host")
		credentials, _ := cmd.Flags().GetStringArray("credential")
		jsonOut, _ := cmd.Flags().GetBool("json")

		// Validate mode: -f conflicts with flag-driven flags.
		if filePath != "" && (host != "" || len(credentials) > 0) {
			return fmt.Errorf("cannot mix -f/--file with --host or --credential flags")
		}

		var reqBody []byte

		if filePath != "" {
			// JSON mode.
			reqBody, err = buildFromJSON(cmd, filePath)
		} else if host != "" || len(credentials) > 0 {
			// Flag-driven mode.
			reqBody, err = buildFromFlags(cmd, host, credentials)
		} else {
			return fmt.Errorf("provide either --host/--credential flags or -f <file>\n\nExamples:\n  agent-vault vault proposal create --credential MY_KEY=\"description\" --message \"reason\"\n  agent-vault vault proposal create --host api.example.com --auth-type bearer --token-key MY_KEY --credential MY_KEY --message \"reason\"\n  agent-vault vault proposal create -f proposal.json")
		}
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/proposals", sess.Address)
		respBody, err := doAdminRequestWithBody("POST", url, sess.Token, reqBody)
		if err != nil {
			return err
		}

		if jsonOut {
			fmt.Fprintln(cmd.OutOrStdout(), string(respBody))
			return nil
		}

		var resp struct {
			ID          int    `json:"id"`
			Status      string `json:"status"`
			Vault       string `json:"vault"`
			ApprovalURL string `json:"approval_url"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "%s Proposal #%d created in vault %q.\n", successText("✓"), resp.ID, resp.Vault)
		if resp.ApprovalURL != "" {
			fmt.Fprintf(w, "Approve at: %s\n", resp.ApprovalURL)
		}
		return nil
	},
}

// buildFromJSON reads a JSON file or stdin and applies flag overrides for message/user_message.
func buildFromJSON(cmd *cobra.Command, filePath string) ([]byte, error) {
	var data []byte
	var err error
	if filePath == "-" {
		data, err = readStdin()
	} else {
		data, err = os.ReadFile(filePath)
	}
	if err != nil {
		return nil, fmt.Errorf("reading input: %w", err)
	}

	m, _ := cmd.Flags().GetString("message")
	um, _ := cmd.Flags().GetString("user-message")

	// Fast path: no overrides, send raw bytes directly (preserves unknown fields).
	if m == "" && um == "" {
		if !json.Valid(data) {
			return nil, fmt.Errorf("invalid JSON")
		}
		return data, nil
	}

	var req proposalCreateRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if m != "" {
		req.Message = m
	}
	if um != "" {
		req.UserMessage = um
	}

	return json.Marshal(req)
}

// buildFromFlags constructs a proposal request from CLI flags.
func buildFromFlags(cmd *cobra.Command, host string, credentialFlags []string) ([]byte, error) {
	req := proposalCreateRequest{}

	// Parse credential flags: "KEY" or "KEY=description".
	for _, c := range credentialFlags {
		slot := proposal.CredentialSlot{Action: proposal.ActionSet}
		if idx := strings.IndexByte(c, '='); idx >= 0 {
			slot.Key = c[:idx]
			slot.Description = c[idx+1:]
		} else {
			slot.Key = c
		}
		if slot.Key == "" {
			return nil, fmt.Errorf("invalid --credential value %q: key cannot be empty", c)
		}
		req.Credentials = append(req.Credentials, slot)
	}

	// Build service if --host is provided.
	if host != "" {
		authType, _ := cmd.Flags().GetString("auth-type")
		if authType == "" {
			return nil, fmt.Errorf("--auth-type is required when --host is specified (supported: %s)", strings.Join(broker.SupportedAuthTypes, ", "))
		}

		auth, err := buildAuthFromFlags(cmd, authType)
		if err != nil {
			return nil, err
		}

		svc := proposal.Service{
			Action: proposal.ActionSet,
			Host:   host,
			Auth:   auth,
		}
		if desc, _ := cmd.Flags().GetString("description"); desc != "" {
			svc.Description = desc
		}
		req.Services = append(req.Services, svc)
	} else {
		// No host — auth flags should not be present.
		authType, _ := cmd.Flags().GetString("auth-type")
		if authType != "" {
			return nil, fmt.Errorf("--auth-type requires --host to be specified")
		}
	}

	if m, _ := cmd.Flags().GetString("message"); m != "" {
		req.Message = m
	}
	if um, _ := cmd.Flags().GetString("user-message"); um != "" {
		req.UserMessage = um
	}

	return json.Marshal(req)
}

// buildAuthFromFlags constructs a broker.Auth from the auth-related flags.
func buildAuthFromFlags(cmd *cobra.Command, authType string) (*broker.Auth, error) {
	a := &broker.Auth{Type: authType}

	switch authType {
	case "bearer":
		tokenKey, _ := cmd.Flags().GetString("token-key")
		if tokenKey == "" {
			return nil, fmt.Errorf("--token-key is required for bearer auth")
		}
		a.Token = tokenKey

	case "basic":
		usernameKey, _ := cmd.Flags().GetString("username-key")
		if usernameKey == "" {
			return nil, fmt.Errorf("--username-key is required for basic auth")
		}
		a.Username = usernameKey
		a.Password, _ = cmd.Flags().GetString("password-key")

	case "api-key":
		apiKeyKey, _ := cmd.Flags().GetString("api-key-key")
		if apiKeyKey == "" {
			return nil, fmt.Errorf("--api-key-key is required for api-key auth")
		}
		a.Key = apiKeyKey
		a.Header, _ = cmd.Flags().GetString("api-key-header")
		a.Prefix, _ = cmd.Flags().GetString("api-key-prefix")

	case "custom":
		return nil, fmt.Errorf("custom auth type requires JSON mode (-f); use flags for bearer, basic, or api-key")

	case "passthrough":
		if err := rejectCredentialFlags(cmd, "passthrough"); err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unsupported auth type %q (supported: %s)", authType, strings.Join(broker.SupportedAuthTypes, ", "))
	}

	return a, nil
}

// rejectCredentialFlags returns an error if any credential-related flag was
// provided. Used by auth types like passthrough that accept no credentials.
func rejectCredentialFlags(cmd *cobra.Command, authType string) error {
	credFlags := []string{
		"token-key",
		"username-key",
		"password-key",
		"api-key-key",
		"api-key-header",
		"api-key-prefix",
	}
	for _, f := range credFlags {
		if v, _ := cmd.Flags().GetString(f); v != "" {
			return fmt.Errorf("--%s is not accepted for %s auth (no credential is injected)", f, authType)
		}
	}
	return nil
}

func init() {
	// JSON mode.
	proposalCreateCmd.Flags().StringP("file", "f", "", "path to JSON proposal file (use - for stdin)")

	// Flag-driven mode.
	proposalCreateCmd.Flags().String("host", "", "target service host (e.g. api.stripe.com)")
	proposalCreateCmd.Flags().String("description", "", "service description")
	proposalCreateCmd.Flags().String("auth-type", "", "auth type: bearer, basic, api-key, passthrough")
	proposalCreateCmd.Flags().String("token-key", "", "credential key for bearer auth")
	proposalCreateCmd.Flags().String("username-key", "", "credential key for basic auth username")
	proposalCreateCmd.Flags().String("password-key", "", "credential key for basic auth password")
	proposalCreateCmd.Flags().String("api-key-key", "", "credential key for api-key auth")
	proposalCreateCmd.Flags().String("api-key-header", "", "header name for api-key (default Authorization)")
	proposalCreateCmd.Flags().String("api-key-prefix", "", "prefix for api-key value")
	proposalCreateCmd.Flags().StringArray("credential", nil, "credential to request: KEY or KEY=description (repeatable)")

	// Shared flags.
	proposalCreateCmd.Flags().StringP("message", "m", "", "proposal message/reason")
	proposalCreateCmd.Flags().String("user-message", "", "human-facing explanation for approval page")
	proposalCreateCmd.Flags().Bool("json", false, "output response as JSON")

	proposalCmd.AddCommand(proposalCreateCmd)
}
