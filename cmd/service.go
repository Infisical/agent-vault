package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage services in a vault",
}

var serviceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List services in a vault",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/vaults/%s/services", sess.Address, vault)
		respBody, err := doAdminRequestWithBody("GET", url, sess.Token, nil)
		if err != nil {
			return err
		}

		var resp struct {
			Vault    string          `json:"vault"`
			Services json.RawMessage `json:"services"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		var services []broker.Service
		if err := json.Unmarshal(resp.Services, &services); err != nil {
			return fmt.Errorf("parsing services: %w", err)
		}

		cfg := broker.Config{
			Vault:    vault,
			Services: services,
		}

		out, err := yaml.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("marshalling yaml: %w", err)
		}

		_, _ = fmt.Fprint(cmd.OutOrStdout(), string(out))
		return nil
	},
}

var serviceSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set services (interactive or from YAML file)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)
		filePath, _ := cmd.Flags().GetString("file")
		if filePath == "" {
			return runInteractiveServiceSet(cmd)
		}

		services, err := loadServicesFromFile(filePath, vault)
		if err != nil {
			return err
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		servicesJSON, err := marshalServiceFileEntries(services)
		if err != nil {
			return fmt.Errorf("marshalling services: %w", err)
		}

		body, err := json.Marshal(map[string]json.RawMessage{"services": servicesJSON})
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/vaults/%s/services", sess.Address, vault)
		if err := doAdminRequest("PUT", url, sess.Token, body); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Services updated for vault %q\n", successText("✓"), vault)
		return nil
	},
}

var serviceClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Remove all services from the vault",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)
		yes, _ := cmd.Flags().GetBool("yes")

		if !yes {
			fmt.Fprintf(cmd.OutOrStderr(), "Clear services for vault %q? [y/N] ", vault)
			reader := bufio.NewReader(os.Stdin)
			answer, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("reading input: %w", err)
			}
			answer = strings.TrimSpace(strings.ToLower(answer))
			if answer != "y" && answer != "yes" {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), mutedText("Aborted."))
				return nil
			}
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/vaults/%s/services", sess.Address, vault)
		if err := doAdminRequest("DELETE", url, sess.Token, nil); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Services cleared for vault %q\n", successText("✓"), vault)
		return nil
	},
}

var serviceAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add or update services (upsert by name)",
	Long: `Add one or more services to the vault (upsert by name).
If a service with the same name already exists, it is replaced.

--host accepts a bare hostname (api.stripe.com), a one-level wildcard
(*.github.com), or an inline path-scoped form (slack.com/api/*) — the
broker splits the path off the host on ingest.

Flag-driven mode. --host is required; --name is required for new services
(the server adopts the existing name when --host uniquely matches an entry
already in the vault — same pattern as 'service remove' by host):
  agent-vault vault service add --name stripe --host api.stripe.com --auth-type bearer --token-key STRIPE_KEY
  agent-vault vault service add --name slack-bot --host 'slack.com/api/*' --auth-type bearer --token-key SLACK_BOT_TOKEN

File mode (upsert, not replace-all):
  agent-vault vault service add -f services.yaml`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)
		filePath, _ := cmd.Flags().GetString("file")

		var services []serviceFileEntry

		if filePath != "" {
			var err error
			services, err = loadServicesFromFile(filePath, vault)
			if err != nil {
				return err
			}
		} else {
			// Flag-driven mode: build a single service.
			host, _ := cmd.Flags().GetString("host")
			if host == "" {
				return fmt.Errorf("provide either --host flags or -f <file>")
			}

			authType, _ := cmd.Flags().GetString("auth-type")
			if authType == "" {
				return fmt.Errorf("--auth-type is required when --host is specified (supported: %s)", strings.Join(broker.SupportedAuthTypes, ", "))
			}

			auth, err := buildAuthFromFlags(cmd, authType)
			if err != nil {
				return err
			}

			name, _ := cmd.Flags().GetString("name")

			host, path, port := broker.SplitInlineHost(host, "")
			svc := broker.Service{Name: name, Host: host, Path: path, Port: port, Auth: *auth}
			if disabled, _ := cmd.Flags().GetBool("disabled"); disabled {
				f := false
				svc.Enabled = &f
			}

			services = []serviceFileEntry{{Service: svc}}
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		servicesJSON, err := marshalServiceFileEntries(services)
		if err != nil {
			return fmt.Errorf("marshalling services: %w", err)
		}

		body, err := json.Marshal(map[string]json.RawMessage{"services": servicesJSON})
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/vaults/%s/services", sess.Address, vault)
		respBody, err := doAdminRequestWithBody("POST", url, sess.Token, body)
		if err != nil {
			return err
		}

		var resp struct {
			ServicesCount int      `json:"services_count"`
			Upserted      []string `json:"upserted"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		for _, n := range resp.Upserted {
			fmt.Fprintf(cmd.OutOrStdout(), "%s Service added: %s (%d services total)\n", successText("✓"), n, resp.ServicesCount)
		}
		return nil
	},
}

var serviceRemoveCmd = &cobra.Command{
	Use:   "remove <name-or-host>",
	Short: "Remove a service by name (canonical) or host (when unique)",
	Long: `Remove a service. The argument is matched against service names first,
then host. If multiple services share the host, the server returns a
409 with the candidate names — retry with the specific name.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)
		ref := args[0]
		yes, _ := cmd.Flags().GetBool("yes")

		if !yes {
			fmt.Fprintf(cmd.OutOrStderr(), "Remove service %q from vault %q? [y/N] ", ref, vault)
			reader := bufio.NewReader(os.Stdin)
			answer, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("reading input: %w", err)
			}
			answer = strings.TrimSpace(strings.ToLower(answer))
			if answer != "y" && answer != "yes" {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), mutedText("Aborted."))
				return nil
			}
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/vaults/%s/services/%s", sess.Address, vault, url.PathEscape(ref))
		respBody, err := doAdminRequestWithBody("DELETE", url, sess.Token, nil)
		if err != nil {
			return err
		}

		var resp struct {
			ServicesCount int    `json:"services_count"`
			Removed       string `json:"removed"`
			RemovedHost   string `json:"removed_host"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		display := resp.Removed
		if resp.RemovedHost != "" && resp.RemovedHost != resp.Removed {
			display = fmt.Sprintf("%s (host=%s)", resp.Removed, resp.RemovedHost)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s Service removed: %s (%d services remaining)\n", successText("✓"), display, resp.ServicesCount)
		return nil
	},
}

var serviceEnableCmd = &cobra.Command{
	Use:   "enable <name-or-host>",
	Short: "Enable a service so proxy traffic resumes",
	Long: `Re-enable a previously disabled service. The argument is matched
against service names first, then host. Idempotent — no error if
already enabled.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return patchServiceEnabled(cmd, args[0], true)
	},
}

var serviceDisableCmd = &cobra.Command{
	Use:   "disable <name-or-host>",
	Short: "Disable a service so proxy requests return 403",
	Long: `Disable a service while preserving its configuration. Agents proxying
to it receive 403 with error code "service_disabled" until the service
is re-enabled. The argument is matched against service names first,
then host. Idempotent.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return patchServiceEnabled(cmd, args[0], false)
	},
}

func patchServiceEnabled(cmd *cobra.Command, ref string, enabled bool) error {
	vault := resolveVault(cmd)

	sess, err := ensureSession()
	if err != nil {
		return err
	}

	body, err := json.Marshal(map[string]bool{"enabled": enabled})
	if err != nil {
		return err
	}

	reqURL := fmt.Sprintf("%s/v1/vaults/%s/services/%s", sess.Address, vault, url.PathEscape(ref))
	respBody, err := doAdminRequestWithBody("PATCH", reqURL, sess.Token, body)
	if err != nil {
		return err
	}

	var resp struct {
		Name    string `json:"name"`
		Host    string `json:"host"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	verb := "disabled"
	if resp.Enabled {
		verb = "enabled"
	}
	display := resp.Name
	if resp.Host != "" && resp.Host != resp.Name {
		display = fmt.Sprintf("%s (host=%s)", resp.Name, resp.Host)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s Service %s: %s\n", successText("✓"), verb, display)
	return nil
}

// serviceFileEntry retains explicit route fields from YAML independently of
// broker.Service, whose omitempty fields cannot distinguish false/empty from
// omission.
type serviceFileEntry struct {
	Service     broker.Service
	RouteFields map[string]json.RawMessage
}

// marshalServiceFileEntries emits route fields exactly when the YAML supplied
// them, including explicit false and empty string values.
func marshalServiceFileEntries(entries []serviceFileEntry) ([]byte, error) {
	services := make([]json.RawMessage, 0, len(entries))
	for _, entry := range entries {
		base, err := json.Marshal(entry.Service)
		if err != nil {
			return nil, err
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(base, &fields); err != nil {
			return nil, err
		}
		for name, value := range entry.RouteFields {
			fields[name] = value
		}
		serviceJSON, err := json.Marshal(fields)
		if err != nil {
			return nil, err
		}
		services = append(services, serviceJSON)
	}
	return json.Marshal(services)
}

// loadServicesFromFile parses a services YAML file ("-" for stdin), applies
// the inline-host split, and preserves explicit egress route field presence.
// Validation runs server-side.
func loadServicesFromFile(filePath, vault string) ([]serviceFileEntry, error) {
	var data []byte
	var err error
	if filePath == "-" {
		data, err = readStdin()
	} else {
		data, err = os.ReadFile(filePath)
	}
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	var cfg struct {
		Services []yaml.Node `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing yaml: %w", err)
	}
	entries := make([]serviceFileEntry, len(cfg.Services))
	for i := range cfg.Services {
		var service broker.Service
		if err := cfg.Services[i].Decode(&service); err != nil {
			return nil, fmt.Errorf("parsing service %d: %w", i, err)
		}
		var routePresence struct {
			UpstreamProxy       yaml.Node `yaml:"upstream_proxy"`
			UseUpstreamProxy    yaml.Node `yaml:"use_upstream_proxy"`
			BypassUpstreamProxy yaml.Node `yaml:"bypass_upstream_proxy"`
		}
		if err := cfg.Services[i].Decode(&routePresence); err != nil {
			return nil, fmt.Errorf("parsing service %d route fields: %w", i, err)
		}
		// Decode the same mapping so aliases and YAML merges are resolved.
		// Use the already-typed service values for JSON: yaml.Node.Decode into
		// any would turn e.g. `yes` into a string, although the bool field
		// above correctly decoded it as true.
		var routeFields map[string]json.RawMessage
		for _, field := range []struct {
			name  string
			node  *yaml.Node
			value any
		}{
			{"upstream_proxy", &routePresence.UpstreamProxy, service.UpstreamProxy},
			{"use_upstream_proxy", &routePresence.UseUpstreamProxy, service.UseUpstreamProxy},
			{"bypass_upstream_proxy", &routePresence.BypassUpstreamProxy, service.BypassUpstreamProxy},
		} {
			if field.node.Kind == 0 {
				continue
			}
			if routeFields == nil {
				routeFields = make(map[string]json.RawMessage, 3)
			}
			encoded, err := serviceRouteFieldJSON(field.node, field.value)
			if err != nil {
				return nil, fmt.Errorf("service %d field %s: %w", i, field.name, err)
			}
			routeFields[field.name] = encoded
		}
		if err := broker.NormalizePort(&service); err != nil {
			return nil, fmt.Errorf("service %d: %w", i, err)
		}
		entries[i] = serviceFileEntry{Service: service, RouteFields: routeFields}
	}
	return entries, nil
}

// serviceRouteFieldJSON keeps an explicitly present YAML null distinct from
// omission. Other values use the type already validated by broker.Service.
func serviceRouteFieldJSON(node *yaml.Node, typedValue any) (json.RawMessage, error) {
	for node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	if node.ShortTag() == "!!null" {
		return json.RawMessage("null"), nil
	}
	return json.Marshal(typedValue)
}

func readStdin() ([]byte, error) {
	var buf []byte
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		buf = append(buf, scanner.Bytes()...)
		buf = append(buf, '\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return buf, nil
}

func init() {
	serviceSetCmd.Flags().StringP("file", "f", "", "Path to services YAML file")
	serviceClearCmd.Flags().Bool("yes", false, "Skip confirmation prompt")

	// service add flags
	serviceAddCmd.Flags().StringP("file", "f", "", "Path to services YAML file (upsert mode)")
	serviceAddCmd.Flags().String("name", "", "Service name (slug, 3–64 lowercase alphanumeric/hyphen chars). Required for new services; may be omitted when --host uniquely matches an existing service (the server adopts that name).")
	serviceAddCmd.Flags().String("host", "", "Target host with optional port and path glob (e.g. api.stripe.com, internal.corp.com:3000, slack.com/api/*)")
	serviceAddCmd.Flags().String("auth-type", "", "Auth type: bearer, basic, api-key, custom, passthrough")
	serviceAddCmd.Flags().String("token-key", "", "Credential key for bearer auth")
	serviceAddCmd.Flags().String("username-key", "", "Credential key for basic auth username")
	serviceAddCmd.Flags().String("password-key", "", "Credential key for basic auth password")
	serviceAddCmd.Flags().String("api-key-key", "", "Credential key for api-key auth")
	serviceAddCmd.Flags().String("api-key-header", "", "Header name for api-key (default Authorization)")
	serviceAddCmd.Flags().String("api-key-prefix", "", "Prefix for api-key value")
	serviceAddCmd.Flags().Bool("disabled", false, "Create the service in a disabled state (proxy traffic returns 403 until enabled)")

	// service remove flags
	serviceRemoveCmd.Flags().Bool("yes", false, "Skip confirmation prompt")

	serviceCmd.AddCommand(serviceListCmd)
	serviceCmd.AddCommand(serviceSetCmd)
	serviceCmd.AddCommand(serviceAddCmd)
	serviceCmd.AddCommand(serviceEnableCmd)
	serviceCmd.AddCommand(serviceDisableCmd)
	serviceCmd.AddCommand(serviceRemoveCmd)
	serviceCmd.AddCommand(serviceClearCmd)
	vaultCmd.AddCommand(serviceCmd)
}
