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

		servicesJSON, err := json.Marshal(services)
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
	Short: "Add or update services (upsert by host)",
	Long: `Add one or more services to the vault (upsert by host).
If a service with the same host already exists, it is replaced.

Flag-driven mode:
  agent-vault vault service add --host api.stripe.com --auth-type bearer --token-key STRIPE_KEY

File mode (upsert, not replace-all):
  agent-vault vault service add -f services.yaml`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)
		filePath, _ := cmd.Flags().GetString("file")

		var services []broker.Service

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

			svc := broker.Service{Host: host, Auth: *auth}
			if desc, _ := cmd.Flags().GetString("description"); desc != "" {
				svc.Description = &desc
			}
			services = []broker.Service{svc}
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		servicesJSON, err := json.Marshal(services)
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

		for _, h := range resp.Upserted {
			fmt.Fprintf(cmd.OutOrStdout(), "%s Service added: %s (%d services total)\n", successText("✓"), h, resp.ServicesCount)
		}
		return nil
	},
}

var serviceRemoveCmd = &cobra.Command{
	Use:   "remove <host>",
	Short: "Remove a service by host",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)
		host := args[0]
		yes, _ := cmd.Flags().GetBool("yes")

		if !yes {
			fmt.Fprintf(cmd.OutOrStderr(), "Remove service %q from vault %q? [y/N] ", host, vault)
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

		url := fmt.Sprintf("%s/v1/vaults/%s/services/%s", sess.Address, vault, url.PathEscape(host))
		respBody, err := doAdminRequestWithBody("DELETE", url, sess.Token, nil)
		if err != nil {
			return err
		}

		var resp struct {
			ServicesCount int    `json:"services_count"`
			Removed       string `json:"removed"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Service removed: %s (%d services remaining)\n", successText("✓"), resp.Removed, resp.ServicesCount)
		return nil
	},
}

// loadServicesFromFile reads and validates a broker config from a YAML file path ("-" for stdin).
func loadServicesFromFile(filePath, vault string) ([]broker.Service, error) {
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
	var cfg broker.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing yaml: %w", err)
	}
	cfg.Vault = vault
	if err := broker.Validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid services: %w", err)
	}
	return cfg.Services, nil
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
	serviceAddCmd.Flags().String("host", "", "Target service host (e.g. api.stripe.com)")
	serviceAddCmd.Flags().String("description", "", "Service description")
	serviceAddCmd.Flags().String("auth-type", "", "Auth type: bearer, basic, api-key, custom, passthrough")
	serviceAddCmd.Flags().String("token-key", "", "Credential key for bearer auth")
	serviceAddCmd.Flags().String("username-key", "", "Credential key for basic auth username")
	serviceAddCmd.Flags().String("password-key", "", "Credential key for basic auth password")
	serviceAddCmd.Flags().String("api-key-key", "", "Credential key for api-key auth")
	serviceAddCmd.Flags().String("api-key-header", "", "Header name for api-key (default Authorization)")
	serviceAddCmd.Flags().String("api-key-prefix", "", "Prefix for api-key value")

	// service remove flags
	serviceRemoveCmd.Flags().Bool("yes", false, "Skip confirmation prompt")

	serviceCmd.AddCommand(serviceListCmd)
	serviceCmd.AddCommand(serviceSetCmd)
	serviceCmd.AddCommand(serviceAddCmd)
	serviceCmd.AddCommand(serviceRemoveCmd)
	serviceCmd.AddCommand(serviceClearCmd)
	vaultCmd.AddCommand(serviceCmd)
}
