package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage services for a vault",
}

var serviceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List services for the vault",
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

		var data []byte
		var err error
		if filePath == "-" {
			data, err = readStdin()
		} else {
			data, err = os.ReadFile(filePath)
		}
		if err != nil {
			return fmt.Errorf("reading file: %w", err)
		}

		var cfg broker.Config
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("parsing yaml: %w", err)
		}

		// Use the --vault flag to determine the target vault.
		cfg.Vault = vault

		if err := broker.Validate(&cfg); err != nil {
			return fmt.Errorf("invalid services: %w", err)
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		servicesJSON, err := json.Marshal(cfg.Services)
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

	serviceCmd.AddCommand(serviceListCmd)
	serviceCmd.AddCommand(serviceSetCmd)
	serviceCmd.AddCommand(serviceClearCmd)
	vaultCmd.AddCommand(serviceCmd)
}
