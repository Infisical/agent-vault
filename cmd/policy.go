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

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage the policy for a vault",
}

var policyGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Print the policy for the vault",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)

		sess, err := loadSession()
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/vaults/%s/policy", sess.Address, vault)
		respBody, err := doAdminRequestWithBody("GET", url, sess.Token, nil)
		if err != nil {
			return err
		}

		var resp struct {
			Vault string          `json:"vault"`
			Rules     json.RawMessage `json:"rules"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		var rules []broker.Rule
		if err := json.Unmarshal(resp.Rules, &rules); err != nil {
			return fmt.Errorf("parsing rules: %w", err)
		}

		cfg := broker.Config{
			Vault: vault,
			Rules:     rules,
		}

		out, err := yaml.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("marshalling yaml: %w", err)
		}

		_, _ = fmt.Fprint(cmd.OutOrStdout(), string(out))
		return nil
	},
}

var policySetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set the policy (interactive or from YAML file)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)
		filePath, _ := cmd.Flags().GetString("file")
		if filePath == "" {
			return runInteractivePolicySet(cmd)
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
			return fmt.Errorf("invalid policy: %w", err)
		}

		sess, err := loadSession()
		if err != nil {
			return err
		}

		rulesJSON, err := json.Marshal(cfg.Rules)
		if err != nil {
			return fmt.Errorf("marshalling rules: %w", err)
		}

		body, err := json.Marshal(map[string]json.RawMessage{"rules": rulesJSON})
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/vaults/%s/policy", sess.Address, vault)
		if err := doAdminRequest("PUT", url, sess.Token, body); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Policy updated for vault %q\n", successText("✓"), vault)
		return nil
	},
}

var policyClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Remove the policy from the vault",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)
		yes, _ := cmd.Flags().GetBool("yes")

		if !yes {
			fmt.Fprintf(cmd.OutOrStderr(), "Clear policy for vault %q? [y/N] ", vault)
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

		sess, err := loadSession()
		if err != nil {
			return err
		}

		url := fmt.Sprintf("%s/v1/vaults/%s/policy", sess.Address, vault)
		if err := doAdminRequest("DELETE", url, sess.Token, nil); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Policy cleared for vault %q\n", successText("✓"), vault)
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
	policySetCmd.Flags().StringP("file", "f", "", "Path to policy YAML file")
	policyClearCmd.Flags().Bool("yes", false, "Skip confirmation prompt")

	policyCmd.AddCommand(policyGetCmd)
	policyCmd.AddCommand(policySetCmd)
	policyCmd.AddCommand(policyClearCmd)
	vaultCmd.AddCommand(policyCmd)
}
