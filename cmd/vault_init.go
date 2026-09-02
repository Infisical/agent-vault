package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
)

var vaultInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Bind the current project to a vault (writes agent-vault.json)",
	Long:  "Writes an agent-vault.json file in the current project so all team members automatically target the same vault. If a config is already discoverable from the current directory, it is updated in place. The file is meant to be committed to version control.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := ensureSession()
		if err != nil {
			return err
		}

		// If --vault flag is provided, use it directly; otherwise interactive pick.
		vaultName, _ := cmd.Flags().GetString("vault")
		if vaultName == "" {
			vaultName, err = selectVault(client)
			if err != nil {
				return err
			}
		}

		// Check for existing file and confirm changing the legacy binding.
		// Preserve versioned profile configuration when adding or updating the
		// top-level vault field.
		configPath := ProjectConfigFile
		if path, found, err := findProjectConfig(); err != nil {
			return err
		} else if found {
			configPath = path
		}

		cfg := projectConfig{}
		if data, err := os.ReadFile(configPath); err == nil {
			if err := json.Unmarshal(data, &cfg); err != nil {
				return fmt.Errorf("parsing existing %s: %w", configPath, err)
			}
			if err := validateProjectConfig(&cfg); err != nil {
				return fmt.Errorf("validating existing %s: %w", configPath, err)
			}
			if cfg.Vault != "" {
				fmt.Fprintf(os.Stderr, "Current binding: vault %q\n", cfg.Vault)
				if cfg.Vault == vaultName {
					fmt.Fprintln(os.Stderr, "Already bound to this vault, nothing to do.")
					return nil
				}
				var ok bool
				if err := huh.NewConfirm().
					Title(fmt.Sprintf("Overwrite with vault %q?", vaultName)).
					Affirmative("Yes").
					Negative("No").
					Value(&ok).
					Run(); err != nil {
					return err
				}
				if !ok {
					return nil
				}
			}
		}

		cfg.Vault = vaultName
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return err
		}
		data = append(data, '\n')

		if err := os.WriteFile(configPath, data, 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", configPath, err)
		}

		fmt.Fprintf(os.Stderr, "%s Wrote %s (vault: %s)\n", successText("✓"), configPath, vaultName)
		fmt.Fprintln(os.Stderr, "Commit this file so your team shares the vault binding.")
		return nil
	},
}

func init() {
	vaultCmd.AddCommand(vaultInitCmd)
}
