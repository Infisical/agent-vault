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
	Short: "Bind the current directory to a vault (writes agent-vault.json)",
	Long:  "Writes an agent-vault.json file in the current directory so all team members automatically target the same vault. The file is meant to be committed to version control.",
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

		// Check for existing file and confirm overwrite.
		if data, err := os.ReadFile(ProjectConfigFile); err == nil {
			var existing struct {
				Vault string `json:"vault"`
			}
			if json.Unmarshal(data, &existing) == nil && existing.Vault != "" {
				fmt.Fprintf(os.Stderr, "Current binding: vault %q\n", existing.Vault)
				if existing.Vault == vaultName {
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

		cfg := map[string]string{"vault": vaultName}
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return err
		}
		data = append(data, '\n')

		if err := os.WriteFile(ProjectConfigFile, data, 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", ProjectConfigFile, err)
		}

		fmt.Fprintf(os.Stderr, "%s Wrote %s (vault: %s)\n", successText("✓"), ProjectConfigFile, vaultName)
		fmt.Fprintln(os.Stderr, "Commit this file so your team shares the vault binding.")
		return nil
	},
}

func init() {
	vaultCmd.AddCommand(vaultInitCmd)
}
