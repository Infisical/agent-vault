package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var unwrapCmd = &cobra.Command{
	Use:   "unwrap <command>",
	Short: "Remove the automatic shim for a command",
	Long:  `Deletes the executable shim for the specified command from the managed shims folder.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetCmd := args[0]
		if strings.ContainsAny(targetCmd, `/\:`) {
			return fmt.Errorf("command name cannot contain path separators or colons")
		}

		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get user home directory: %w", err)
		}

		shimsDir := filepath.Join(homeDir, ".agent-vault", "shims")
		shimPath := filepath.Join(shimsDir, targetCmd)

		if _, err := os.Stat(shimPath); os.IsNotExist(err) {
			return fmt.Errorf("no shim found for command '%s' at: %s", targetCmd, shimPath)
		}

		if err := os.Remove(shimPath); err != nil {
			return fmt.Errorf("failed to remove shim: %w", err)
		}

		fmt.Fprintln(cmd.OutOrStdout(), fmt.Sprintf("%s Shim removed successfully for command: %s", successText("✔"), targetCmd))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(unwrapCmd)
}
