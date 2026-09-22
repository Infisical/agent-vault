package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

var wrapCmd = &cobra.Command{
	Use:   "wrap <command>",
	Short: "Create an automatic shim for a command",
	Long: `Creates an executable shim script inside the managed Agent Vault shims directory.
The shim transparently runs the command prefixed with 'agent-vault run --'.`,
	Args: cobra.ExactArgs(1),
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
		if err := os.MkdirAll(shimsDir, 0755); err != nil {
			return fmt.Errorf("failed to create shims directory: %w", err)
		}

		shimPath := filepath.Join(shimsDir, targetCmd)

		// Determine the binary/executable to use in the shim
		// Ideally we call the same agent-vault binary we're running now, or default to "agent-vault"
		selfPath, err := os.Executable()
		if err != nil {
			selfPath = "agent-vault"
		}

		var shimContent string
		if runtime.GOOS == "windows" {
			// Windows batch file shim if on Windows, but the prompt says script, let's support both or shell script.
			// Let's write a standard POSIX shell script, and if on Windows, we can write a .bat file as well or instead.
			// The requirements mention shell $PATH, so shell script is the primary focus.
			shimContent = fmt.Sprintf(`#!/usr/bin/env sh
exec "%s" run -- "%s" "$@"
`, selfPath, targetCmd)
		} else {
			shimContent = fmt.Sprintf(`#!/usr/bin/env sh
exec "%s" run -- "%s" "$@"
`, selfPath, targetCmd)
		}

		if err := os.WriteFile(shimPath, []byte(shimContent), 0755); err != nil {
			return fmt.Errorf("failed to write shim file: %w", err)
		}

		fmt.Fprintln(cmd.OutOrStdout(), fmt.Sprintf("%s Shim created successfully at: %s", successText("✔"), shimPath))
		fmt.Fprintln(cmd.OutOrStdout(), "\nTo use this shim automatically, make sure the shims directory is in your PATH.")
		fmt.Fprintln(cmd.OutOrStdout(), "You can add it by appending or prepending it in your shell profile (e.g., ~/.bashrc, ~/.zshrc):")
		fmt.Fprintln(cmd.OutOrStdout(), fmt.Sprintf("\n    %s\n", boldText(fmt.Sprintf(`export PATH="%s:$PATH"`, shimsDir))))

		return nil
	},
}

func init() {
	rootCmd.AddCommand(wrapCmd)
}
