package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "agent-vault",
	Short: "Agent Vault, a local-first credential brokerage layer for AI agents",
	Long: `Agent Vault sits between a development agent and target services,
proxying requests and attaching credentials on behalf of the agent.

Agents never see the underlying credentials, they make requests to Agent Vault,
and Agent Vault uses the appropriate credentials when performing outbound HTTP calls.`,
	CompletionOptions: cobra.CompletionOptions{HiddenDefaultCmd: true},
}

var ownerCmd = &cobra.Command{
	Use:   "owner",
	Short: "Instance owner commands",
}

func init() {
	rootCmd.AddCommand(ownerCmd)
}

func Execute() {
	err := rootCmd.Execute()
	if err == nil {
		return
	}
	// An ExitCodeError carries the wrapped subprocess's exit status —
	// propagate it verbatim. The subprocess already wrote to stderr;
	// we stay quiet and exit with its code.
	var ece *ExitCodeError
	if errors.As(err, &ece) {
		os.Exit(ece.Code)
	}
	fmt.Fprintln(os.Stderr, errorText(err.Error()))
	os.Exit(1)
}
