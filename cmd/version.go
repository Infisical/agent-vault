package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Set via ldflags at build time.
var (
	version        = "dev"
	commit         = "unknown"
	date           = "unknown"
	posthogAPIKey  = ""
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version and build information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("agent-vault %s\n", version)
			fmt.Printf("  commit:  %s\n", commit)
			fmt.Printf("  built:   %s\n", date)
			fmt.Printf("  go:      %s\n", runtime.Version())
			fmt.Printf("  os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		},
	})

	rootCmd.Version = version
}
