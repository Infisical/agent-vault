package cmd

import "github.com/spf13/cobra"

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authentication commands",
}

func init() {
	authCmd.AddCommand(loginCmd)
	authCmd.AddCommand(registerCmd)
	rootCmd.AddCommand(authCmd)
}
