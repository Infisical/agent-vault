package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Mint a vault-scoped session token and print it to stdout",
	Long: `Create a temporary vault-scoped session token and print it to stdout.

This is useful when you need a scoped token without wrapping a child process
via "vault run". The token can be used with AGENT_VAULT_TOKEN and
AGENT_VAULT_ADDR environment variables. (AGENT_VAULT_SESSION_TOKEN is the
deprecated alias and still works.)

Example:
  export AGENT_VAULT_TOKEN=$(agent-vault vault token)
  export AGENT_VAULT_ADDR=http://localhost:14321
  export AGENT_VAULT_VAULT=default`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		addr, _ := cmd.Flags().GetString("address")
		if addr == "" {
			addr = sess.Address
		}

		ttl, _ := cmd.Flags().GetInt("ttl")
		_, token, err := mintScopedSession(cmd, sess, addr, ttl)
		if err != nil {
			return err
		}

		fmt.Fprint(cmd.OutOrStdout(), token)
		return nil
	},
}

func init() {
	tokenCmd.Flags().String("address", "", "Agent Vault server address (defaults to session address)")
	tokenCmd.Flags().Int("ttl", 0, "Session TTL in seconds (300–604800; default: server default 24h)")

	vaultCmd.AddCommand(tokenCmd)
}
