package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Infisical/agent-vault/internal/pidfile"
	"github.com/Infisical/agent-vault/internal/session"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/spf13/cobra"
)

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset the instance to a fresh state (owner only)",
	Long: `Permanently deletes all data — users, credentials, services, proposals, and
vaults — and returns the instance to a freshly-installed state.

Requires an active login session with owner role. If the server is running,
it will be stopped automatically before the reset.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		yes, _ := cmd.Flags().GetBool("yes")

		// 1. Load session
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		// 2. Verify owner role
		url := sess.Address + "/v1/admin/users/me"
		respBody, err := doAdminRequestWithBody("GET", url, sess.Token, nil)
		if err != nil {
			return err
		}

		var userInfo struct {
			Role string `json:"role"`
		}
		if err := json.Unmarshal(respBody, &userInfo); err != nil {
			return fmt.Errorf("parsing user info: %w", err)
		}
		if userInfo.Role != "owner" {
			return fmt.Errorf("reset requires owner role")
		}

		// 3. Confirm
		if !yes {
			fmt.Fprintln(cmd.OutOrStderr(), warningText("WARNING")+": This will permanently delete all data including users, credentials, services, proposals, and vaults.")
			fmt.Fprintf(cmd.OutOrStderr(), "Type %q to confirm: ", "reset")
			reader := bufio.NewReader(os.Stdin)
			answer, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("reading input: %w", err)
			}
			if strings.TrimSpace(answer) != "reset" {
				fmt.Fprintln(cmd.OutOrStdout(), mutedText("Aborted."))
				return nil
			}
		}

		// 4. Stop server if running
		if err := stopServer(); err != nil {
			return err
		}

		// 5. Delete database, WAL, SHM, and journal files
		dbPath, err := store.DefaultDBPath()
		if err != nil {
			return fmt.Errorf("resolving database path: %w", err)
		}
		paths := []string{dbPath, dbPath + "-wal", dbPath + "-shm", dbPath + "-journal"}

		// Overwrite before removing (best-effort secure wipe).
		for _, p := range paths {
			if f, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
				if info, err := f.Stat(); err == nil {
					zeros := make([]byte, 4096)
					remaining := info.Size()
					for remaining > 0 {
						n := int64(len(zeros))
						if n > remaining {
							n = remaining
						}
						_, _ = f.Write(zeros[:n])
						remaining -= n
					}
					_ = f.Sync()
				}
				_ = f.Close()
			}
		}

		for _, p := range paths {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("removing %s: %w", p, err)
			}
		}

		// 6. Clear session
		if err := session.Clear(); err != nil {
			return fmt.Errorf("clearing session: %w", err)
		}

		// 7. Remove PID file
		_ = pidfile.Remove()

		fmt.Fprintf(cmd.OutOrStdout(), "%s Instance reset. Run 'agent-vault server' to start fresh.\n", successText("✓"))
		return nil
	},
}

func init() {
	resetCmd.Flags().Bool("yes", false, "Skip confirmation prompt")
	ownerCmd.AddCommand(resetCmd)
}
