package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Infisical/agent-vault/internal/session"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var changePasswordCmd = &cobra.Command{
	Use:   "change-password",
	Short: "Change your account password",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		fromStdin, _ := cmd.Flags().GetBool("password-stdin")

		var currentPw, newPw string

		if fromStdin {
			scanner := bufio.NewScanner(os.Stdin)
			if !scanner.Scan() {
				return fmt.Errorf("failed to read current password from stdin")
			}
			currentPw = strings.TrimRight(scanner.Text(), "\r\n")
			if !scanner.Scan() {
				return fmt.Errorf("failed to read new password from stdin")
			}
			newPw = strings.TrimRight(scanner.Text(), "\r\n")
		} else {
			fd := int(os.Stdin.Fd())
			if !term.IsTerminal(fd) {
				return fmt.Errorf("no TTY detected; use --password-stdin for non-interactive input")
			}

			_, _ = fmt.Fprint(cmd.ErrOrStderr(), "Current password: ")
			pw, err := term.ReadPassword(fd)
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())
			if err != nil {
				return fmt.Errorf("reading current password: %w", err)
			}
			currentPw = string(pw)

			_, _ = fmt.Fprint(cmd.ErrOrStderr(), "New password: ")
			pw, err = term.ReadPassword(fd)
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())
			if err != nil {
				return fmt.Errorf("reading new password: %w", err)
			}
			newPw = string(pw)

			_, _ = fmt.Fprint(cmd.ErrOrStderr(), "Confirm new password: ")
			pw2, err := term.ReadPassword(fd)
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())
			if err != nil {
				return fmt.Errorf("reading password confirmation: %w", err)
			}
			if string(pw) != string(pw2) {
				return fmt.Errorf("passwords do not match")
			}
		}

		if len(newPw) < 8 {
			return fmt.Errorf("new password must be at least 8 characters")
		}

		body, err := json.Marshal(map[string]string{
			"current_password": currentPw,
			"new_password":     newPw,
		})
		if err != nil {
			return err
		}

		respBody, err := doAdminRequestWithBody("POST", sess.Address+"/v1/auth/change-password", sess.Token, body)
		if err != nil {
			return fmt.Errorf("password change failed: %w", err)
		}

		// Update the saved session with the new token.
		var result struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(respBody, &result); err == nil && result.Token != "" {
			sess.Token = result.Token
			if err := session.Save(sess); err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Warning: password changed but failed to save new session: %v\n", err)
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "You may need to run 'agent-vault auth login' again.\n")
				return nil
			}
		}

		_, _ = fmt.Fprintln(cmd.OutOrStdout(), successText("✓")+" Password changed successfully.")
		return nil
	},
}

func init() {
	changePasswordCmd.Flags().Bool("password-stdin", false, "read current and new passwords from stdin (two lines)")
}
