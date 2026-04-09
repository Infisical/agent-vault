package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// readLoginEmail reads the email either from --email flag or by prompting interactively.
func readLoginEmail(cmd *cobra.Command) (string, error) {
	email, _ := cmd.Flags().GetString("email")
	if email != "" {
		return email, nil
	}

	fromStdin, _ := cmd.Flags().GetBool("password-stdin")
	if fromStdin {
		return "", fmt.Errorf("--email is required when using --password-stdin")
	}

	_, _ = fmt.Fprint(cmd.ErrOrStderr(), "Email: ")
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading email: %w", err)
	}
	return strings.TrimSpace(line), nil
}

// readPassword reads the password either from stdin (when
// --password-stdin is set) or by prompting interactively.
func readPassword(cmd *cobra.Command) (string, error) {
	fromStdin, _ := cmd.Flags().GetBool("password-stdin")
	if fromStdin {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			return "", fmt.Errorf("failed to read password from stdin")
		}
		return strings.TrimRight(scanner.Text(), "\r\n"), nil
	}

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("no TTY detected; use --password-stdin for non-interactive input")
	}

	_, _ = fmt.Fprint(cmd.ErrOrStderr(), "Password: ")
	pw, err := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(cmd.ErrOrStderr()) // newline after hidden input
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	return string(pw), nil
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with email and password",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		fromStdin, _ := cmd.Flags().GetBool("password-stdin")
		addressChanged := cmd.Flags().Changed("address")

		var address string
		if addressChanged {
			// Explicit --address flag: use it directly, skip interactive prompt.
			address, _ = cmd.Flags().GetString("address")
		} else if fromStdin {
			// Non-interactive mode: use the default address.
			address = DefaultAddress
		} else {
			// Interactive mode: show hosting selection.
			addr, err := selectAddress()
			if err != nil {
				return err
			}
			address = addr
		}

		email, err := readLoginEmail(cmd)
		if err != nil {
			return err
		}

		password, err := readPassword(cmd)
		if err != nil {
			return err
		}

		if _, err := doLogin(address, email, password); err != nil {
			return err
		}

		_, _ = fmt.Fprintln(cmd.OutOrStdout(), successText("✓")+" Login successful.")
		return nil
	},
}

func init() {
	loginCmd.Flags().String("address", DefaultAddress, "server address")
	loginCmd.Flags().String("email", "", "account email address")
	loginCmd.Flags().Bool("password-stdin", false, "read password from stdin (for non-interactive use)")
}
