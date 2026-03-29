package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/Infisical/agent-vault/internal/session"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	hostingLocal       = "local"
	hostingSelfHosting = "self-hosting"
	defaultAddress     = DefaultAddress
)

// selectAddress prompts the user to pick a hosting option interactively.
// Returns the server address to use.
func selectAddress() (string, error) {
	var choice string
	err := huh.NewSelect[string]().
		Title("Select your hosting option:").
		Options(
			huh.NewOption(fmt.Sprintf("Agent Vault (%s:%d)", DefaultHost, DefaultPort), hostingLocal),
			huh.NewOption("Self-Hosting or Dedicated Instance", hostingSelfHosting),
		).
		Value(&choice).
		Run()
	if err != nil {
		return "", fmt.Errorf("hosting selection: %w", err)
	}

	if choice == hostingLocal {
		return defaultAddress, nil
	}

	var address string
	err = huh.NewInput().
		Title("Enter your server address:").
		Placeholder("https://my-agent-vault.example.com").
		Value(&address).
		Validate(func(s string) error {
			s = strings.TrimSpace(s)
			if s == "" {
				return fmt.Errorf("address cannot be empty")
			}
			if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
				return fmt.Errorf("address must start with http:// or https://")
			}
			return nil
		}).
		Run()
	if err != nil {
		return "", fmt.Errorf("address input: %w", err)
	}

	return strings.TrimRight(strings.TrimSpace(address), "/"), nil
}

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
			address = defaultAddress
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

		body, err := json.Marshal(map[string]string{"email": email, "password": password})
		if err != nil {
			return err
		}

		resp, err := http.Post(address+"/v1/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("could not reach server at %s: %w", address, err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("invalid email or password")
		}

		if resp.StatusCode != http.StatusOK {
			var errResp struct {
				Error string `json:"error"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&errResp)
			if errResp.Error != "" {
				return fmt.Errorf("login failed: %s", errResp.Error)
			}
			return fmt.Errorf("login failed with status %d", resp.StatusCode)
		}

		var result struct {
			Token     string `json:"token"`
			ExpiresAt string `json:"expires_at"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if err := session.Save(&session.ClientSession{
			Token:   result.Token,
			Address: address,
		}); err != nil {
			return fmt.Errorf("saving session: %w", err)
		}

		_, _ = fmt.Fprintln(cmd.OutOrStdout(), successText("✓")+" Login successful.")
		return nil
	},
}

func init() {
	loginCmd.Flags().String("address", DefaultAddress, "server address")
	loginCmd.Flags().String("email", "", "account email address")
	loginCmd.Flags().Bool("password-stdin", false, "read password from stdin (for non-interactive use)")
	rootCmd.AddCommand(loginCmd)
}
