package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Create an account on a running server",
	Long:  "Self-signup for an Agent Vault account. The first user to register becomes the instance owner.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		address, _ := cmd.Flags().GetString("address")
		fromStdin, _ := cmd.Flags().GetBool("password-stdin")

		// Resolve email.
		email, _ := cmd.Flags().GetString("email")
		if email == "" {
			if fromStdin {
				return fmt.Errorf("--email is required when using --password-stdin")
			}
			_, _ = fmt.Fprint(cmd.ErrOrStderr(), "Email: ")
			reader := bufio.NewReader(os.Stdin)
			line, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("reading email: %w", err)
			}
			email = strings.TrimSpace(line)
		}
		if err := auth.ValidateEmail(email); err != nil {
			return err
		}

		// Resolve password.
		var password string
		if fromStdin {
			scanner := bufio.NewScanner(os.Stdin)
			if !scanner.Scan() {
				return fmt.Errorf("failed to read password from stdin")
			}
			password = strings.TrimRight(scanner.Text(), "\r\n")
		} else {
			fd := int(os.Stdin.Fd())
			if !term.IsTerminal(fd) {
				return fmt.Errorf("no TTY detected; use --password-stdin and --email for non-interactive input")
			}
			_, _ = fmt.Fprint(cmd.ErrOrStderr(), "Password: ")
			pw1, err := term.ReadPassword(fd)
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())
			if err != nil {
				return fmt.Errorf("reading password: %w", err)
			}
			_, _ = fmt.Fprint(cmd.ErrOrStderr(), "Confirm password: ")
			pw2, err := term.ReadPassword(fd)
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())
			if err != nil {
				return fmt.Errorf("reading password confirmation: %w", err)
			}
			if string(pw1) != string(pw2) {
				return fmt.Errorf("passwords do not match")
			}
			password = string(pw1)
		}

		if len(password) < 8 {
			return fmt.Errorf("password must be at least 8 characters")
		}

		// Send register request.
		body, err := json.Marshal(map[string]string{
			"email":    email,
			"password": password,
		})
		if err != nil {
			return err
		}

		resp, err := http.Post(address+"/v1/auth/register", "application/json", bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("could not reach server at %s: %w", address, err)
		}
		defer func() { _ = resp.Body.Close() }()

		var result struct {
			Email                string `json:"email"`
			Role                 string `json:"role"`
			RequiresVerification bool   `json:"requires_verification"`
			EmailSent            bool   `json:"email_sent"`
			Message              string `json:"message"`
			Error                string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&result)

		if resp.StatusCode >= 400 {
			if result.Error != "" {
				return fmt.Errorf("%s", result.Error)
			}
			return fmt.Errorf("registration failed with status %d", resp.StatusCode)
		}

		if !result.RequiresVerification {
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", successText("✓"), result.Message)
			return nil
		}

		if result.EmailSent {
			fmt.Fprintf(cmd.OutOrStdout(), "%s Account created. Check your email for a verification code.\n", successText("✓"))
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "%s Account created. Ask your Agent Vault instance owner for the verification code.\n", successText("✓"))
		}

		// Prompt for verification code.
		if fromStdin {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Use 'agent-vault verify' to complete verification.")
			return nil
		}

		_, _ = fmt.Fprint(cmd.ErrOrStderr(), "Verification code: ")
		reader := bufio.NewReader(os.Stdin)
		codeLine, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading verification code: %w", err)
		}
		code := strings.TrimSpace(codeLine)

		verifyBody, _ := json.Marshal(map[string]string{
			"email": email,
			"code":  code,
		})

		verifyResp, err := http.Post(address+"/v1/auth/verify", "application/json", bytes.NewReader(verifyBody))
		if err != nil {
			return fmt.Errorf("could not reach server: %w", err)
		}
		defer func() { _ = verifyResp.Body.Close() }()

		var verifyResult struct {
			Message string `json:"message"`
			Error   string `json:"error"`
		}
		_ = json.NewDecoder(verifyResp.Body).Decode(&verifyResult)

		if verifyResp.StatusCode >= 400 {
			if verifyResult.Error != "" {
				return fmt.Errorf("verification failed: %s", verifyResult.Error)
			}
			return fmt.Errorf("verification failed with status %d", verifyResp.StatusCode)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Account verified. You can now log in with 'agent-vault login'.\n", successText("✓"))
		return nil
	},
}

func init() {
	registerCmd.Flags().String("address", DefaultAddress, "address of the running Agent Vault server")
	registerCmd.Flags().String("email", "", "email address")
	registerCmd.Flags().Bool("password-stdin", false, "read password from stdin")
	rootCmd.AddCommand(registerCmd)
}
