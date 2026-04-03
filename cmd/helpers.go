package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/pidfile"
	"github.com/Infisical/agent-vault/internal/session"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	hostingLocal       = "local"
	hostingSelfHosting = "self-hosting"
)

// httpClient is used for setup-flow HTTP calls with a reasonable timeout.
var httpClient = &http.Client{Timeout: 10 * time.Second}

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
		return DefaultAddress, nil
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

// isInteractive returns true if stdin is a terminal.
func isInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// serverStatus holds the parsed /v1/status response.
type serverStatus struct {
	Initialized    bool `json:"initialized"`
	NeedsFirstUser bool `json:"needs_first_user"`
}

// checkServerStatus queries the server's public status endpoint.
func checkServerStatus(address string) (*serverStatus, error) {
	resp, err := httpClient.Get(address + "/v1/status")
	if err != nil {
		return nil, fmt.Errorf("could not reach server at %s: %w", address, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server at %s returned status %d", address, resp.StatusCode)
	}

	var status serverStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("parsing server status: %w", err)
	}
	return &status, nil
}

// registerResult holds the parsed register API response.
type registerResult struct {
	Email                string `json:"email"`
	Role                 string `json:"role"`
	RequiresVerification bool   `json:"requires_verification"`
	EmailSent            bool   `json:"email_sent"`
	Message              string `json:"message"`
}

// doRegister posts credentials to /v1/auth/register and returns the result.
func doRegister(address, email, password string) (*registerResult, error) {
	body, err := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(address+"/v1/auth/register", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("could not reach server at %s: %w", address, err)
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		registerResult
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)

	if resp.StatusCode >= 400 {
		if result.Error != "" {
			return nil, fmt.Errorf("%s", result.Error)
		}
		return nil, fmt.Errorf("registration failed with status %d", resp.StatusCode)
	}

	return &result.registerResult, nil
}

// doLogin posts credentials to /v1/auth/login, saves the session on success, and returns it.
func doLogin(address, email, password string) (*session.ClientSession, error) {
	body, err := json.Marshal(map[string]string{"email": email, "password": password})
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(address+"/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("could not reach server at %s: %w", address, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("invalid email or password")
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error != "" {
			return nil, fmt.Errorf("login failed: %s", errResp.Error)
		}
		return nil, fmt.Errorf("login failed with status %d", resp.StatusCode)
	}

	var result struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	sess := &session.ClientSession{
		Token:   result.Token,
		Address: address,
	}
	if err := session.Save(sess); err != nil {
		return nil, fmt.Errorf("saving session: %w", err)
	}
	return sess, nil
}

// interactiveReadEmail prompts for an email address on stderr and reads from stdin.
func interactiveReadEmail() (string, error) {
	return auth.PromptEmail("Email: ")
}

// interactiveReadPassword prompts for a password using hidden input.
func interactiveReadPassword() (string, error) {
	pw, err := auth.PromptPassword("Password: ")
	if err != nil {
		return "", err
	}
	return string(pw), nil
}

// interactiveReadPasswordWithConfirm prompts for a password with confirmation and enforces minimum length.
func interactiveReadPasswordWithConfirm() (string, error) {
	pw, err := auth.PromptNewPassword("Password: ", "Confirm password: ")
	if err != nil {
		return "", err
	}
	if len(pw) < 8 {
		return "", fmt.Errorf("password must be at least 8 characters")
	}
	return string(pw), nil
}

// ensureSession loads the client session, or interactively guides the user through setup if no session exists and a TTY is available.
func ensureSession() (*session.ClientSession, error) {
	sess, err := session.Load()
	if err != nil {
		return nil, fmt.Errorf("loading session: %w", err)
	}
	if sess != nil {
		return sess, nil
	}

	if !isInteractive() {
		return nil, fmt.Errorf("not logged in, run 'agent-vault login' first")
	}

	fmt.Fprintln(os.Stderr, "\nNo active session. Let's get you connected.")

	address, err := selectAddress()
	if err != nil {
		return nil, err
	}

	status, err := checkServerStatus(address)
	if err != nil {
		return nil, err
	}

	if status.NeedsFirstUser {
		fmt.Fprintln(os.Stderr, "\nThis server needs its first user (owner account).")

		email, err := interactiveReadEmail()
		if err != nil {
			return nil, err
		}
		password, err := interactiveReadPasswordWithConfirm()
		if err != nil {
			return nil, err
		}

		if _, err := doRegister(address, email, password); err != nil {
			return nil, fmt.Errorf("registration failed: %w", err)
		}
		fmt.Fprintln(os.Stderr, successText("✓")+" Owner account created. Logging in...")

		sess, err := doLogin(address, email, password)
		if err != nil {
			return nil, fmt.Errorf("auto-login failed: %w", err)
		}
		fmt.Fprintln(os.Stderr, successText("✓")+" Login successful.\n")
		return sess, nil
	}

	// Server has existing users — prompt to log in or register.
	const choiceLogin = "login"
	const choiceRegister = "register"
	var choice string
	err = huh.NewSelect[string]().
		Title("This server already has users. What would you like to do?").
		Options(
			huh.NewOption("Log in to existing account", choiceLogin),
			huh.NewOption("Create a new account", choiceRegister),
		).
		Value(&choice).
		Run()
	if err != nil {
		return nil, fmt.Errorf("action selection: %w", err)
	}

	if choice == choiceRegister {
		email, err := interactiveReadEmail()
		if err != nil {
			return nil, err
		}
		password, err := interactiveReadPasswordWithConfirm()
		if err != nil {
			return nil, err
		}

		result, err := doRegister(address, email, password)
		if err != nil {
			return nil, fmt.Errorf("registration failed: %w", err)
		}

		if result.RequiresVerification {
			if result.EmailSent {
				fmt.Fprintln(os.Stderr, successText("✓")+" Account created. Check your email for a verification code.")
			} else {
				fmt.Fprintln(os.Stderr, successText("✓")+" Account created. Ask your instance owner for the verification code.")
			}
			return nil, fmt.Errorf("account requires verification before login; verify your account then re-run this command")
		}

		fmt.Fprintln(os.Stderr, successText("✓")+" "+result.Message)
		sess, err := doLogin(address, email, password)
		if err != nil {
			return nil, fmt.Errorf("auto-login failed: %w", err)
		}
		fmt.Fprintln(os.Stderr, successText("✓")+" Login successful.\n")
		return sess, nil
	}

	// Login flow.
	email, err := interactiveReadEmail()
	if err != nil {
		return nil, err
	}
	password, err := interactiveReadPassword()
	if err != nil {
		return nil, err
	}

	sess, err = doLogin(address, email, password)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, successText("✓")+" Login successful.\n")
	return sess, nil
}

// resolveVault returns the target vault using: --vault flag > context file > "default".
func resolveVault(cmd *cobra.Command) string {
	if name, _ := cmd.Flags().GetString("vault"); name != "" {
		return name
	}
	if ctx := session.LoadVaultContext(); ctx != "" {
		return ctx
	}
	return store.DefaultVault
}

// doAdminRequestWithBody makes an authenticated HTTP request to the server and returns the response body.
func doAdminRequestWithBody(method, url, token string, body []byte) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody, &errResp)
		if errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	return respBody, nil
}

// doAdminRequest makes an authenticated HTTP request to the server and checks for errors.
func doAdminRequest(method, url, token string, body []byte) error {
	_, err := doAdminRequestWithBody(method, url, token, body)
	return err
}

// stopServer sends SIGTERM to a running server process and waits for it to exit.
// Returns nil if no server is running.
func stopServer() error {
	pid, err := pidfile.Read()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading PID file: %w", err)
	}

	if !pidfile.IsRunning(pid) {
		_ = pidfile.Remove()
		return nil
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("finding server process %d: %w", pid, err)
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("sending SIGTERM to server process %d: %w", pid, err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !pidfile.IsRunning(pid) {
			_ = pidfile.Remove()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}

	return fmt.Errorf("server process %d did not exit within 10 seconds; you may need to kill it manually", pid)
}
