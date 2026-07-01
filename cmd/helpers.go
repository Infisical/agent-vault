package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/pidfile"
	"github.com/Infisical/agent-vault/internal/session"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/telemetry"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// errSessionExpired marks an error as recoverable by re-authenticating.
// It is returned by HTTP helpers whenever the server replies with 401 to
// an admin-token-bearing request; withReauthRetry uses errors.Is to detect
// it. Match on status (not the error string) so all three 401 messages
// the server emits — "Session expired", "Invalid or expired session",
// "Authorization required" — are handled the same way.
var errSessionExpired = &sessionExpiredError{msg: "session expired"}

// sessionExpiredError carries a server- or caller-supplied message while
// still matching errSessionExpired via errors.Is. Wrapping the sentinel
// through fmt.Errorf("%s: %w", body, errSessionExpired) would stutter
// ("Session expired: session expired"); this type renders only `msg`.
type sessionExpiredError struct{ msg string }

func (e *sessionExpiredError) Error() string { return e.msg }
func (e *sessionExpiredError) Is(target error) bool {
	_, ok := target.(*sessionExpiredError)
	return ok
}

// isInteractiveFn and reauthFn are indirections so tests can stub the TTY
// check and the interactive re-auth without wiring a real terminal.
var (
	isInteractiveFn = isInteractive
	reauthFn        = reauthInteractive
)

const (
	hostingLocal       = "local"
	hostingSelfHosting = "self-hosting"
)

// httpClient is used for control-plane HTTP calls (discover, proposals,
// sessions) with a reasonable timeout. The custom proxy function skips
// the proxy for calls to AGENT_VAULT_ADDR (the broker's own server) so
// control-plane traffic goes direct even when the child process inherits
// MITM proxy env vars. All other destinations fall through to the
// system proxy, so corporate proxies still work for direct CLI usage.
var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &clientHeaderTransport{
		base: &http.Transport{
			Proxy: func(r *http.Request) (*url.URL, error) {
				if avAddr := os.Getenv("AGENT_VAULT_ADDR"); avAddr != "" {
					if u, err := url.Parse(avAddr); err == nil && r.URL.Host == u.Host {
						return nil, nil
					}
				}
				return http.ProxyFromEnvironment(r)
			},
		},
	},
}

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

// registerResult holds the parsed register API response. Token and
// ExpiresAt are populated only when the server auto-logs the caller in
// (currently: the first-user register path). Other paths return them as
// "" and the caller is expected to drive the verification flow.
type registerResult struct {
	Email                string `json:"email"`
	Role                 string `json:"role"`
	RequiresVerification bool   `json:"requires_verification"`
	EmailSent            bool   `json:"email_sent"`
	Message              string `json:"message"`
	Token                string `json:"token,omitempty"`
	ExpiresAt            string `json:"expires_at,omitempty"`
}

// doRegister posts credentials to /v1/auth/register. When the response
// includes a token (first-user auto-login), the session is also saved
// to disk and returned so the caller can use it directly without a
// follow-up /v1/auth/login. Returns (result, sess, err); sess is nil
// when verification is required.
func doRegister(address, email, password, deviceLabel string) (*registerResult, *session.ClientSession, error) {
	body, err := json.Marshal(map[string]string{
		"email":        email,
		"password":     password,
		"device_label": deviceLabel,
	})
	if err != nil {
		return nil, nil, err
	}

	resp, err := httpClient.Post(address+"/v1/auth/register", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("could not reach server at %s: %w", address, err)
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		registerResult
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)

	if resp.StatusCode >= 400 {
		if result.Error != "" {
			return nil, nil, fmt.Errorf("%s", result.Error)
		}
		return nil, nil, fmt.Errorf("registration failed with status %d", resp.StatusCode)
	}

	if result.Token == "" {
		return &result.registerResult, nil, nil
	}

	sess := &session.ClientSession{
		Token:       result.Token,
		Address:     address,
		Email:       email,
		DeviceLabel: deviceLabel,
	}
	if err := session.Save(sess); err != nil {
		return nil, nil, fmt.Errorf("saving session: %w", err)
	}
	tel.Identify(email, map[string]string{"email": email})
	tel.Alias(email, telemetry.MachineID())
	return &result.registerResult, sess, nil
}

// doLogin posts credentials to /v1/auth/login, saves the session on
// success, and returns it. deviceLabel is sent as `device_label` so the
// server records this login in the user's active-sessions list. Callers
// resolve the label themselves (the cobra command honors --device-label;
// internal callers default to defaultDeviceLabel()).
func doLogin(address, email, password, deviceLabel string) (*session.ClientSession, error) {
	body, err := json.Marshal(map[string]string{
		"email":        email,
		"password":     password,
		"device_label": deviceLabel,
	})
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Post(address+"/v1/auth/login", "application/json", bytes.NewReader(body))
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
		Token:       result.Token,
		Address:     address,
		Email:       email,
		DeviceLabel: deviceLabel,
	}
	if err := session.Save(sess); err != nil {
		return nil, fmt.Errorf("saving session: %w", err)
	}
	tel.Identify(email, map[string]string{"email": email})
	tel.Alias(email, telemetry.MachineID())
	return sess, nil
}

// reauthInteractive prompts the user to log in again on the same address as
// sess and returns the freshly-saved session. Skips the email prompt when
// sess.Email is already known (i.e. session was minted by a doLogin call
// after the Email field was added).
func reauthInteractive(sess *session.ClientSession) (*session.ClientSession, error) {
	fmt.Fprintln(os.Stderr, "\nYour session has expired. Please log in again.")

	email := sess.Email
	if email == "" {
		got, err := interactiveReadEmail()
		if err != nil {
			return nil, err
		}
		email = got
	} else {
		fmt.Fprintf(os.Stderr, "Re-authenticating as %s\n", email)
	}

	password, err := interactiveReadPassword()
	if err != nil {
		return nil, err
	}

	// Preserve the operator's original --device-label choice across
	// silent re-auth; fall back to hostname only when the saved session
	// pre-dates the DeviceLabel field.
	label := sess.DeviceLabel
	if label == "" {
		label = defaultDeviceLabel()
	}
	newSess, err := doLogin(sess.Address, email, password, label)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, successText("✓")+" Login successful.")
	return newSess, nil
}

// withReauthRetry runs op once. If op fails with errSessionExpired and
// stdin is a TTY, prompts the user to re-authenticate, updates *sess in
// place so callers holding the pointer pick up the new token, and runs op
// exactly once more. Non-interactive callers see the original error
// untouched so CI/scripts can detect and handle it themselves.
//
// addr is the server the failing request was sent to; reauth is skipped
// when it differs from sess.Address, because the saved login is tied to
// sess.Address and a fresh token for that server would still be useless
// against a different one (e.g. `--address=B` with a session for A).
func withReauthRetry(sess *session.ClientSession, addr string, op func(*session.ClientSession) error) error {
	err := op(sess)
	if err == nil || !errors.Is(err, errSessionExpired) {
		return err
	}
	if !isInteractiveFn() || addr != sess.Address {
		return err
	}
	newSess, rerr := reauthFn(sess)
	if rerr != nil {
		return fmt.Errorf("re-authentication failed: %w", rerr)
	}
	*sess = *newSess
	return op(sess)
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
		return nil, fmt.Errorf("not logged in, run 'agent-vault auth login' first")
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

		_, sess, err := doRegister(address, email, password, defaultDeviceLabel())
		if err != nil {
			return nil, fmt.Errorf("registration failed: %w", err)
		}
		if sess == nil {
			return nil, fmt.Errorf("auto-login after register failed: server did not return a session")
		}
		fmt.Fprintln(os.Stderr, successText("✓")+" Owner account created. Login successful.\n")
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

		result, _, err := doRegister(address, email, password, defaultDeviceLabel())
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
		sess, err := doLogin(address, email, password, defaultDeviceLabel())
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

	sess, err = doLogin(address, email, password, defaultDeviceLabel())
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, successText("✓")+" Login successful.\n")
	return sess, nil
}

// ProjectConfigFile is the name of the project-level vault binding file.
const ProjectConfigFile = "agent-vault.json"

// loadProjectVault reads agent-vault.json from the working directory.
// Returns the vault name or "" if the file doesn't exist or is invalid.
func loadProjectVault() string {
	data, err := os.ReadFile(ProjectConfigFile)
	if err != nil {
		return ""
	}
	var cfg struct {
		Vault string `json:"vault"`
	}
	if json.Unmarshal(data, &cfg) != nil {
		return ""
	}
	return cfg.Vault
}

// resolveVault returns the target vault using: --vault flag > AGENT_VAULT_VAULT env > project file > context file > "default".
func resolveVault(cmd *cobra.Command) string {
	if name, _ := cmd.Flags().GetString("vault"); name != "" {
		return name
	}
	if v := os.Getenv("AGENT_VAULT_VAULT"); v != "" {
		return v
	}
	if pv := loadProjectVault(); pv != "" {
		return pv
	}
	if ctx := session.LoadVaultContext(); ctx != "" {
		return ctx
	}
	return store.DefaultVault
}

// envVarToken is the env var name for an Agent Vault bearer token
// (vault-scoped session or long-lived agent token).
const (
	envVarToken = "AGENT_VAULT_TOKEN"

	// discoverRespMaxBytes caps JSON parsing of the /discover response so
	// a hostile or misbehaving server can't make `vault run` hang on a
	// multi-GB body. 1 MiB comfortably covers a vault with thousands of
	// services + credential keys.
	discoverRespMaxBytes = 1 << 20
)

// resolveSession returns a client session from env vars (agent mode) or falls
// back to ensureSession (human mode). When the session came from env, the
// returned string is envVarToken; "" when the session came from ensureSession.
// Callers branch on `tokenSource != ""` to distinguish agent mode from admin
// mode.
//
// If a token is set but AGENT_VAULT_ADDR is missing, returns a clear error
// rather than silently falling through to interactive login — masking that
// misconfig produces "why don't my creds work" tickets.
func resolveSession() (*session.ClientSession, string, error) {
	token := os.Getenv(envVarToken)
	addr := os.Getenv("AGENT_VAULT_ADDR")
	if token != "" && addr == "" {
		return nil, "", fmt.Errorf("%s is set but AGENT_VAULT_ADDR is empty — both are required for agent mode", envVarToken)
	}
	if token != "" {
		return &session.ClientSession{Token: token, Address: strings.TrimRight(addr, "/")}, envVarToken, nil
	}
	sess, err := ensureSession()
	return sess, "", err
}

// validateEnvToken probes /discover with the env-supplied token before
// `vault run` execs the child, so a bad/expired token fails fast at startup
// instead of producing 401s on every proxied call. /discover is the same
// auth path the proxy will use a moment later, so success here means the
// token works end-to-end.
//
// Also catches a quiet footgun: if a vault-scoped session token is supplied
// but AGENT_VAULT_VAULT names a different vault, the broker silently uses
// the session's baked-in vault and ignores X-Vault. The discover response
// echoes the actual vault, so we compare and reject the mismatch — otherwise
// the child would see a misleading AGENT_VAULT_VAULT in its environment.
func validateEnvToken(addr, token, vault, tokenSource string) error {
	if tokenSource == "" {
		tokenSource = envVarToken
	}
	url := strings.TrimRight(addr, "/") + "/discover"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("validate token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if vault != "" {
		req.Header.Set("X-Vault", vault)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("validate token: contacting %s: %w", addr, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("agent token rejected by broker (HTTP %d) — verify %s is current and has access to vault %q", resp.StatusCode, tokenSource, vault)
	}
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("validate token: server returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var dr struct {
		Vault string `json:"vault"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, discoverRespMaxBytes)).Decode(&dr); err != nil {
		return fmt.Errorf("validate token: parsing /discover response: %w", err)
	}
	// Drain trailing bytes so net/http can pool the connection (Decode
	// stops at the first JSON value's closing brace).
	_, _ = io.Copy(io.Discard, resp.Body)
	if vault != "" && dr.Vault != "" && dr.Vault != vault {
		// resolveVaultForAgentMode prioritizes --vault over AGENT_VAULT_VAULT,
		// so name both surfaces in the remediation rather than hardcoding the
		// env var (which may not even be set if the user passed --vault).
		return fmt.Errorf("vault mismatch: requested vault %q does not match the supplied token's vault %q — set AGENT_VAULT_VAULT (or --vault) to %q, or use a token for %q",
			vault, dr.Vault, dr.Vault, vault)
	}
	return nil
}

// resolveAddress determines the server address from flags, env vars, or session.
func resolveAddress(cmd *cobra.Command) string {
	if addr, _ := cmd.Flags().GetString("address"); addr != "" {
		return addr
	}
	if addr := os.Getenv("AGENT_VAULT_ADDR"); addr != "" {
		return addr
	}
	if sess, err := session.Load(); err == nil && sess != nil {
		return sess.Address
	}
	return DefaultAddress
}

// fetchAndDecode performs an authenticated request and decodes the JSON response into T.
func fetchAndDecode[T any](method, path string) (*T, error) {
	sess, err := ensureSession()
	if err != nil {
		return nil, err
	}
	var respBody []byte
	err = withReauthRetry(sess, sess.Address, func(s *session.ClientSession) error {
		var ierr error
		respBody, ierr = doAdminRequestWithBody(method, s.Address+path, s.Token, nil)
		return ierr
	})
	if err != nil {
		return nil, err
	}
	var result T
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
	return &result, nil
}

// doAdminRequestWithBody makes an authenticated HTTP request to the server and returns the response body.
func doAdminRequestWithBody(method, url, token string, body []byte) ([]byte, error) {
	return doVaultScopedRequestWithBody(method, url, token, "", body)
}

// doVaultScopedRequestWithBody is like doAdminRequestWithBody but also sends
// X-Vault: vault. Required for vault-scoped endpoints (/discover, /v1/proposals)
// when the token may be an instance-level agent token — the broker returns
// HTTP 400 ("Agent tokens require X-Vault header") without it. Vault-scoped
// session tokens carry their vault on the session row, so the header is
// ignored in that case; passing it unconditionally is safe.
func doVaultScopedRequestWithBody(method, url, token, vault string, body []byte) ([]byte, error) {
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
	if vault != "" {
		req.Header.Set("X-Vault", vault)
	}

	resp, err := httpClient.Do(req)
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
		msg := errResp.Error
		if msg == "" {
			msg = fmt.Sprintf("server returned status %d", resp.StatusCode)
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, &sessionExpiredError{msg: msg}
		}
		return nil, fmt.Errorf("%s", msg)
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

const instanceRoleHelp = "owner, member, or no-access"

func validInstanceRole(s string) bool {
	switch s {
	case "owner", "member", "no-access":
		return true
	}
	return false
}

