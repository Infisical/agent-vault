package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/ca"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/pidfile"
	"github.com/Infisical/agent-vault/internal/server"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/spf13/cobra"
)

const maxPasswordAttempts = 3

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start an Agent Vault server",
	RunE: func(cmd *cobra.Command, args []string) error {
		port, _ := cmd.Flags().GetInt("port")
		host, _ := cmd.Flags().GetString("host")
		detach, _ := cmd.Flags().GetBool("detach")
		mitmPort, _ := cmd.Flags().GetInt("mitm-port")
		addr := fmt.Sprintf("%s:%d", host, port)

		// --- Detached child path: read master key + initialized flag from stdin pipe ---
		if os.Getenv("_AGENT_VAULT_DETACHED") == "1" {
			return runDetachedChild(host, addr, mitmPort)
		}

		dbPath, err := store.DefaultDBPath()
		if err != nil {
			return fmt.Errorf("resolving db path: %w", err)
		}

		db, err := store.Open(dbPath)
		if err != nil {
			return fmt.Errorf("opening store: %w", err)
		}
		defer func() { _ = db.Close() }()

		passwordStdin, _ := cmd.Flags().GetBool("password-stdin")
		interactive := !passwordStdin && os.Getenv("AGENT_VAULT_MASTER_PASSWORD") == ""

		masterKey, err := unlockOrSetup(cmd, db, passwordStdin)
		if err != nil {
			return err
		}

		// Check if owner account exists; create interactively if possible.
		ctx := context.Background()
		userCount, err := db.CountUsers(ctx)
		if err != nil {
			masterKey.Wipe()
			return fmt.Errorf("checking user count: %w", err)
		}
		initialized := userCount > 0

		if !initialized && interactive {
			if err := promptOwnerSetup(cmd, db, nil); err != nil {
				masterKey.Wipe()
				return err
			}
			initialized = true
		}

		if detach {
			return spawnDetached(cmd, masterKey, initialized, host, port, mitmPort, addr)
		}

		// --- Foreground path ---
		defer masterKey.Wipe()
		baseURL := os.Getenv("AGENT_VAULT_ADDR")
		if baseURL == "" {
			baseURL = "http://" + addr
		}
		smtpCfg := notify.LoadSMTPConfig()
		_ = os.Unsetenv("AGENT_VAULT_SMTP_PASSWORD")
		notifier := notify.New(smtpCfg)
		oauthProviders := loadOAuthProviders(baseURL)
		srv := server.New(addr, db, masterKey.Key(), notifier, initialized, baseURL, oauthProviders)
		srv.SetSkills(skillCLI, skillHTTP)
		if err := attachMITMIfEnabled(srv, host, mitmPort, masterKey.Key()); err != nil {
			return err
		}
		return srv.Start()
	},
}

// attachMITMIfEnabled initializes the CA and attaches a transparent MITM
// proxy to srv when mitmPort > 0. The CA is loaded or created under the
// standard ~/.agent-vault/ca/ directory, encrypted with the master key.
func attachMITMIfEnabled(srv *server.Server, host string, mitmPort int, masterKey []byte) error {
	if mitmPort <= 0 {
		return nil
	}
	caProv, err := ca.New(masterKey, ca.Options{})
	if err != nil {
		return fmt.Errorf("init CA: %w", err)
	}
	srv.AttachMITM(mitm.New(
		net.JoinHostPort(host, strconv.Itoa(mitmPort)),
		caProv,
		srv.SessionResolver(),
		srv.CredentialProvider(),
	))
	return nil
}

// promptOwnerSetup interactively creates the owner account.
// masterPassword is optional — if provided, the admin password is checked against it.
func promptOwnerSetup(cmd *cobra.Command, db *store.SQLiteStore, masterPassword []byte) error {
	fmt.Fprintln(cmd.OutOrStderr(), boldText("Create owner account:"))

	email, err := auth.PromptEmail("  Admin email: ")
	if err != nil {
		return fmt.Errorf("email input: %w", err)
	}

	pw, err := auth.PromptNewPassword("  Admin password: ", "  Confirm admin password: ")
	if err != nil {
		return fmt.Errorf("password input: %w", err)
	}

	if len(pw) < 8 {
		return fmt.Errorf("admin password must be at least 8 characters")
	}

	if masterPassword != nil && string(pw) == string(masterPassword) {
		return fmt.Errorf("admin password must be different from the master password")
	}

	hash, salt, kdfP, err := auth.HashUserPassword(pw)
	crypto.WipeBytes(pw)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	// Get the default vault so the owner is granted admin access on it.
	vault, err := db.GetVault(context.Background(), "default")
	if err != nil {
		return fmt.Errorf("looking up default vault: %w", err)
	}

	if _, err := db.RegisterFirstUser(context.Background(), email, hash, salt, vault.ID, kdfP.Time, kdfP.Memory, kdfP.Threads); err != nil {
		return fmt.Errorf("creating owner account: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "%s Owner account created for %s\n", successText("✓"), email)
	return nil
}

// unlockOrSetup prompts for the master password and returns the derived key.
// Priority: AGENT_VAULT_MASTER_PASSWORD envvar > --password-stdin > interactive prompt.
func unlockOrSetup(cmd *cobra.Command, db *store.SQLiteStore, passwordStdin bool) (*auth.MasterKey, error) {
	// 1. AGENT_VAULT_MASTER_PASSWORD envvar (highest priority, for containerized/cloud deployments)
	if envPw := os.Getenv("AGENT_VAULT_MASTER_PASSWORD"); envPw != "" {
		_ = os.Unsetenv("AGENT_VAULT_MASTER_PASSWORD")
		return unlockOrSetupWithPassword(db, []byte(envPw))
	}

	// 2. --password-stdin (non-interactive, single attempt)
	if passwordStdin {
		password, err := readPasswordFromStdin()
		if err != nil {
			return nil, err
		}
		return unlockOrSetupWithPassword(db, password)
	}

	// 3. Interactive prompt
	ctx := context.Background()
	record, err := db.GetMasterKeyRecord(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking master key: %w", err)
	}

	if record == nil {
		// First-time setup — prompt with confirmation
		fmt.Fprintln(cmd.OutOrStderr(), boldText("No master password set. Setting up for the first time."))
		pw, err := auth.PromptNewPassword(
			"Enter master password: ",
			"Confirm master password: ",
		)
		if err != nil {
			return nil, fmt.Errorf("password input: %w", err)
		}
		return setupMasterKey(db, pw)
	}

	// Interactive unlock — up to 3 attempts
	verRec := buildVerificationRecord(record)
	fmt.Fprintln(cmd.OutOrStderr(), boldText("Agent Vault is locked. Enter master password to unlock."))

	for attempt := 1; attempt <= maxPasswordAttempts; attempt++ {
		password, err := auth.PromptPassword("Master password: ")
		if err != nil {
			return nil, fmt.Errorf("password input: %w", err)
		}

		mk, err := auth.Unlock(password, verRec)
		crypto.WipeBytes(password)
		if err == nil {
			return mk, nil
		}

		if attempt < maxPasswordAttempts {
			fmt.Fprintf(cmd.OutOrStderr(), "%s Wrong password. %d attempt(s) remaining.\n", warningText("!"), maxPasswordAttempts-attempt)
		} else {
			return nil, fmt.Errorf("too many failed attempts")
		}
	}

	return nil, fmt.Errorf("too many failed attempts")
}

// unlockOrSetupWithPassword derives the master key from a known password (no prompting, no retry).
// Used by the AGENT_VAULT_MASTER_PASSWORD envvar and --password-stdin code paths.
func unlockOrSetupWithPassword(db *store.SQLiteStore, password []byte) (*auth.MasterKey, error) {
	ctx := context.Background()
	record, err := db.GetMasterKeyRecord(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking master key: %w", err)
	}

	if record == nil {
		return setupMasterKey(db, password)
	}

	// Unlock — single attempt, no retry
	verRec := buildVerificationRecord(record)
	mk, err := auth.Unlock(password, verRec)
	crypto.WipeBytes(password)
	if err != nil {
		return nil, fmt.Errorf("wrong password")
	}
	return mk, nil
}

// setupMasterKey runs first-time master key setup with the given password.
func setupMasterKey(db *store.SQLiteStore, password []byte) (*auth.MasterKey, error) {
	mk, rec, err := auth.Setup(password)
	crypto.WipeBytes(password)
	if err != nil {
		return nil, fmt.Errorf("setting up master key: %w", err)
	}

	storeRec := &store.MasterKeyRecord{
		Salt:       rec.Salt,
		Sentinel:   rec.Sentinel,
		Nonce:      rec.Nonce,
		KDFTime:    rec.Params.Time,
		KDFMemory:  rec.Params.Memory,
		KDFThreads: rec.Params.Threads,
	}
	if err := db.SetMasterKeyRecord(context.Background(), storeRec); err != nil {
		mk.Wipe()
		return nil, fmt.Errorf("persisting master key record: %w", err)
	}
	return mk, nil
}

// buildVerificationRecord converts a store record to an auth verification record.
func buildVerificationRecord(record *store.MasterKeyRecord) *auth.VerificationRecord {
	return &auth.VerificationRecord{
		Salt:     record.Salt,
		Sentinel: record.Sentinel,
		Nonce:    record.Nonce,
		Params: crypto.KDFParams{
			Time:    record.KDFTime,
			Memory:  record.KDFMemory,
			Threads: record.KDFThreads,
			KeyLen:  32,
			SaltLen: 16,
		},
	}
}

// readPasswordFromStdin reads a single line from stdin for non-interactive password input.
func readPasswordFromStdin() ([]byte, error) {
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return nil, fmt.Errorf("failed to read password from stdin")
	}
	return []byte(strings.TrimRight(scanner.Text(), "\r\n")), nil
}

// runDetachedChild is the entry point for the detached child process.
// It reads 33 bytes from stdin: 32-byte master key + 1-byte initialized flag.
func runDetachedChild(host, addr string, mitmPort int) error {
	buf := make([]byte, 33)
	if _, err := io.ReadFull(os.Stdin, buf); err != nil {
		return fmt.Errorf("reading master key from pipe: %w", err)
	}
	key := buf[:32]
	initialized := buf[32] == 1

	dbPath, err := store.DefaultDBPath()
	if err != nil {
		return fmt.Errorf("resolving db path: %w", err)
	}

	db, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer func() { _ = db.Close() }()

	baseURL := os.Getenv("AGENT_VAULT_ADDR")
	if baseURL == "" {
		baseURL = "http://" + addr
	}
	smtpCfg := notify.LoadSMTPConfig()
	_ = os.Unsetenv("AGENT_VAULT_SMTP_PASSWORD")
	notifier := notify.New(smtpCfg)
	oauthProviders := loadOAuthProviders(baseURL)
	srv := server.New(addr, db, key, notifier, initialized, baseURL, oauthProviders)
	srv.SetSkills(skillCLI, skillHTTP)
	if err := attachMITMIfEnabled(srv, host, mitmPort, key); err != nil {
		return err
	}
	return srv.Start()
}

// spawnDetached re-execs the server as a background process, passing the master key + initialized flag via a pipe.
func spawnDetached(cmd *cobra.Command, masterKey *auth.MasterKey, initialized bool, host string, port, mitmPort int, addr string) error {
	defer masterKey.Wipe()

	// Check if a server is already running.
	if pid, err := pidfile.Read(); err == nil {
		if pidfile.IsRunning(pid) {
			return fmt.Errorf("server is already running (PID %d). Use 'agent-vault server stop' to stop it first", pid)
		}
		// Stale PID file — clean up.
		_ = pidfile.Remove()
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolving executable path: %w", err)
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("creating pipe: %w", err)
	}

	logPath, err := serverLogPath()
	if err != nil {
		return fmt.Errorf("resolving log path: %w", err)
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return fmt.Errorf("opening log file: %w", err)
	}

	childArgs := []string{"server", "--port", strconv.Itoa(port), "--host", host}
	if mitmPort > 0 {
		childArgs = append(childArgs, "--mitm-port", strconv.Itoa(mitmPort))
	}
	child := exec.Command(exe, childArgs...)
	child.Stdin = pr
	child.Stdout = logFile
	child.Stderr = logFile
	child.Env = append(os.Environ(), "_AGENT_VAULT_DETACHED=1")
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := child.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		_ = logFile.Close()
		return fmt.Errorf("starting detached server: %w", err)
	}

	// Send the master key + initialized flag (33 bytes) to the child via the pipe.
	var initByte byte
	if initialized {
		initByte = 1
	}
	payload := make([]byte, 33)
	copy(payload, masterKey.Key())
	payload[32] = initByte
	if _, err := pw.Write(payload); err != nil {
		// Wipe payload before returning.
		for i := range payload {
			payload[i] = 0
		}
		_ = pw.Close()
		_ = pr.Close()
		_ = logFile.Close()
		return fmt.Errorf("sending master key to child: %w", err)
	}
	// Wipe the payload copy of the master key.
	for i := range payload {
		payload[i] = 0
	}
	_ = pw.Close()
	_ = pr.Close()
	_ = logFile.Close()

	// Poll the health endpoint to verify the child started.
	healthURL := fmt.Sprintf("http://%s/health", addr)
	started := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(healthURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				started = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	if started {
		fmt.Fprintf(cmd.OutOrStdout(), "%s Server started in background (PID %d). Logs: %s\n",
			successText("✓"), child.Process.Pid, logPath)
		return nil
	}

	fmt.Fprintf(cmd.OutOrStderr(), "%s Server may still be starting. Check %s for details.\n",
		warningText("!"), logPath)
	return fmt.Errorf("server did not respond within 3 seconds")
}

func serverLogPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".agent-vault", "server.log"), nil
}

// --- Stop subcommand ---

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop a running Agent Vault server",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		pid, err := pidfile.Read()
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("no server appears to be running (PID file not found)")
			}
			return fmt.Errorf("reading PID file: %w", err)
		}

		if !pidfile.IsRunning(pid) {
			_ = pidfile.Remove()
			return fmt.Errorf("server process %d is not running (stale PID file removed)", pid)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Stopping server (PID %d)...\n", pid)

		if err := stopServer(); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Server stopped.\n", successText("✓"))
		return nil
	},
}

// loadOAuthProviders reads OAuth configuration from environment variables
// and returns a map of enabled providers.
func loadOAuthProviders(baseURL string) map[string]oauth.Provider {
	providers := make(map[string]oauth.Provider)

	google := oauth.NewGoogleProvider(oauth.GoogleConfig{
		ClientID:     os.Getenv("AGENT_VAULT_OAUTH_GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("AGENT_VAULT_OAUTH_GOOGLE_CLIENT_SECRET"),
		RedirectURL:  strings.TrimRight(baseURL, "/") + "/v1/auth/oauth/google/callback",
	})
	if google.Enabled() {
		providers["google"] = google
	}

	// Clear sensitive env var after reading (matches master password pattern).
	_ = os.Unsetenv("AGENT_VAULT_OAUTH_GOOGLE_CLIENT_SECRET")

	return providers
}

func init() {
	serverCmd.Flags().IntP("port", "p", DefaultPort, "port to listen on")
	serverCmd.Flags().String("host", DefaultHost, "host to bind to")
	serverCmd.Flags().BoolP("detach", "d", false, "run server in background after unlocking")
	serverCmd.Flags().Bool("password-stdin", false, "read master password from stdin (for non-interactive use)")
	serverCmd.Flags().Int("mitm-port", 0, "enable transparent MITM proxy on this port (0 = disabled)")
	serverCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(serverCmd)
}
