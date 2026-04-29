package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
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
	"github.com/Infisical/agent-vault/internal/requestlog"
	"github.com/Infisical/agent-vault/internal/server"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/spf13/cobra"
)

const maxPasswordAttempts = 3

// resolveLogLevel turns the --log-level flag (or AGENT_VAULT_LOG_LEVEL env
// fallback) into a slog.Level. Flag wins if explicitly set. Accepts "info"
// and "debug" only — anything else is rejected with a clear error.
// flagChanged indicates whether the user passed --log-level explicitly.
func resolveLogLevel(flagValue string, flagChanged bool) (slog.Level, error) {
	value := flagValue
	if !flagChanged {
		if env := os.Getenv("AGENT_VAULT_LOG_LEVEL"); env != "" {
			value = env
		}
	}
	switch strings.ToLower(value) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	default:
		return 0, fmt.Errorf("invalid log level %q (accepted: info, debug)", value)
	}
}

// resolveBaseURL returns the externally-reachable base URL for the server.
// Priority: AGENT_VAULT_ADDR env var > FLY_APP_NAME-derived URL > http://{addr}.
func resolveBaseURL(addr string) string {
	if v := os.Getenv("AGENT_VAULT_ADDR"); v != "" {
		return v
	}
	if app := os.Getenv("FLY_APP_NAME"); app != "" {
		return "https://" + app + ".fly.dev"
	}
	return "http://" + addr
}

// buildLogger constructs the process-wide slog logger. Text handler to
// stderr keeps it readable in a terminal without a dependency bump.
func buildLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start an Agent Vault server",
	RunE: func(cmd *cobra.Command, args []string) error {
		port, _ := cmd.Flags().GetInt("port")
		host, _ := cmd.Flags().GetString("host")
		detach, _ := cmd.Flags().GetBool("detach")
		mitmPort, _ := cmd.Flags().GetInt("mitm-port")
		logLevelFlag, _ := cmd.Flags().GetString("log-level")
		logLevelChanged := cmd.Flags().Changed("log-level")
		addr := fmt.Sprintf("%s:%d", host, port)

		logLevel, err := resolveLogLevel(logLevelFlag, logLevelChanged)
		if err != nil {
			return err
		}
		logger := buildLogger(logLevel)

		// --- Detached child path: read master key + initialized flag from stdin pipe ---
		if os.Getenv("_AGENT_VAULT_DETACHED") == "1" {
			return runDetachedChild(host, addr, mitmPort, logger)
		}

		// Pre-flight before unlocking the vault: don't make the user type a
		// master password just to learn the port is taken.
		if pid, err := pidfile.Read(); err == nil {
			if pid != os.Getpid() && pidfile.IsRunning(pid) {
				return fmt.Errorf("server is already running (PID %d). Use 'agent-vault server stop' to stop it first", pid)
			}
			_ = pidfile.Remove()
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
			var explicitLogLevel *string
			if logLevelChanged {
				explicitLogLevel = &logLevelFlag
			}
			return spawnDetached(cmd, masterKey, initialized, host, port, mitmPort, addr, explicitLogLevel)
		}

		// --- Foreground path ---
		defer masterKey.Wipe()
		baseURL := resolveBaseURL(addr)
		smtpCfg := notify.LoadSMTPConfig()
		_ = os.Unsetenv("AGENT_VAULT_SMTP_PASSWORD")
		notifier := notify.New(smtpCfg)
		oauthProviders := loadOAuthProviders(baseURL)
		srv := server.New(addr, db, masterKey.Key(), notifier, initialized, baseURL, oauthProviders, logger)
		srv.SetSkills(skillCLI, skillHTTP)
		shutdownLogs := attachLogSink(srv, db, logger)
		defer shutdownLogs()
		if err := attachMITMIfEnabled(srv, host, mitmPort, masterKey.Key()); err != nil {
			return err
		}
		return srv.Start()
	},
}

// attachMITMIfEnabled initializes the CA and attaches a transparent MITM
// proxy to srv when mitmPort > 0. The CA is loaded or created under the
// standard ~/.agent-vault/ca/ directory, encrypted with the master key.
//
// CA init failures are non-fatal, matching the behavior for bind failures
// in server.Start: since the MITM proxy is default-on, environments that
// cannot create ~/.agent-vault/ca/ (read-only FS, containers without HOME,
// corrupted state) must still be able to run the core HTTP server.
func attachMITMIfEnabled(srv *server.Server, host string, mitmPort int, masterKey []byte) error {
	if mitmPort <= 0 {
		return nil
	}
	caProv, err := ca.New(masterKey, ca.Options{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: transparent proxy disabled (CA init failed: %v); pass --mitm-port 0 to suppress\n", err)
		return nil
	}
	srv.AttachMITM(mitm.New(
		net.JoinHostPort(host, strconv.Itoa(mitmPort)),
		mitm.Options{
			CA:          caProv,
			Sessions:    srv.SessionResolver(),
			Credentials: srv.CredentialProvider(),
			BaseURL:     srv.BaseURL(),
			Logger:      srv.Logger(),
			RateLimit:   srv.RateLimit(),
			LogSink:     srv.LogSink(),
		},
	))
	return nil
}

// attachLogSink wires the request-log pipeline: a SQLiteSink with async
// batching feeds persistent storage, and a retention goroutine trims old
// rows. Returns a shutdown function the caller runs after Start()
// returns to flush pending records and stop retention.
func attachLogSink(srv *server.Server, db *store.SQLiteStore, logger *slog.Logger) func() {
	sink := requestlog.NewSQLiteSink(db, logger, requestlog.SQLiteSinkConfig{})
	srv.AttachLogSink(sink)

	retentionCtx, cancelRetention := context.WithCancel(context.Background())
	go requestlog.RunRetention(retentionCtx, db, logger)

	return func() {
		cancelRetention()
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := sink.Close(flushCtx); err != nil {
			fmt.Fprintf(os.Stderr, "warning: request_log sink flush: %v\n", err)
		}
	}
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

// unlockOrSetup resolves the master password and returns the DEK.
// Priority: AGENT_VAULT_MASTER_PASSWORD envvar > --password-stdin > interactive prompt.
// When no password is provided (envvar empty, no --password-stdin), sets up in passwordless mode.
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
		// First-time setup — prompt with confirmation, allow empty for passwordless
		fmt.Fprintln(cmd.OutOrStderr(), boldText("Setting up for the first time."))
		pw, err := auth.PromptNewPassword(
			"Enter master password (leave empty for passwordless): ",
			"Confirm master password: ",
		)
		if err != nil {
			return nil, fmt.Errorf("password input: %w", err)
		}
		return setupMasterKey(db, pw)
	}

	// Existing record — check if passwordless
	if record.DEKPlaintext != nil {
		verRec := buildVerificationRecord(record)
		mk, err := auth.UnlockPasswordless(verRec)
		if err != nil {
			return nil, fmt.Errorf("unlocking (passwordless): %w", err)
		}
		return mk, nil
	}

	// Password-protected — interactive unlock, up to 3 attempts
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

// unlockOrSetupWithPassword resolves the DEK using a known password (no prompting, no retry).
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

	// Passwordless instance — password is ignored, unlock without it
	if record.DEKPlaintext != nil {
		crypto.WipeBytes(password)
		verRec := buildVerificationRecord(record)
		mk, err := auth.UnlockPasswordless(verRec)
		if err != nil {
			return nil, fmt.Errorf("unlocking (passwordless): %w", err)
		}
		return mk, nil
	}

	// Password-protected — single attempt, no retry
	verRec := buildVerificationRecord(record)
	mk, err := auth.Unlock(password, verRec)
	crypto.WipeBytes(password)
	if err != nil {
		return nil, fmt.Errorf("wrong password")
	}
	return mk, nil
}

// setupMasterKey runs first-time DEK generation and KEK wrapping.
// If password is empty, sets up in passwordless mode.
func setupMasterKey(db *store.SQLiteStore, password []byte) (*auth.MasterKey, error) {
	var mk *auth.MasterKey
	var rec *auth.VerificationRecord
	var err error

	if len(password) == 0 {
		mk, rec, err = auth.SetupPasswordless()
	} else {
		mk, rec, err = auth.SetupWithPassword(password)
		crypto.WipeBytes(password)
	}
	if err != nil {
		return nil, fmt.Errorf("setting up master key: %w", err)
	}

	storeRec := verificationToStoreRecord(rec)
	if err := db.SetMasterKeyRecord(context.Background(), storeRec); err != nil {
		mk.Wipe()
		return nil, fmt.Errorf("persisting master key record: %w", err)
	}
	return mk, nil
}

// verificationToStoreRecord converts an auth VerificationRecord to a store MasterKeyRecord.
func verificationToStoreRecord(rec *auth.VerificationRecord) *store.MasterKeyRecord {
	r := &store.MasterKeyRecord{
		Sentinel:      rec.Sentinel,
		SentinelNonce: rec.SentinelNonce,
		DEKCiphertext: rec.DEKCiphertext,
		DEKNonce:      rec.DEKNonce,
		DEKPlaintext:  rec.DEKPlaintext,
		Salt:          rec.Salt,
	}
	if rec.Params.Time > 0 {
		r.KDFTime = &rec.Params.Time
		r.KDFMemory = &rec.Params.Memory
		r.KDFThreads = &rec.Params.Threads
	}
	return r
}

// buildVerificationRecord converts a store record to an auth verification record.
func buildVerificationRecord(record *store.MasterKeyRecord) *auth.VerificationRecord {
	vr := &auth.VerificationRecord{
		Sentinel:      record.Sentinel,
		SentinelNonce: record.SentinelNonce,
		DEKCiphertext: record.DEKCiphertext,
		DEKNonce:      record.DEKNonce,
		DEKPlaintext:  record.DEKPlaintext,
		Salt:          record.Salt,
	}
	if record.KDFTime != nil {
		defaults := crypto.DefaultKDFParams()
		vr.Params = crypto.KDFParams{
			Time:    *record.KDFTime,
			Memory:  *record.KDFMemory,
			Threads: *record.KDFThreads,
			KeyLen:  defaults.KeyLen,
			SaltLen: defaults.SaltLen,
		}
	}
	return vr
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
func runDetachedChild(host, addr string, mitmPort int, logger *slog.Logger) error {
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

	baseURL := resolveBaseURL(addr)
	smtpCfg := notify.LoadSMTPConfig()
	_ = os.Unsetenv("AGENT_VAULT_SMTP_PASSWORD")
	notifier := notify.New(smtpCfg)
	oauthProviders := loadOAuthProviders(baseURL)
	srv := server.New(addr, db, key, notifier, initialized, baseURL, oauthProviders, logger)
	srv.SetSkills(skillCLI, skillHTTP)
	shutdownLogs := attachLogSink(srv, db, logger)
	defer shutdownLogs()
	if err := attachMITMIfEnabled(srv, host, mitmPort, key); err != nil {
		return err
	}
	return srv.Start()
}

// spawnDetached re-execs the server as a background process, passing the master key + initialized flag via a pipe.
// explicitLogLevel, when non-nil, forwards the parent's --log-level flag to the child so a flag-only
// invocation (no env var) still takes effect after re-exec.
func spawnDetached(cmd *cobra.Command, masterKey *auth.MasterKey, initialized bool, host string, port, mitmPort int, addr string, explicitLogLevel *string) error {
	defer masterKey.Wipe()

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

	childArgs := []string{"server", "--port", strconv.Itoa(port), "--host", host, "--mitm-port", strconv.Itoa(mitmPort)}
	if explicitLogLevel != nil {
		childArgs = append(childArgs, "--log-level", *explicitLogLevel)
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
		crypto.WipeBytes(payload)
		_ = pw.Close()
		_ = pr.Close()
		_ = logFile.Close()
		return fmt.Errorf("sending master key to child: %w", err)
	}
	crypto.WipeBytes(payload)
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
	serverCmd.Flags().IntP("port", "p", defaultPort(), "port to listen on (also respects PORT env var)")
	serverCmd.Flags().String("host", DefaultHost, "host to bind to")
	serverCmd.Flags().BoolP("detach", "d", false, "run server in background after unlocking")
	serverCmd.Flags().Bool("password-stdin", false, "read master password from stdin (for non-interactive use)")
	serverCmd.Flags().Int("mitm-port", DefaultMITMPort, "port for the transparent MITM proxy (0 = disabled)")
	serverCmd.Flags().String("log-level", "info", "log level: info (default) or debug (per-request proxy logs)")
	serverCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(serverCmd)
}
