package cmd

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"time"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/Infisical/agent-vault/internal/isolation"
	"github.com/Infisical/agent-vault/internal/session"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
)

//go:embed skill_cli.md
var skillCLI string

// newRunCmd is called twice — for `vault run` and top-level `run` — so each
// command gets its own pflag state. examplePrefix parameterizes the Example
// section of Long.
func newRunCmd(examplePrefix string) *cobra.Command {
	c := &cobra.Command{
		Use:   "run [flags] -- <command> [args...]",
		Short: "Wrap an agent process with Agent Vault access",
		Long: `Start an agent process (e.g. claude, agent, codex, hermes, opencode, openclaw) with an Agent Vault session.
Everything after -- is treated as the command to execute.

Two modes:
  Admin mode (default): use the on-disk session from 'agent-vault auth login'.
    Mints a fresh vault-scoped session token for the child.
  Agent mode: pre-supply a token via env. Used for unattended / containerized
    deployments where there's no human to interactively log in.
      AGENT_VAULT_TOKEN  — vault-scoped session token or long-lived agent token
      AGENT_VAULT_ADDR   — broker base URL
      AGENT_VAULT_VAULT  — vault to scope the run to (required in agent mode for both token types)
    The token is validated against the broker once before the child is exec'd.
    --ttl has no effect in agent mode and is rejected (the token's lifetime
    is fixed at mint time).

Environment variables set on the child:
  AGENT_VAULT_TOKEN  — bearer token for the Agent Vault server
  AGENT_VAULT_ADDR   — base URL of the Agent Vault HTTP control server
  AGENT_VAULT_VAULT  — vault the session is scoped to

The child also inherits HTTPS_PROXY / HTTP_PROXY / NO_PROXY /
NODE_USE_ENV_PROXY / OPENCLAW_PROXY_URL plus the root CA trust variables
(SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE,
GIT_SSL_CAINFO, DENO_CERT) so both HTTPS and plain-HTTP clients
transparently route through the broker. NODE_USE_ENV_PROXY=1 enables
Node.js built-in proxy support (v22.21.0+) so fetch() and
http.get()/https.get() honor the proxy env natively. OPENCLAW_PROXY_URL
feeds OpenClaw's Proxyline managed proxy (OpenClaw requires this in
addition to proxy.enabled in its config). HTTPS_PROXY and HTTP_PROXY
both point at the same proxy URL — the listener accepts
CONNECT for https:// upstreams and absolute-form forward-proxy requests
for http:// on the same port. The root CA PEM is written to
~/.agent-vault/mitm-ca.pem.

Example:
  ` + examplePrefix + ` -- claude
  ` + examplePrefix + ` --vault myproject -- claude`,
		Args:                  cobra.MinimumNArgs(1),
		DisableFlagsInUseLine: true,
		RunE:                  runCmdRunE,
	}

	var iso IsolationMode
	c.Flags().Var(&iso, "isolation", "Isolation mode: host (default) or container")

	c.Flags().String("address", "", "Agent Vault server address (defaults to session address)")
	c.Flags().Int("ttl", 0, "Session TTL in seconds (300–604800; default: server default 24h)")

	c.Flags().String("image", "", "Container image override (requires --isolation=container)")
	c.Flags().StringArray("mount", nil, "Extra bind mount src:dst[:ro] (repeatable; requires --isolation=container)")
	c.Flags().Bool("keep", false, "Don't pass --rm to docker (requires --isolation=container)")
	c.Flags().Bool("no-firewall", false, "Skip iptables egress rules inside the container (requires --isolation=container; debug only)")
	c.Flags().Bool("home-volume-shared", false, "Share /home/claude/.claude across invocations (requires --isolation=container); default is a per-invocation volume, losing auth state but avoiding concurrency corruption")
	c.Flags().Bool("share-agent-dir", false, "Bind-mount the host's agent state dir (~/.claude) into the container so it reuses your host login (requires --isolation=container; mutually exclusive with --home-volume-shared)")

	return c
}

var runCmd = newRunCmd("agent-vault vault run")
var topRunCmd = newRunCmd("agent-vault run")

func runCmdRunE(cmd *cobra.Command, args []string) error {
	// 0. Resolve isolation mode and validate flag compatibility before any
	//    network I/O — the user sees conflicts immediately, not after
	//    a slow session-mint round-trip.
	mode := *cmd.Flags().Lookup("isolation").Value.(*IsolationMode)
	if mode == "" {
		if v := os.Getenv("AGENT_VAULT_ISOLATION"); v != "" {
			if err := mode.Set(v); err != nil {
				return fmt.Errorf("AGENT_VAULT_ISOLATION: %w", err)
			}
		}
	}
	if mode == "" {
		mode = IsolationHost
	}
	if err := validateIsolationFlagConflicts(cmd, mode); err != nil {
		return err
	}

	// 1. Resolve session: env-supplied token (agent mode) or on-disk admin
	//    session (human mode). Agent mode is the path used by containerized
	//    deployments where there's no TTY and no on-disk session.
	//    tokenSource is "" in human mode; in agent mode it's envVarToken.
	sess, tokenSource, err := resolveSession()
	if err != nil {
		return err
	}
	fromEnv := tokenSource != ""

	addr, _ := cmd.Flags().GetString("address")
	if addr == "" {
		addr = sess.Address
	}

	// 2-3. Determine the token + vault. In agent mode the env-supplied
	//      token IS the credential; we validate it once against the broker
	//      so a bad token fails fast at startup instead of producing 401s
	//      on every proxied call. In admin mode we mint a fresh
	//      vault-scoped token (existing behavior).
	var (
		vault, token string
	)
	if fromEnv {
		// Hard-error on --ttl: the env-supplied token's lifetime is fixed
		// at mint time, so silently ignoring would mislead users who
		// believed they bounded the run.
		if cmd.Flags().Changed("ttl") {
			return fmt.Errorf("--ttl has no effect when %s is supplied; the token's lifetime is fixed at mint time", tokenSource)
		}
		v, err := resolveVaultForAgentMode(cmd)
		if err != nil {
			return err
		}
		vault = v
		token = sess.Token
		if err := validateEnvToken(addr, token, vault, tokenSource); err != nil {
			return err
		}
	} else {
		ttl, _ := cmd.Flags().GetInt("ttl")
		v, scopedToken, err := mintScopedSession(cmd, sess, addr, ttl)
		if err != nil {
			return err
		}
		vault = v
		token = scopedToken
	}

	if mode == IsolationContainer {
		return runContainer(cmd, args, token, addr, vault)
	}

	// 4. Resolve the target binary.
	binary, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("command not found: %s", args[0])
	}

	// 5. Build env: inherit current env + inject Agent Vault vars. Strip
	//    any pre-existing AGENT_VAULT_* keys first — POSIX getenv returns
	//    the *first* match (glibc, curl, libcurl-backed Python, Go's own
	//    syscall.Getenv), so a stale parent-env value would otherwise
	//    silently shadow the freshly-injected one. Particularly important
	//    in agent mode, where the parent env is *guaranteed* to carry these
	//    keys (that's how agent mode is detected).
	env := os.Environ()
	env = stripEnvKeys(env, agentVaultInjectedKeys)
	env = append(env,
		"AGENT_VAULT_TOKEN="+token,
		"AGENT_VAULT_ADDR="+addr,
		"AGENT_VAULT_VAULT="+vault,
	)

	// 6. Route the child's HTTP and HTTPS traffic through the transparent
	//    MITM proxy. The MITM ingress is the only credential-injection
	//    path, so a failure here is fatal.
	newEnv, mitmPort, err := requireMITMEnv(env, addr, token, vault, "")
	if err != nil {
		return err
	}
	env = newEnv
	fmt.Fprintf(os.Stderr, "%s routing HTTP/HTTPS through MITM proxy (%s)\n", successText("agent-vault:"), net.JoinHostPort(resolveMITMHost(addr), strconv.Itoa(mitmPort)))

	// 7. If the target command is a supported agent, offer to install the
	//    Agent Vault skill (only when not already present).
	if name, dir, ok := agentSkillDir(args[0]); ok {
		maybeInstallSkills(name, dir)
		if name == "OpenClaw" {
			maybeConfigureOpenClaw()
		}
	}

	// 8. Confirm, then exec — replaces this process entirely so the child
	//    (e.g. Claude Code) gets direct terminal control.
	fmt.Fprintf(os.Stderr, "%s agent-vault connected. Starting %s...\n\n", successText("agent-vault:"), boldText(args[0]))
	// gosec G702: this is an exec wrapper — the whole purpose is to run a
	// user-specified binary with user-specified args, identical to the
	// rationale for the G204 exclusion in .golangci.yml.
	return syscall.Exec(binary, args, env) //nolint:gosec
}

// knownAgents maps CLI binary base-names to the (agentName, skillsDir)
// pair used by maybeInstallSkills. Multiple base-names can map to the
// same entry (e.g. "cursor" and "agent" both target ".cursor").
var knownAgents = []struct {
	bases     []string
	agentName string
	baseDir   string
}{
	{[]string{"claude"}, "Claude Code", ".claude"},
	{[]string{"cursor", "agent"}, "Cursor", ".cursor"},
	{[]string{"codex"}, "Codex", ".agents"},
	{[]string{"hermes"}, "Hermes", ".hermes"},
	{[]string{"opencode"}, "OpenCode", ".opencode"},
	{[]string{"openclaw"}, "OpenClaw", ".openclaw"},
}

// agentSkillDir returns the display name and skills base directory for a
// known agent command, or ok=false if the command is not recognized.
func agentSkillDir(cmd string) (agentName, baseDir string, ok bool) {
	base := filepath.Base(cmd)
	for _, a := range knownAgents {
		for _, b := range a.bases {
			if base == b {
				return a.agentName, a.baseDir, true
			}
		}
	}
	return "", "", false
}

// maybeInstallSkills installs both Agent Vault skills (CLI and HTTP) under
// ~/{baseDir}/skills/ if either is missing, prompting the user once for
// confirmation. agentName is used in user-facing messages (e.g. "Claude Code").
func maybeInstallSkills(agentName, baseDir string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	type skillEntry struct {
		relPath string
		content string
	}
	skills := []skillEntry{
		{filepath.Join(baseDir, "skills", "agent-vault-cli", "SKILL.md"), skillCLI},
	}

	// Install or update skills whose on-disk content differs from the
	// embedded version. This keeps skills current after agent-vault
	// upgrades without requiring manual deletion.
	var stale []skillEntry
	for _, s := range skills {
		fullPath := filepath.Join(home, s.relPath)
		existing, err := os.ReadFile(fullPath)
		if err != nil || !bytes.Equal(existing, []byte(s.content)) {
			stale = append(stale, s)
		}
	}
	if len(stale) == 0 {
		return
	}

	for _, s := range stale {
		fullPath := filepath.Join(home, s.relPath)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not create skill directory: %v\n", err)
			continue
		}
		if err := os.WriteFile(fullPath, []byte(s.content), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not write skill file: %v\n", err)
			continue
		}
	}
	fmt.Fprintf(os.Stderr, "%s Installed Agent Vault skills for %s.\n", successText("agent-vault:"), agentName)
}

// maybeConfigureOpenClaw ensures OpenClaw's managed proxy and trusted env
// proxy settings are enabled. Without these, OpenClaw ignores the proxy
// env vars that agent-vault run injects. Uses `openclaw config set` so the
// settings persist across gateway restarts. Errors are non-fatal — the
// proxy still works for provider API calls via HTTPS_PROXY; these settings
// extend coverage to web_fetch and gateway-internal traffic.
func maybeConfigureOpenClaw() {
	openclawBin, err := exec.LookPath("openclaw")
	if err != nil {
		return
	}
	settings := []struct{ key, value string }{
		{"proxy.enabled", "true"},
		{"tools.web.fetch.useTrustedEnvProxy", "true"},
	}
	var ok int
	for _, s := range settings {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, err := exec.CommandContext(ctx, openclawBin, "config", "set", s.key, s.value).CombinedOutput()
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not set OpenClaw config %s: %s\n", s.key, strings.TrimSpace(string(out)))
		} else {
			ok++
		}
	}
	if ok > 0 {
		fmt.Fprintf(os.Stderr, "%s Configured OpenClaw proxy settings (revert with: openclaw config set proxy.enabled false && openclaw config set tools.web.fetch.useTrustedEnvProxy false).\n", successText("agent-vault:"))
	}
}

// resolveVaultForAgentMode picks the vault when the token is supplied via env
// (agent / containerized run). No project-file or interactive-picker fallback
// — neither makes sense in an unattended container, and silently defaulting
// to "default" would mask misconfig. Priority: --vault > AGENT_VAULT_VAULT > error.
func resolveVaultForAgentMode(cmd *cobra.Command) (string, error) {
	if name, _ := cmd.Flags().GetString("vault"); name != "" {
		return name, nil
	}
	if v := os.Getenv("AGENT_VAULT_VAULT"); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("vault is required in agent mode: set AGENT_VAULT_VAULT or pass --vault")
}

// resolveVaultForCommand is the agent-mode-aware vault resolver shared by
// peer commands that talk to vault-scoped endpoints (discover, proposal
// create). When tokenSource is non-empty (env-mode), it requires --vault or
// AGENT_VAULT_VAULT — same contract `vault run` enforces — so a
// misconfigured deploy fails fast with a clear remediation instead of
// silently sending `X-Vault: default` and routing at the wrong vault.
// In human mode it delegates to resolveVault, which falls back to project
// file / vault context / "default".
func resolveVaultForCommand(cmd *cobra.Command, tokenSource string) (string, error) {
	if tokenSource != "" {
		return resolveVaultForAgentMode(cmd)
	}
	return resolveVault(cmd), nil
}

// resolveVaultForRun picks the vault for a run session. Priority:
// --vault flag > project file > vault context > interactive select (if multiple) > "default".
func resolveVaultForRun(cmd *cobra.Command, addr, token string) (string, error) {
	// Explicit --vault flag takes priority.
	if name, _ := cmd.Flags().GetString("vault"); name != "" {
		return name, nil
	}
	// Project-level agent-vault.json is next.
	if pv := loadProjectVault(); pv != "" {
		return pv, nil
	}
	// Vault context (set by a previous command) is next.
	if ctx := session.LoadVaultContext(); ctx != "" {
		return ctx, nil
	}

	// Fetch vaults from the server to decide.
	vaults, err := fetchUserVaults(addr, token)
	if err != nil {
		// Bubble session-expiry so the outer retry can re-auth and
		// resolve the user's actual vault membership; otherwise a
		// multi-vault user would be silently demoted to "default".
		if errors.Is(err, errSessionExpired) {
			return "", err
		}
		// For any other failure (offline, server down) keep the
		// historical silent fallback to "default" so single-vault
		// users on flaky networks still get something working.
		return store.DefaultVault, nil
	}

	switch len(vaults) {
	case 0:
		return store.DefaultVault, nil
	case 1:
		return vaults[0], nil
	default:
		var choice string
		opts := make([]huh.Option[string], len(vaults))
		for i, v := range vaults {
			opts[i] = huh.NewOption(v, v)
		}
		err := huh.NewSelect[string]().
			Title("Which vault?").
			Options(opts...).
			Value(&choice).
			Run()
		if err != nil {
			return "", fmt.Errorf("vault selection: %w", err)
		}
		return choice, nil
	}
}

// fetchUserVaults returns the names of vaults the current user has access to.
func fetchUserVaults(addr, token string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, addr+"/v1/vaults", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		msg := errResp.Error
		if msg == "" {
			msg = fmt.Sprintf("status %d", resp.StatusCode)
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, &sessionExpiredError{msg: "listing vaults: " + msg}
		}
		return nil, fmt.Errorf("listing vaults: %s", msg)
	}

	var result struct {
		Vaults []struct {
			Name string `json:"name"`
		} `json:"vaults"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	names := make([]string, len(result.Vaults))
	for i, v := range result.Vaults {
		names[i] = v.Name
	}
	return names, nil
}

// mitmInjectedKeys is the keyset that BuildProxyEnv emits. Any
// pre-existing occurrence inherited from os.Environ() must be stripped
// before the new values are appended — POSIX getenv returns the *first*
// match in C code paths (glibc, curl, libcurl-backed Python), so a stale
// corporate HTTPS_PROXY from the parent shell would otherwise silently
// win and the MITM route would be bypassed entirely.
var mitmInjectedKeys = func() map[string]struct{} {
	m := make(map[string]struct{}, len(isolation.ProxyEnvKeys))
	for _, k := range isolation.ProxyEnvKeys {
		m[k] = struct{}{}
	}
	return m
}()

// agentVaultInjectedKeys is the AGENT_VAULT_* keyset injected into the child
// in step 5 of runCmdRunE. Same rationale as mitmInjectedKeys: in agent mode
// the parent env is guaranteed to already carry these keys (that's how agent
// mode is detected), and POSIX getenv returns the first match — so a stale
// AGENT_VAULT_VAULT from the parent shell would silently override the value
// we just resolved from --vault.
var agentVaultInjectedKeys = map[string]struct{}{
	"AGENT_VAULT_TOKEN": {},
	"AGENT_VAULT_ADDR":  {},
	"AGENT_VAULT_VAULT": {},
}

// stripEnvKeys returns env with every entry whose key (the part before
// '=') appears in keys removed. Case-sensitive, matching how the kernel
// stores envp and how POSIX getenv looks keys up.
func stripEnvKeys(env []string, keys map[string]struct{}) []string {
	out := env[:0:len(env)]
	for _, kv := range env {
		i := strings.IndexByte(kv, '=')
		if i < 0 {
			out = append(out, kv)
			continue
		}
		if _, drop := keys[kv[:i]]; drop {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// resolveMITMHost extracts the host the child process should dial for
// the MITM proxy from the configured server address. Falls back to
// loopback when addr is unparseable or has no host.
func resolveMITMHost(addr string) string {
	if u, err := url.Parse(addr); err == nil {
		if h := u.Hostname(); h != "" {
			return h
		}
	}
	return "127.0.0.1"
}

// requireMITMEnv calls augmentEnvWithMITM and converts both transport
// failures and a server-side --mitm-port 0 into actionable errors.
// MITM is the only ingress, so neither case is recoverable for vault run.
func requireMITMEnv(env []string, addr, token, vault, caPath string) ([]string, int, error) {
	newEnv, port, ok, err := augmentEnvWithMITM(env, addr, token, vault, caPath)
	if err != nil {
		return env, 0, fmt.Errorf("MITM setup failed: %w", err)
	}
	if !ok {
		return env, 0, errors.New("MITM proxy is disabled on the Agent Vault server; restart the server without --mitm-port 0 to enable it")
	}
	return newEnv, port, nil
}

// augmentEnvWithMITM extends env so the child transparently routes HTTP
// and HTTPS through the broker. Returns (env, 0, false, nil) when the
// server has MITM disabled. The second return value is the port the
// server reported; callers log it so operators see the actual listen
// port (not a constant). caPath is a test seam — pass "" for the
// default location.
//
// Both HTTPS_PROXY and HTTP_PROXY are injected, pointing at the same
// proxy URL. The listener handles CONNECT for https://
// upstreams and absolute-form forward-proxy requests for http://.
func augmentEnvWithMITM(env []string, addr, token, vault, caPath string) ([]string, int, bool, error) {
	pem, port, enabled, err := fetchMITMCA(addr)
	if err != nil {
		return env, 0, false, err
	}
	if !enabled {
		return env, 0, false, nil
	}
	if port == 0 {
		// Older server that didn't advertise X-MITM-Port. Fall back to
		// the compile-time default so upgrade paths don't hard-break.
		port = DefaultMITMPort
	}

	if caPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return env, 0, false, fmt.Errorf("resolve home dir: %w", err)
		}
		caPath = filepath.Join(home, ".agent-vault", "mitm-ca.pem")
	}
	if err := os.MkdirAll(filepath.Dir(caPath), 0o700); err != nil {
		return env, 0, false, fmt.Errorf("create CA dir: %w", err)
	}
	// The parent directory is already 0o700 so anyone with read access to
	// the file is also the file owner — 0o600 adds no real restriction,
	// but keeps gosec G306 happy.
	// gosec G703: caPath is derived from --mitm-ca flag or $HOME, both of
	// which are user-controlled by design (same rationale as the existing
	// G304 exclusion in .golangci.yml).
	if err := os.WriteFile(caPath, pem, 0o600); err != nil { //nolint:gosec
		return env, 0, false, fmt.Errorf("write CA: %w", err)
	}


	env = stripEnvKeys(env, mitmInjectedKeys)
	env = append(env, isolation.BuildProxyEnv(isolation.ProxyEnvParams{
		Host:   resolveMITMHost(addr),
		Port:   port,
		Token:  token,
		Vault:  vault,
		CAPath: caPath,
	})...)
	return env, port, true, nil
}

// mintScopedSession resolves the target vault and mints a vault-scoped
// session token, with inline re-auth on a 401 from the admin session.
// The interactive vault picker (huh.NewSelect for multi-vault users with
// no override) runs at most once across retries — re-prompting after
// re-auth would be a UX regression, and the user's earlier choice is
// still valid because vault membership is rechecked server-side when
// requestScopedSession fires.
func mintScopedSession(cmd *cobra.Command, sess *session.ClientSession, addr string, ttl int) (vault, scopedToken string, err error) {
	err = withReauthRetry(sess, addr, func(s *session.ClientSession) error {
		if vault == "" {
			v, verr := resolveVaultForRun(cmd, addr, s.Token)
			if verr != nil {
				return verr
			}
			vault = v
		}
		token, terr := requestScopedSession(addr, s.Token, vault, ttl)
		if terr != nil {
			return terr
		}
		scopedToken = token
		return nil
	})
	return
}

// requestScopedSession calls the server to create a vault-scoped session
// and returns the scoped token. Tokens are always minted with role
// `proxy`; the server enforces this and the CLI no longer exposes a flag
// for it.
func requestScopedSession(addr, adminToken, vault string, ttlSeconds int) (string, error) {
	body := map[string]any{"vault": vault}
	if ttlSeconds > 0 {
		body["ttl_seconds"] = ttlSeconds
	}
	reqBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, addr+"/v1/sessions", bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not reach server at %s: %w", addr, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		msg := errResp.Error
		if msg == "" {
			msg = fmt.Sprintf("status %d", resp.StatusCode)
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return "", &sessionExpiredError{msg: "failed to create scoped session: " + msg}
		}
		return "", fmt.Errorf("failed to create scoped session: %s", msg)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("parsing scoped session response: %w", err)
	}
	return result.Token, nil
}

func init() {
	// `vault run` inherits --vault from vaultCmd's persistent flag set; the
	// top-level shorthand is parented to rootCmd, which has no such flag, so
	// we register it locally here. Registering it inside newRunCmd would
	// collide with the inherited one on runCmd at flag-merge time.
	topRunCmd.Flags().String("vault", "", "target vault (overrides active context)")

	vaultCmd.AddCommand(runCmd)
	rootCmd.AddCommand(topRunCmd)
}
