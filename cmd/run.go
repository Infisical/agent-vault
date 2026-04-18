package cmd

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Infisical/agent-vault/internal/session"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
)

//go:embed skill_cli.md
var skillCLI string

//go:embed skill_http.md
var skillHTTP string

var runCmd = &cobra.Command{
	Use:   "run [flags] -- <command> [args...]",
	Short: "Wrap an agent process with Agent Vault access",
	Long: `Start an agent process (e.g. claude, agent, codex, hermes) with an Agent Vault session.
Everything after -- is treated as the command to execute.

Environment variables always set on the child:
  AGENT_VAULT_SESSION_TOKEN  — vault-scoped bearer token for the Agent Vault server
  AGENT_VAULT_ADDR           — base URL of the Agent Vault HTTP control server
  AGENT_VAULT_VAULT          — vault the session is scoped to

When the server's transparent MITM proxy is reachable (default), the child
also inherits HTTPS_PROXY / NO_PROXY / NODE_USE_ENV_PROXY plus the root CA trust
variables (SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE,
GIT_SSL_CAINFO, DENO_CERT) so standard HTTPS clients transparently route through the
broker. NODE_USE_ENV_PROXY=1 enables Node.js built-in proxy support (v22.21.0+) so
fetch() and https.get() honor HTTPS_PROXY natively. HTTP_PROXY is intentionally not set — the MITM proxy only handles
HTTPS (CONNECT) and would 405 any plain http:// request. The root CA PEM
is written to ~/.agent-vault/mitm-ca.pem. Pass --no-mitm to disable
injection and rely solely on the explicit /proxy/{host}/{path} endpoint.

Example:
  agent-vault vault run -- claude
  agent-vault vault run --vault myproject -- claude
  agent-vault vault run --no-mitm -- claude`,
	Args:                  cobra.MinimumNArgs(1),
	DisableFlagsInUseLine: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1. Load the admin session from agent-vault auth login.
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		addr, _ := cmd.Flags().GetString("address")
		if addr == "" {
			addr = sess.Address
		}

		// 2. Resolve the target vault: --vault flag > context > interactive select > "default".
		vault, err := resolveVaultForRun(cmd, addr, sess.Token)
		if err != nil {
			return err
		}

		// 3. Request a vault-scoped session token from the server.
		role, _ := cmd.Flags().GetString("role")
		ttl, _ := cmd.Flags().GetInt("ttl")
		scopedToken, err := requestScopedSession(addr, sess.Token, vault, role, ttl)
		if err != nil {
			return err
		}

		// 4. Resolve the target binary.
		binary, err := exec.LookPath(args[0])
		if err != nil {
			return fmt.Errorf("command not found: %s", args[0])
		}

		// 5. Build env: inherit current env + inject Agent Vault vars.
		env := os.Environ()
		env = append(env,
			"AGENT_VAULT_SESSION_TOKEN="+scopedToken,
			"AGENT_VAULT_ADDR="+addr,
			"AGENT_VAULT_VAULT="+vault,
		)

		// 6. Route the child's HTTPS traffic through the transparent MITM
		//    proxy. Explicit /proxy stays available as a fallback.
		if noMITM, _ := cmd.Flags().GetBool("no-mitm"); !noMITM {
			newEnv, mitmPort, ok, err := augmentEnvWithMITM(env, addr, scopedToken, vault, "")
			switch {
			case err != nil:
				fmt.Fprintf(os.Stderr, "agent-vault: MITM setup failed (%v); continuing with explicit proxy only\n", err)
			case !ok:
				fmt.Fprintln(os.Stderr, "agent-vault: MITM proxy disabled on server; using explicit proxy only")
			default:
				env = newEnv
				fmt.Fprintf(os.Stderr, "%s routing HTTPS through MITM proxy (127.0.0.1:%d)\n", successText("agent-vault:"), mitmPort)
			}
		}

		// 7. If the target command is a supported agent, offer to install the
		//    Agent Vault skill (only when not already present).
		if name, dir, ok := agentSkillDir(args[0]); ok {
			maybeInstallSkills(name, dir)
		}

		// 8. Confirm, then exec — replaces this process entirely so the child
		//    (e.g. Claude Code) gets direct terminal control.
		fmt.Fprintf(os.Stderr, "%s agent-vault connected. Starting %s...\n\n", successText("agent-vault:"), boldText(args[0]))
		return syscall.Exec(binary, args, env)
	},
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
		{filepath.Join(baseDir, "skills", "agent-vault-http", "SKILL.md"), skillHTTP},
	}

	// Check which skills need installing.
	var missing []skillEntry
	for _, s := range skills {
		if _, err := os.Stat(filepath.Join(home, s.relPath)); err != nil {
			missing = append(missing, s)
		}
	}
	if len(missing) == 0 {
		return
	}

	fmt.Fprintf(os.Stderr, "Install Agent Vault skills for %s? [Y/n] ", agentName)
	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer != "" && answer != "y" && answer != "yes" {
		return
	}

	for _, s := range missing {
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
		// If we can't list vaults, fall back to "default".
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

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
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

// mitmInjectedKeys is the set of env keys augmentEnvWithMITM manages on
// the child. Any pre-existing occurrence inherited from os.Environ() must
// be stripped before the new values are appended — POSIX getenv returns
// the *first* match in C code paths (glibc, curl, libcurl-backed Python),
// so a stale corporate HTTPS_PROXY from the parent shell would otherwise
// silently win and the MITM route would be bypassed entirely.
var mitmInjectedKeys = map[string]struct{}{
	"HTTPS_PROXY":         {},
	"NO_PROXY":            {},
	"NODE_USE_ENV_PROXY":  {},
	"SSL_CERT_FILE":       {},
	"NODE_EXTRA_CA_CERTS": {},
	"REQUESTS_CA_BUNDLE":  {},
	"CURL_CA_BUNDLE":      {},
	"GIT_SSL_CAINFO":      {},
	"DENO_CERT":           {},
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

// augmentEnvWithMITM extends env so the child transparently routes HTTPS
// through the broker. Returns (env, 0, false, nil) when the server has
// MITM disabled. The second return value is the port the server reported;
// callers log it so operators see the actual listen port (not a constant).
// caPath is a test seam — pass "" for the default location.
//
// Only HTTPS_PROXY is injected — not HTTP_PROXY. The MITM proxy handles
// HTTP CONNECT only and returns 405 for every other method, so setting
// HTTP_PROXY would route plain http:// requests into a dead end.
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
	if err := os.WriteFile(caPath, pem, 0o600); err != nil {
		return env, 0, false, fmt.Errorf("write CA: %w", err)
	}

	mitmHost := "127.0.0.1"
	if u, err := url.Parse(addr); err == nil {
		if h := u.Hostname(); h != "" {
			mitmHost = h
		}
	}
	proxyURL := (&url.URL{
		Scheme: "http",
		User:   url.UserPassword(token, vault),
		Host:   fmt.Sprintf("%s:%d", mitmHost, port),
	}).String()

	env = stripEnvKeys(env, mitmInjectedKeys)
	// CA trust variables must stay in sync with buildProxyEnv() in
	// sdks/sdk-typescript/src/resources/sessions.ts.
	env = append(env,
		"HTTPS_PROXY="+proxyURL,
		"NO_PROXY=localhost,127.0.0.1",
		"NODE_USE_ENV_PROXY=1",
		"SSL_CERT_FILE="+caPath,
		"NODE_EXTRA_CA_CERTS="+caPath,
		"REQUESTS_CA_BUNDLE="+caPath,
		"CURL_CA_BUNDLE="+caPath,
		"GIT_SSL_CAINFO="+caPath,
		"DENO_CERT="+caPath,
	)
	return env, port, true, nil
}

// requestScopedSession calls the server to create a vault-scoped session
// and returns the scoped token.
func requestScopedSession(addr, adminToken, vault, role string, ttlSeconds int) (string, error) {
	body := map[string]any{"vault": vault}
	if role != "" {
		body["vault_role"] = role
	}
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

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not reach server at %s: %w", addr, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error != "" {
			return "", fmt.Errorf("failed to create scoped session: %s", errResp.Error)
		}
		return "", fmt.Errorf("failed to create scoped session (status %d)", resp.StatusCode)
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
	runCmd.Flags().String("address", "", "Agent Vault server address (defaults to session address)")
	runCmd.Flags().String("role", "", "Vault role for the agent session (proxy, member, admin; default: proxy)")
	runCmd.Flags().Int("ttl", 0, "Session TTL in seconds (300–604800; default: server default 24h)")
	runCmd.Flags().Bool("no-mitm", false, "Skip HTTPS_PROXY/CA env injection for the child (explicit /proxy only)")

	vaultCmd.AddCommand(runCmd)
}
