package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/spf13/cobra"
)

const gitCredentialUsername = "agent-vault"

func gitCredentialPassword() string {
	return strings.ReplaceAll("agent vault sentinel", " ", "-")
}

var gitCredentialCmd = &cobra.Command{
	Use:   "git-credential <get|store|erase>",
	Short: "Git credential helper for Agent Vault proxied Git HTTPS remotes",
	Long: `Implements Git's credential helper protocol for Git-over-HTTPS runs.

The helper deliberately returns only non-secret sentinel credentials. Real
credentials stay in Agent Vault and are injected by the MITM proxy configured by
agent-vault run --git. store and erase are safe no-ops.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGitCredentialHelper(cmd.InOrStdin(), cmd.OutOrStdout(), args[0])
	},
}

type gitCredentialRequest struct {
	Protocol string
	Host     string
	Path     string
	Username string
}

func parseGitCredentialRequest(r io.Reader) (gitCredentialRequest, error) {
	scanner := bufio.NewScanner(r)
	req := gitCredentialRequest{}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "protocol":
			req.Protocol = strings.ToLower(v)
		case "host":
			req.Host = strings.ToLower(v)
		case "path":
			req.Path = v
		case "username":
			req.Username = v
		}
	}
	if err := scanner.Err(); err != nil {
		return req, err
	}
	return req, nil
}

func runGitCredentialHelper(in io.Reader, out io.Writer, op string) error {
	req, err := parseGitCredentialRequest(in)
	if err != nil {
		return err
	}
	switch op {
	case "store", "erase":
		return nil
	case "get":
	default:
		return fmt.Errorf("unsupported git credential operation %q", op)
	}
	if !gitCredentialRequestSupported(req) {
		return nil
	}
	if !gitCredentialHostAllowed(req) {
		return nil
	}
	_, err = fmt.Fprintf(out, "username=%s\npassword=%s\n\n", gitCredentialUsername, gitCredentialPassword())
	return err
}

func gitCredentialRequestSupported(req gitCredentialRequest) bool {
	if req.Protocol != "https" || req.Host == "" {
		return false
	}
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return broker.ValidateHost(host) == nil
}

func gitCredentialHostAllowed(req gitCredentialRequest) bool {
	hosts := strings.TrimSpace(os.Getenv("AGENT_VAULT_GIT_HOSTS"))
	if hosts == "" || hosts == "*" {
		return true
	}
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	for _, pattern := range strings.Split(hosts, ",") {
		pattern = strings.TrimSpace(strings.ToLower(pattern))
		if pattern == "" {
			continue
		}
		if _, ok := broker.MatchService(host, req.Path, []broker.Service{{Name: "git", Host: pattern, Auth: broker.Auth{Type: "passthrough"}}}); ok.HostTier != 0 {
			return true
		}
	}
	return false
}

func gitConfigEnv(env []string, helperPath, caPath string) []string {
	entries := [][2]string{
		// Reset inherited/global helpers first. Without this, Git still invokes
		// helpers such as osxkeychain on store/erase and non-interactive macOS
		// runs can print fatal keychain errors even when the operation succeeds.
		{"credential.helper", ""},
		{"credential.helper", "!" + helperPath + " git-credential"},
		{"credential.useHttpPath", "true"},
		{"http.sslCAInfo", caPath},
		{"http.proxySSLCAInfo", caPath},
	}
	env = stripGitConfigEnv(env)
	env = append(env, "GIT_TERMINAL_PROMPT=0")
	env = append(env, fmt.Sprintf("GIT_CONFIG_COUNT=%d", len(entries)))
	for i, entry := range entries {
		env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, entry[0]))
		env = append(env, fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, entry[1]))
	}
	return env
}

func stripGitConfigEnv(env []string) []string {
	out := env[:0:len(env)]
	for _, kv := range env {
		key, _, _ := strings.Cut(kv, "=")
		if key == "GIT_TERMINAL_PROMPT" || key == "GIT_CONFIG_COUNT" || strings.HasPrefix(key, "GIT_CONFIG_KEY_") || strings.HasPrefix(key, "GIT_CONFIG_VALUE_") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func gitHelperPath() string {
	if p, err := os.Executable(); err == nil && p != "" {
		return p
	}
	return "agent-vault"
}

func fetchAllowedGitHosts(addr, token, vault string) string {
	if addr == "" || token == "" || vault == "" {
		return ""
	}
	reqURL := fmt.Sprintf("%s/v1/vaults/%s/services", strings.TrimRight(addr, "/"), url.PathEscape(vault))
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var payload struct {
		Services []broker.Service `json:"services"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return ""
	}
	var hosts []string
	seen := map[string]bool{}
	for _, svc := range payload.Services {
		h, _ := broker.SplitInlineHost(svc.Host, svc.Path)
		if h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	return strings.Join(hosts, ",")
}

func init() {
	rootCmd.AddCommand(gitCredentialCmd)
}
