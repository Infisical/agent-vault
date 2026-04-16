package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/store"
)

// isSecureRequest returns true if the request arrived over TLS (direct) or if
// the configured baseURL uses HTTPS (proxy deployments). We derive the flag
// from the trusted server-side baseURL rather than the client-supplied
// X-Forwarded-Proto header to avoid spoofing.
func isSecureRequest(r *http.Request, baseURL string) bool {
	if r.TLS != nil {
		return true
	}
	return strings.HasPrefix(baseURL, "https://")
}

// isValidProxyHost validates that a target host is a safe hostname or host:port.
func isValidProxyHost(host string) bool {
	h := host
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		h = host[:idx]
		port := host[idx+1:]
		for _, c := range port {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return brokercore.IsValidHost(h)
}

// newProxyClient creates an HTTP client for outbound proxy requests.
// It uses a safe DialContext that blocks connections to forbidden IP ranges
// based on the AGENT_VAULT_NETWORK_MODE setting.
func newProxyClient() *http.Client {
	mode := netguard.ModeFromEnv()
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: netguard.SafeDialContext(mode),
		},
	}
}

// proxyClient is initialized in New() to ensure environment is fully configured.
var proxyClient *http.Client

// resolveVaultForSession resolves the vault ID for the current session.
// For user scoped sessions (VaultID set), returns the session's vault directly.
// For agent tokens (VaultID empty), reads vault name from X-Vault header and checks access.
// Returns vault, vault role, error. Writes error response to w on failure.
func (s *Server) resolveVaultForSession(w http.ResponseWriter, r *http.Request, sess *store.Session) (*store.Vault, string, error) {
	ctx := r.Context()

	if sess.VaultID != "" {
		// User scoped session — vault is baked into the session.
		ns, err := s.store.GetVaultByID(ctx, sess.VaultID)
		if err != nil || ns == nil {
			jsonError(w, http.StatusInternalServerError, "Failed to resolve vault")
			return nil, "", fmt.Errorf("vault not found")
		}
		return ns, sess.VaultRole, nil
	}

	// Agent token — resolve vault from X-Vault header.
	if sess.AgentID == "" {
		jsonError(w, http.StatusForbidden, "Session requires vault scope")
		return nil, "", fmt.Errorf("no vault context")
	}

	vaultName := r.Header.Get("X-Vault")
	if vaultName == "" {
		jsonError(w, http.StatusBadRequest, "Agent tokens require X-Vault header to specify which vault to use")
		return nil, "", fmt.Errorf("missing X-Vault header")
	}

	ns, err := s.store.GetVault(ctx, vaultName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, "Vault not found: "+vaultName)
		return nil, "", fmt.Errorf("vault not found")
	}

	// Check agent has access to this vault.
	role, err := s.store.GetVaultRole(ctx, sess.AgentID, ns.ID)
	if err != nil {
		jsonError(w, http.StatusForbidden, "Agent does not have access to vault: "+vaultName)
		return nil, "", fmt.Errorf("no vault access")
	}

	return ns, role, nil
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	// 1. Parse target host and path from /proxy/{target_host}/{path...}
	trimmed := strings.TrimPrefix(r.URL.Path, "/proxy/")
	if trimmed == "" {
		proxyError(w, http.StatusBadRequest, "bad_request", "Missing target host in proxy URL")
		return
	}
	// Split into host and remaining path.
	targetHost, remainingPath, _ := strings.Cut(trimmed, "/")
	if targetHost == "" {
		proxyError(w, http.StatusBadRequest, "bad_request", "Missing target host in proxy URL")
		return
	}

	// Validate targetHost is a safe hostname (no @, ?, #, spaces, control chars).
	// This prevents userinfo injection (e.g. host@evil.com) in the outbound URL.
	if !isValidProxyHost(targetHost) {
		proxyError(w, http.StatusBadRequest, "bad_request", "Invalid target host")
		return
	}

	ctx := r.Context()

	// 2. Resolve vault — user scoped sessions use session vault, agent tokens use X-Vault header.
	sess := sessionFromContext(ctx)
	if sess == nil {
		proxyError(w, http.StatusForbidden, "forbidden", "Proxy requires an authenticated session")
		return
	}
	ns, _, err := s.resolveVaultForSession(w, r, sess)
	if err != nil {
		return // error already written
	}

	// Resolve broker service + inject credentials.
	inject, err := s.CredentialProvider().Inject(ctx, ns.ID, targetHost)
	if err != nil {
		if errors.Is(err, brokercore.ErrCredentialMissing) {
			fmt.Fprintf(os.Stderr, "[agent-vault] credential resolution failed for vault %s: %v\n", ns.ID, err)
		}
		brokercore.WriteInjectError(w, err, targetHost, ns.Name)
		return
	}
	resolved := inject.Headers

	// 7. Build outbound URL.
	targetURL := "https://" + targetHost
	if remainingPath != "" {
		targetURL += "/" + remainingPath
	}
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	// 8. Build outbound request.
	outReq, err := http.NewRequestWithContext(ctx, r.Method, targetURL, r.Body)
	if err != nil {
		proxyError(w, http.StatusInternalServerError, "internal", "Failed to create outbound request")
		return
	}

	// Copy only safe headers from the agent request (allowlist approach).
	for _, k := range brokercore.PassthroughHeaders {
		if vv := r.Header.Values(k); len(vv) > 0 {
			for _, v := range vv {
				outReq.Header.Add(k, v)
			}
		}
	}
	outReq.Host = targetHost

	// Merge injected headers (injected wins on conflict).
	for k, v := range resolved {
		outReq.Header.Set(k, v)
	}

	// 9. Forward request to target.
	resp, err := proxyClient.Do(outReq)
	if err != nil {
		// Sanitize error — do not leak internal IPs or hostnames to the agent.
		proxyError(w, http.StatusBadGateway, "upstream_error",
			fmt.Sprintf("Failed to reach %s", targetHost))
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// 10. Stream response back to agent (filter unsafe headers).
	for k, vv := range resp.Header {
		// Skip hop-by-hop and security-sensitive headers from upstream.
		if brokercore.ShouldStripResponseHeader(k) {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	// Limit response body to prevent resource exhaustion.
	_, _ = io.Copy(w, io.LimitReader(resp.Body, brokercore.MaxResponseBytes))
}
