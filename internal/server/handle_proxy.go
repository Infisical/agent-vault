package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/crypto"
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

// proxyForbiddenWithHint writes a 403 with a proposal_hint so agents can
// programmatically construct a proposal from a denied proxy request.
func proxyForbiddenWithHint(w http.ResponseWriter, targetHost, nsName string) {
	jsonStatus(w, http.StatusForbidden, map[string]interface{}{
		"error":   "forbidden",
		"message": fmt.Sprintf("No broker service matching host %q in vault %q", targetHost, nsName),
		"proposal_hint": map[string]interface{}{
			"host":                 targetHost,
			"endpoint":             "POST /v1/proposals",
			"supported_auth_types": broker.SupportedAuthTypes,
		},
	})
}

// hopByHopHeaders are HTTP/1.1 hop-by-hop headers that must not be forwarded by proxies.
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// isHopByHopHeader returns true if the header is a hop-by-hop header.
func isHopByHopHeader(name string) bool {
	return hopByHopHeaders[http.CanonicalHeaderKey(name)]
}

// isValidProxyHost validates that a target host is a safe hostname or host:port.
// Rejects characters that could cause URL parsing issues (userinfo injection, etc.).
func isValidProxyHost(host string) bool {
	if host == "" {
		return false
	}
	// Strip optional port suffix for hostname validation.
	h := host
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		h = host[:idx]
		port := host[idx+1:]
		// Port must be numeric.
		for _, c := range port {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	if h == "" {
		return false
	}
	// Reject any character that could cause URL parsing issues.
	for _, c := range h {
		if c == '@' || c == '?' || c == '#' || c == '/' || c == '\\' || c == ' ' || c == '%' || c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// proxyPassthroughHeaders is the allowlist of headers forwarded from agent
// requests to upstream services. All other agent headers are dropped.
var proxyPassthroughHeaders = []string{
	"Content-Type",
	"Content-Encoding",
	"Accept",
	"Accept-Encoding",
	"Accept-Language",
	"User-Agent",
	"Idempotency-Key",
	"X-Request-Id",
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

	// 4. Load broker config for this vault.
	brokerCfg, err := s.store.GetBrokerConfig(ctx, ns.ID)
	if err != nil || brokerCfg == nil {
		proxyForbiddenWithHint(w, targetHost, ns.Name)
		return
	}

	var services []broker.Service
	if err := json.Unmarshal([]byte(brokerCfg.ServicesJSON), &services); err != nil {
		proxyError(w, http.StatusInternalServerError, "internal", "Failed to parse broker services")
		return
	}

	// 5. Match host against broker services.
	// Strip port for matching (services use bare hostnames).
	matchHost := targetHost
	if h, _, err := net.SplitHostPort(targetHost); err == nil {
		matchHost = h
	}
	matched := broker.MatchHost(matchHost, services)
	if matched == nil {
		proxyForbiddenWithHint(w, targetHost, ns.Name)
		return
	}

	// 6. Resolve credentials from matched service's auth config.
	resolved, err := matched.Auth.Resolve(func(key string) (string, error) {
		cred, err := s.store.GetCredential(ctx, ns.ID, key)
		if err != nil {
			return "", fmt.Errorf("credential %q not found", key)
		}
		plaintext, err := crypto.Decrypt(cred.Ciphertext, cred.Nonce, s.encKey)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt credential %q", key)
		}
		return string(plaintext), nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[agent-vault] credential resolution failed for vault %s: %v\n", ns.ID, err)
		proxyError(w, http.StatusBadGateway, "credential_not_found", "A required credential could not be resolved; check vault configuration")
		return
	}

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
	for _, k := range proxyPassthroughHeaders {
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
		if isHopByHopHeader(k) || strings.EqualFold(k, "Set-Cookie") {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	// Limit response body to 100 MB to prevent resource exhaustion.
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 100<<20))
}
