package server

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/requestlog"
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
// based on AGENT_VAULT_ALLOW_PRIVATE_RANGES and AGENT_VAULT_NETWORK_ALLOWLIST.
func newProxyClient() *http.Client {
	allowPrivate := netguard.AllowPrivateFromEnv()
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: netguard.SafeDialContext(allowPrivate),
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
	start := time.Now()
	event := brokercore.ProxyEvent{
		Ingress: brokercore.IngressExplicit,
		Method:  r.Method,
		Path:    r.URL.Path,
	}
	// Captured as the handler resolves the request; Emit hands off the
	// terminal snapshot to both the slog line and the log sink.
	var (
		logVaultID   string
		logActorType string
		logActorID   string
	)
	emit := func(status int, errCode string) {
		event.Emit(s.logger, start, status, errCode)
		// Skip persistence for early-exit paths before vault resolution:
		// an empty vault_id violates the FK constraint and would roll
		// back the entire 250ms batch, losing valid records alongside.
		if s.logSink != nil && logVaultID != "" {
			s.logSink.Record(r.Context(), requestlog.FromEvent(event, logVaultID, logActorType, logActorID))
		}
	}

	// 1. Parse target host and path from /proxy/{target_host}/{path...}
	trimmed := strings.TrimPrefix(r.URL.Path, "/proxy/")
	if trimmed == "" {
		proxyError(w, http.StatusBadRequest, "bad_request", "Missing target host in proxy URL")
		emit(http.StatusBadRequest, "bad_request")
		return
	}
	// Split into host and remaining path.
	targetHost, remainingPath, _ := strings.Cut(trimmed, "/")
	if targetHost == "" {
		proxyError(w, http.StatusBadRequest, "bad_request", "Missing target host in proxy URL")
		emit(http.StatusBadRequest, "bad_request")
		return
	}
	event.Host = targetHost
	// Log the upstream path, not the /proxy/{host}/... ingress path, so this
	// field is directly comparable to the MITM ingress log line.
	event.Path = "/" + remainingPath

	// Validate targetHost is a safe hostname (no @, ?, #, spaces, control chars).
	// This prevents userinfo injection (e.g. host@evil.com) in the outbound URL.
	if !isValidProxyHost(targetHost) {
		proxyError(w, http.StatusBadRequest, "bad_request", "Invalid target host")
		emit(http.StatusBadRequest, "bad_request")
		return
	}

	ctx := r.Context()

	// 2. Resolve vault — user scoped sessions use session vault, agent tokens use X-Vault header.
	sess := sessionFromContext(ctx)
	if sess == nil {
		proxyError(w, http.StatusForbidden, "forbidden", "Proxy requires an authenticated session")
		emit(http.StatusForbidden, "forbidden")
		return
	}
	ns, _, err := s.resolveVaultForSession(w, r, sess)
	if err != nil {
		emit(0, "vault_error")
		return // error already written
	}
	logVaultID = ns.ID
	if sess.UserID != "" {
		logActorType, logActorID = brokercore.ActorTypeUser, sess.UserID
	} else if sess.AgentID != "" {
		logActorType, logActorID = brokercore.ActorTypeAgent, sess.AgentID
	}

	// Enforced post-vault-resolution; scope isn't known until here.
	scope := &brokercore.ProxyScope{UserID: sess.UserID, AgentID: sess.AgentID}
	enf := s.rateLimit.EnforceProxy(ctx, scope.ActorID(), ns.ID)
	if !enf.Allowed {
		ratelimit.WriteDenial(w, enf.Decision, enf.Message)
		emit(http.StatusTooManyRequests, enf.ErrCode)
		return
	}
	defer enf.Release()

	r.Body = http.MaxBytesReader(w, r.Body, brokercore.MaxProxyBodyBytes)

	// Resolve broker service + inject credentials.
	inject, err := s.CredentialProvider().Inject(ctx, ns.ID, targetHost)
	if inject != nil {
		event.MatchedService = inject.MatchedHost
		event.CredentialKeys = inject.CredentialKeys
	}
	if err != nil {
		errCode := "no_match"
		status := http.StatusForbidden
		if errors.Is(err, brokercore.ErrCredentialMissing) {
			errCode = "credential_not_found"
			status = http.StatusBadGateway
			brokercore.LogCredentialMissing(s.logger, ns.ID, event.MatchedService, event.CredentialKeys)
		}
		brokercore.WriteInjectError(w, err, targetHost, ns.Name, s.baseURL)
		emit(status, errCode)
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
		emit(http.StatusInternalServerError, "internal")
		return
	}
	outReq.Host = targetHost

	// Authorization carries the Agent Vault session token on this ingress;
	// strip it on passthrough so the session credential never reaches the
	// target. Clients needing to forward an upstream Authorization should
	// use the MITM ingress, where Proxy-Authorization is broker-scoped.
	brokercore.ApplyInjection(r.Header, outReq.Header, inject, "Authorization")

	// Apply any declared substitutions to the outbound URL and headers.
	// Surfaces not listed in the substitution's `in:` are not scanned —
	// scope is the security boundary.
	if err := brokercore.ApplySubstitutions(outReq.URL, outReq.Header, inject.Substitutions); err != nil {
		proxyError(w, http.StatusBadGateway, "substitution_error", "Substitution failed before forwarding")
		emit(http.StatusBadGateway, "substitution_error")
		return
	}

	// 9. Forward request to target.
	resp, err := proxyClient.Do(outReq)
	if err != nil {
		// Log the actual error for operators (includes details like TLS failures,
		// connection refused, DNS errors, etc.) while sending sanitized message to client.
		s.logger.Debug("upstream request failed",
			slog.String("vault_id", ns.ID),
			slog.String("vault_name", ns.Name),
			slog.String("target_host", targetHost),
			slog.String("error", err.Error()),
		)
		// Sanitize error — do not leak internal IPs or hostnames to the agent.
		proxyError(w, http.StatusBadGateway, "upstream_error",
			fmt.Sprintf("Failed to reach %s", targetHost))
		emit(http.StatusBadGateway, "upstream_error")
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
	emit(resp.StatusCode, "")
}
