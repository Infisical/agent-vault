package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

type scopedSessionRequest struct {
	Vault      string `json:"vault"`
	VaultRole  string `json:"vault_role"`
	TTLSeconds *int   `json:"ttl_seconds,omitempty"`
}

type scopedSessionResponse struct {
	Token    string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	AVAddr   string `json:"av_addr,omitempty"`
	ProxyURL string `json:"proxy_url,omitempty"`
}

func (s *Server) handleScopedSession(w http.ResponseWriter, r *http.Request) {
	var req scopedSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Vault == "" {
		jsonError(w, http.StatusBadRequest, "Vault is required")
		return
	}

	// Validate role if provided.
	if req.VaultRole != "" && req.VaultRole != "proxy" && req.VaultRole != "member" && req.VaultRole != "admin" {
		jsonError(w, http.StatusBadRequest, "vault_role must be one of: proxy, member, admin")
		return
	}

	// Validate TTL bounds if provided.
	if req.TTLSeconds != nil {
		ttl := time.Duration(*req.TTLSeconds) * time.Second
		if ttl < scopedSessionMinTTL || ttl > scopedSessionMaxTTL {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf(
				"ttl_seconds must be between %d and %d",
				int(scopedSessionMinTTL.Seconds()), int(scopedSessionMaxTTL.Seconds()),
			))
			return
		}
	}

	ctx := r.Context()

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}

	// Check that the caller has access to this vault.
	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	// Default to "proxy" if no role specified; cap to caller's own role.
	requestedRole := req.VaultRole
	if requestedRole == "" {
		requestedRole = "proxy"
	}
	parentSess := sessionFromContext(ctx)
	cappedRole, errMsg := s.capRequestedRole(ctx, parentSess, ns.ID, requestedRole)
	if errMsg != "" {
		jsonError(w, http.StatusForbidden, errMsg)
		return
	}

	// Compute expiry: use ttl_seconds if provided, otherwise default 24h.
	var expiresAt *time.Time
	if req.TTLSeconds != nil {
		t := time.Now().Add(time.Duration(*req.TTLSeconds) * time.Second)
		expiresAt = &t
	} else {
		t := time.Now().Add(scopedSessionDefaultTTL)
		expiresAt = &t
	}

	sess, err := s.store.CreateScopedSession(ctx, ns.ID, cappedRole, expiresAt)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create scoped session")
		return
	}

	jsonOK(w, scopedSessionResponse{
		Token:     sess.ID,
		ExpiresAt: formatExpiresAt(sess.ExpiresAt),
		AVAddr:    s.baseURL,
		ProxyURL:  s.baseURL + "/proxy",
	})
}

// capRequestedRole enforces role-capping rules: the requested role cannot
// exceed the caller's own vault role. Proxy-role agents cannot mint sessions at all.
// Returns the validated role, or an error string if the caller lacks permission.
func (s *Server) capRequestedRole(ctx context.Context, sess *store.Session, vaultID, requestedRole string) (string, string) {
	if requestedRole == "" {
		requestedRole = "proxy"
	}

	var callerRole string

	if sess.VaultID != "" {
		// Scoped session (agent or temp invite).
		if sess.VaultID != vaultID {
			return "", "Session not authorized for this vault"
		}
		if !roleSatisfies(sess.VaultRole, "member") {
			return "", "Member role required"
		}
		callerRole = sess.VaultRole
	} else {
		// Instance-level session: resolve actor and check vault access.
		actor, err := s.actorFromSession(ctx, sess)
		if err != nil || actor == nil {
			return "", "Invalid session"
		}
		role, err2 := s.store.GetVaultRole(ctx, actor.ID, vaultID)
		if err2 != nil {
			return "", "No access to this vault"
		}
		callerRole = role
	}

	if !roleSatisfies(callerRole, requestedRole) {
		return "", fmt.Sprintf("Your vault role (%s) cannot mint sessions with role %s", callerRole, requestedRole)
	}
	return requestedRole, ""
}

