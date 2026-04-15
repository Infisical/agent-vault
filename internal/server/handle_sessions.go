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
	Vault     string `json:"vault"`
	VaultRole string `json:"vault_role"`
}

type scopedSessionResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

func (s *Server) handleScopedSession(w http.ResponseWriter, r *http.Request) {
	var req scopedSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Vault == "" {
		jsonError(w, http.StatusBadRequest, "Vault is required")
		return
	}

	ctx := r.Context()

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}

	// Check that the user has access to this vault.
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

	sess, err := s.store.CreateScopedSession(ctx, ns.ID, cappedRole, timePtr(time.Now().Add(sessionTTL)))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create scoped session")
		return
	}

	jsonOK(w, scopedSessionResponse{
		Token:     sess.ID,
		ExpiresAt: formatExpiresAt(sess.ExpiresAt),
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
		if !agentRoleSatisfies(sess.VaultRole, "member") {
			return "", "Member role required"
		}
		callerRole = sess.VaultRole
	} else {
		// User session: require vault access.
		user, err := s.userFromSession(ctx, sess)
		if err != nil || user == nil {
			return "", "Invalid session"
		}
		has, err := s.store.HasVaultAccess(ctx, user.ID, vaultID)
		if err != nil || !has {
			return "", "No access to this vault"
		}
		role, err2 := s.store.GetVaultRole(ctx, user.ID, vaultID)
		if err2 != nil {
			return "", "Failed to check vault role"
		}
		callerRole = role
	}

	if !agentRoleSatisfies(callerRole, requestedRole) {
		return "", fmt.Sprintf("Your vault role (%s) cannot mint sessions with role %s", callerRole, requestedRole)
	}
	return requestedRole, ""
}

type directSessionRequest struct {
	Vault      string `json:"vault"`
	VaultRole  string `json:"vault_role"`
	TTLSeconds *int   `json:"ttl_seconds,omitempty"`
}

type directSessionResponse struct {
	AVAddr         string            `json:"av_addr"`
	AVSessionToken string            `json:"av_session_token"`
	AVVault        string            `json:"av_vault"`
	VaultRole      string            `json:"vault_role"`
	ProxyURL       string            `json:"proxy_url"`
	Services       []discoverService `json:"services"`
	Instructions   string            `json:"instructions"`
	ExpiresAt      string            `json:"expires_at"`
}

func (s *Server) handleDirectSession(w http.ResponseWriter, r *http.Request) {
	var req directSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Vault == "" {
		req.Vault = "default"
	}
	if req.VaultRole == "" {
		req.VaultRole = "proxy"
	}
	if req.VaultRole != "proxy" && req.VaultRole != "member" && req.VaultRole != "admin" {
		jsonError(w, http.StatusBadRequest, "vault_role must be one of: proxy, member, admin")
		return
	}
	if req.TTLSeconds != nil {
		ttl := *req.TTLSeconds
		if ttl < directSessionMinTTL || ttl > directSessionMaxTTL {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("ttl_seconds must be between %d and %d", directSessionMinTTL, directSessionMaxTTL))
			return
		}
	}
	ctx := r.Context()

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}

	sess := sessionFromContext(ctx)
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return
	}

	cappedRole, errMsg := s.capRequestedRole(ctx, sess, ns.ID, req.VaultRole)
	if errMsg != "" {
		jsonError(w, http.StatusForbidden, errMsg)
		return
	}

	// ttl_seconds omitted = no expiry; ttl_seconds present = finite session.
	var expiresAt *time.Time
	if req.TTLSeconds != nil {
		t := time.Now().Add(time.Duration(*req.TTLSeconds) * time.Second)
		expiresAt = &t
	}
	newSess, err := s.store.CreateScopedSession(ctx, ns.ID, cappedRole, expiresAt)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create session")
		return
	}

	services := s.buildServiceList(ctx, ns.ID)

	jsonOK(w, directSessionResponse{
		AVAddr:         s.baseURL,
		AVSessionToken: newSess.ID,
		AVVault:        ns.Name,
		VaultRole:      cappedRole,
		ProxyURL:       s.baseURL + "/proxy",
		Services:       services,
		Instructions:   instructionsForRole(cappedRole),
		ExpiresAt:      formatExpiresAt(newSess.ExpiresAt),
	})
}
