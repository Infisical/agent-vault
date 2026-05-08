package server

import (
	"fmt"
	"net/http"

	"github.com/Infisical/agent-vault/internal/store"
)

// resolveVaultForSession resolves the vault for the current session.
// User-scoped sessions carry the vault directly; instance-level agent
// tokens select a vault via the X-Vault request header and must either
// be owners (auto-access) or have a scope grant on the vault.
func (s *Server) resolveVaultForSession(w http.ResponseWriter, r *http.Request, sess *store.Session) (*store.Vault, error) {
	ctx := r.Context()

	if sess.VaultID != "" {
		ns, err := s.store.GetVaultByID(ctx, sess.VaultID)
		if err != nil || ns == nil {
			jsonError(w, http.StatusInternalServerError, "Failed to resolve vault")
			return nil, fmt.Errorf("vault not found")
		}
		return ns, nil
	}

	if sess.AgentID == "" {
		jsonError(w, http.StatusForbidden, "Session requires vault scope")
		return nil, fmt.Errorf("no vault context")
	}

	vaultName := r.Header.Get("X-Vault")
	if vaultName == "" {
		jsonError(w, http.StatusBadRequest, "Agent tokens require X-Vault header to specify which vault to use")
		return nil, fmt.Errorf("missing X-Vault header")
	}

	ns, err := s.store.GetVault(ctx, vaultName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, "Vault not found: "+vaultName)
		return nil, fmt.Errorf("vault not found")
	}

	agent, err := s.store.GetAgentByID(ctx, sess.AgentID)
	if err != nil || agent == nil {
		jsonError(w, http.StatusForbidden, "Agent not found")
		return nil, fmt.Errorf("agent not found")
	}
	if agent.Role != "owner" {
		has, err := s.store.HasVaultAccess(ctx, sess.AgentID, ns.ID)
		if err != nil || !has {
			jsonError(w, http.StatusForbidden, "Agent does not have access to vault: "+vaultName)
			return nil, fmt.Errorf("no vault access")
		}
	}

	return ns, nil
}
