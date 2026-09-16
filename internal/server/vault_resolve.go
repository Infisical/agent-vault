package server

import (
	"fmt"
	"net/http"

	"github.com/Infisical/agent-vault/internal/store"
)

// resolveVaultByPath resolves the vault named by the {name} path value,
// responding 404 and returning nil when it does not exist. Callers read the
// vault name back off the returned row. This is the preamble every
// vault-scoped handler opens with; it carries no authorization, so callers
// still apply requireVaultAccess/requireVaultMember/requireVaultAdmin.
func (s *Server) resolveVaultByPath(w http.ResponseWriter, r *http.Request) *store.Vault {
	name := r.PathValue("name")
	ns, err := s.store.GetVault(r.Context(), name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return nil
	}
	return ns
}

// resolveVaultForSession resolves the vault and vault role for the current
// session. User-scoped sessions carry the vault directly; instance-level
// agent tokens select a vault via the X-Vault request header and the
// agent's vault membership.
func (s *Server) resolveVaultForSession(w http.ResponseWriter, r *http.Request, sess *store.Session) (*store.Vault, string, error) {
	ctx := r.Context()

	if sess.VaultID != "" {
		ns, err := s.store.GetVaultByID(ctx, sess.VaultID)
		if err != nil || ns == nil {
			jsonError(w, http.StatusInternalServerError, "Failed to resolve vault")
			return nil, "", fmt.Errorf("vault not found")
		}
		return ns, sess.VaultRole, nil
	}

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

	role, err := s.store.GetVaultRole(ctx, sess.AgentID, ns.ID)
	if err != nil {
		jsonError(w, http.StatusForbidden, "Agent does not have access to vault: "+vaultName)
		return nil, "", fmt.Errorf("no vault access")
	}

	return ns, role, nil
}
