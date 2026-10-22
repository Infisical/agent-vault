package server

import (
	"errors"
	"net/http"
	"sort"

	"github.com/Infisical/agent-vault/internal/approval"
)

// requestApprovalVault requires an authenticated human who administers the
// vault. Agent tokens, including agent admin tokens, cannot self-approve.
func (s *Server) requestApprovalVault(w http.ResponseWriter, r *http.Request) string {
	sess := sessionFromContext(r.Context())
	if sess == nil || sess.UserID == "" {
		jsonError(w, http.StatusForbidden, "A human user session is required")
		return ""
	}
	vault, err := s.store.GetVault(r.Context(), r.PathValue("name"))
	if err != nil || vault == nil {
		jsonError(w, http.StatusNotFound, "Vault not found")
		return ""
	}
	if _, err := s.requireVaultAdmin(w, r, vault.ID); err != nil {
		return ""
	}
	return vault.ID
}

func (s *Server) handleRequestApprovalsList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	vaultID := s.requestApprovalVault(w, r)
	if vaultID == "" {
		return
	}
	items := s.approvals.List(vaultID)
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.Before(items[j].CreatedAt) })
	jsonOK(w, map[string]interface{}{"approvals": items})
}

func (s *Server) handleRequestApprovalApprove(w http.ResponseWriter, r *http.Request) {
	s.handleRequestApprovalDecision(w, r, true)
}

func (s *Server) handleRequestApprovalReject(w http.ResponseWriter, r *http.Request) {
	s.handleRequestApprovalDecision(w, r, false)
}

func (s *Server) handleRequestApprovalDecision(w http.ResponseWriter, r *http.Request, approve bool) {
	w.Header().Set("Cache-Control", "no-store")
	vaultID := s.requestApprovalVault(w, r)
	if vaultID == "" {
		return
	}
	err := s.approvals.Decide(vaultID, r.PathValue("id"), approve)
	if errors.Is(err, approval.ErrNotFound) {
		jsonError(w, http.StatusNotFound, "Pending request not found or expired")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Could not record decision")
		return
	}
	jsonOK(w, map[string]string{"status": "decided"})
}
