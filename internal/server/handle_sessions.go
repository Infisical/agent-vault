package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

type scopedSessionRequest struct {
	Vault      string `json:"vault"`
	VaultRole  string `json:"vault_role"`
	TTLSeconds *int   `json:"ttl_seconds,omitempty"`
	Label      string `json:"label,omitempty"`
}

type scopedSessionResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	AVAddr    string `json:"av_addr,omitempty"`
}

// scopedSessionView is the JSON projection returned by GET /v1/sessions.
// The raw token is intentionally absent — it is shown only at creation
// time and never re-readable. Rows are referenced by `id` (the public_id).
type scopedSessionView struct {
	ID        string                  `json:"id"`
	Label     string                  `json:"label,omitempty"`
	VaultRole string                  `json:"vault_role"`
	CreatedBy *scopedSessionActorView `json:"created_by,omitempty"`
	CreatedAt string                  `json:"created_at"`
	ExpiresAt string                  `json:"expires_at,omitempty"`
}

type scopedSessionActorView struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	DisplayName string `json:"display_name"`
}

// maxScopedSessionLabel caps the label length stored on a scoped session.
// Labels are user-supplied free-form text shown in the Tokens UI, so we
// keep them short to avoid table layout issues.
const maxScopedSessionLabel = 100

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

	// Cap label length so the Tokens UI table stays legible.
	if len(req.Label) > maxScopedSessionLabel {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf(
			"label must be at most %d characters", maxScopedSessionLabel,
		))
		return
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

	// Resolve the calling actor so the Tokens UI can show "minted by X".
	// A nil actor here means the caller is itself a vault-scoped session
	// (e.g. an agent token or a previously-minted scoped token); we leave
	// the created_by fields blank in that case rather than failing the mint.
	var createdByID, createdByType string
	if actor, err := s.actorFromSession(ctx, parentSess); err == nil && actor != nil {
		createdByID = actor.ID
		createdByType = actor.Type
	}

	sess, err := s.store.CreateScopedSession(ctx, store.CreateScopedSessionParams{
		VaultID:            ns.ID,
		VaultRole:          cappedRole,
		ExpiresAt:          expiresAt,
		Label:              req.Label,
		CreatedByActorID:   createdByID,
		CreatedByActorType: createdByType,
	})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create scoped session")
		return
	}

	jsonOK(w, scopedSessionResponse{
		Token:     sess.ID,
		ExpiresAt: formatExpiresAt(sess.ExpiresAt),
		AVAddr:    s.baseURL,
	})
}

// handleListScopedSessions returns the active vault-scoped tokens for a
// vault, sorted most recent first. Any caller with vault access can view
// the list (mirrors how the Users/Agents tabs are visible to all members).
// The raw token is never returned — rows are referenced by public_id.
func (s *Server) handleListScopedSessions(w http.ResponseWriter, r *http.Request) {
	vaultName := r.URL.Query().Get("vault")
	if vaultName == "" {
		jsonError(w, http.StatusBadRequest, "vault is required")
		return
	}

	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, vaultName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", vaultName))
		return
	}

	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	rows, err := s.store.ListScopedSessionsByVault(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list scoped sessions")
		return
	}

	displayNames := make(map[string]string, len(rows))
	out := make([]scopedSessionView, 0, len(rows))
	for _, sess := range rows {
		view := scopedSessionView{
			ID:        sess.PublicID,
			Label:     sess.Label,
			VaultRole: sess.VaultRole,
			CreatedAt: formatExpiresAt(&sess.CreatedAt),
			ExpiresAt: formatExpiresAt(sess.ExpiresAt),
		}
		if sess.CreatedByActorID != "" && sess.CreatedByActorType != "" {
			cacheKey := sess.CreatedByActorType + ":" + sess.CreatedByActorID
			displayName, ok := displayNames[cacheKey]
			if !ok {
				if actor, err := s.actorByID(ctx, sess.CreatedByActorID, sess.CreatedByActorType); err == nil {
					displayName = actor.DisplayLabel()
				} else {
					displayName = sess.CreatedByActorID
				}
				displayNames[cacheKey] = displayName
			}
			view.CreatedBy = &scopedSessionActorView{
				ID:          sess.CreatedByActorID,
				Type:        sess.CreatedByActorType,
				DisplayName: displayName,
			}
		}
		out = append(out, view)
	}
	jsonOK(w, map[string]interface{}{"sessions": out})
}

// handleRevokeScopedSession deletes one vault-scoped token by its
// public_id. The caller must be at least a vault `member` of the row's
// vault — proxy-only sessions cannot revoke. Cross-vault revocation is
// blocked at the store level via the vault_id filter.
func (s *Server) handleRevokeScopedSession(w http.ResponseWriter, r *http.Request) {
	publicID := r.PathValue("id")
	if publicID == "" {
		jsonError(w, http.StatusBadRequest, "Session id is required")
		return
	}

	vaultName := r.URL.Query().Get("vault")
	if vaultName == "" {
		jsonError(w, http.StatusBadRequest, "vault is required")
		return
	}

	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, vaultName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", vaultName))
		return
	}

	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	err = s.store.RevokeScopedSession(ctx, ns.ID, publicID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "Session not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, "Failed to revoke scoped session")
		return
	}
	jsonOK(w, map[string]string{"status": "revoked"})
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

