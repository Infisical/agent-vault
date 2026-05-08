package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type scopedSessionRequest struct {
	Vault      string `json:"vault"`
	TTLSeconds *int   `json:"ttl_seconds,omitempty"`
}

type scopedSessionResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	AVAddr    string `json:"av_addr,omitempty"`
}

func (s *Server) handleScopedSession(w http.ResponseWriter, r *http.Request) {
	var req scopedSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Vault == "" {
		jsonError(w, http.StatusBadRequest, "Vault is required")
		return
	}

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

	// requireVaultAccess returns the resolved actor; effective power inside
	// the scoped session derives from the actor's instance role.
	actor, err := s.requireVaultAccess(w, r, ns.ID)
	if err != nil {
		return
	}

	var expiresAt *time.Time
	if req.TTLSeconds != nil {
		t := time.Now().Add(time.Duration(*req.TTLSeconds) * time.Second)
		expiresAt = &t
	} else {
		t := time.Now().Add(scopedSessionDefaultTTL)
		expiresAt = &t
	}

	var userID, agentID string
	if actor.Type == "user" {
		userID = actor.ID
	} else {
		agentID = actor.ID
	}
	sess, err := s.store.CreateScopedSession(ctx, ns.ID, userID, agentID, expiresAt)
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
