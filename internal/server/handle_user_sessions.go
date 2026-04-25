package server

import (
	"database/sql"
	"errors"
	"net/http"
)

// userSessionView is the JSON projection returned by GET /v1/auth/sessions.
// Hides the underlying token hash; clients reference rows by PublicID.
type userSessionView struct {
	ID            string `json:"id"`
	DeviceLabel   string `json:"device_label,omitempty"`
	LastIP        string `json:"last_ip,omitempty"`
	LastUserAgent string `json:"last_user_agent,omitempty"`
	CreatedAt     string `json:"created_at"`
	LastUsedAt    string `json:"last_used_at,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	Current       bool   `json:"current"`
}

// handleListUserSessions returns active sessions for the calling user. The
// session that issued this request is flagged with current=true so a UI
// can warn before revoking it.
func (s *Server) handleListUserSessions(w http.ResponseWriter, r *http.Request) {
	caller := sessionFromContext(r.Context())
	if caller == nil || caller.UserID == "" {
		jsonError(w, http.StatusForbidden, "User session required")
		return
	}

	rows, err := s.store.ListUserSessions(r.Context(), caller.UserID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list sessions")
		return
	}

	out := make([]userSessionView, 0, len(rows))
	for _, sess := range rows {
		created := sess.CreatedAt
		out = append(out, userSessionView{
			ID:            sess.PublicID,
			DeviceLabel:   sess.DeviceLabel,
			LastIP:        sess.LastIP,
			LastUserAgent: sess.LastUserAgent,
			CreatedAt:     formatExpiresAt(&created),
			LastUsedAt:    formatExpiresAt(sess.LastUsedAt),
			ExpiresAt:     formatExpiresAt(sess.ExpiresAt),
			Current:       sess.PublicID == caller.PublicID,
		})
	}
	jsonOK(w, map[string]interface{}{"sessions": out})
}

// handleRevokeUserSession deletes one session (by public id) belonging to
// the calling user. Same-account scoping is enforced in the store; this
// handler only exposes 404 vs 200 to the caller.
func (s *Server) handleRevokeUserSession(w http.ResponseWriter, r *http.Request) {
	caller := sessionFromContext(r.Context())
	if caller == nil || caller.UserID == "" {
		jsonError(w, http.StatusForbidden, "User session required")
		return
	}
	publicID := r.PathValue("id")
	if publicID == "" {
		jsonError(w, http.StatusBadRequest, "Session id is required")
		return
	}

	err := s.store.RevokeUserSession(r.Context(), caller.UserID, publicID)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "Session not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to revoke session")
		return
	}
	// Self-revoke handling: clear the av_session cookie so a browser
	// drops the dead cookie immediately, and signal `current: true` in
	// the JSON body so non-cookie clients (the CLI) can clear their own
	// on-disk session.json without a follow-up sniffing call.
	selfRevoke := caller.PublicID == publicID
	if selfRevoke {
		http.SetCookie(w, sessionCookie(r, s.baseURL, "", -1))
	}
	jsonOK(w, revokeSessionResponse{Status: "revoked", Current: selfRevoke})
}

// revokeSessionResponse is the JSON shape returned by
// DELETE /v1/auth/sessions/{id}. Current indicates whether the caller
// just revoked their own session; CLI clients use it to decide whether
// to drop their on-disk session.json.
type revokeSessionResponse struct {
	Status  string `json:"status"`
	Current bool   `json:"current"`
}

