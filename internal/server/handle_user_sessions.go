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
	// Self-revoke: clear the av_session cookie so a browser caller drops
	// the now-dead cookie immediately instead of carrying it until the
	// next 401. Mirrors handleLogout / handleDeleteAccount. CLI Bearer
	// callers don't carry the cookie and ignore Set-Cookie headers.
	if caller.PublicID == publicID {
		http.SetCookie(w, sessionCookie(r, s.baseURL, "", -1))
	}
	jsonOK(w, map[string]string{"status": "revoked"})
}

