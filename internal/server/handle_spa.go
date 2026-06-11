package server

import (
	"encoding/json"
	"net/http"
	"os"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]string{"status": "ok"})
}

// handleStatus returns the instance initialization status (public, no auth).
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"initialized":      s.initialized,
		"needs_first_user": !s.initialized,
	}

	// Expose base_url only when the operator has explicitly set
	// AGENT_VAULT_ADDR. Auto-derived fallbacks may not be reachable from a
	// remote agent, so we suppress them and let the client show a placeholder.
	if os.Getenv("AGENT_VAULT_ADDR") != "" {
		resp["base_url"] = s.BaseURL()
	}

	// Read all settings in one query instead of two separate reads.
	if settings, err := s.store.GetAllSettings(r.Context()); err == nil {
		if raw, ok := settings[settingAllowedDomains]; ok {
			var domains []string
			if json.Unmarshal([]byte(raw), &domains) == nil && len(domains) > 0 {
				resp["allowed_email_domains"] = domains
			}
		}
		if raw, ok := settings[settingInviteOnly]; ok && raw == "true" {
			resp["invite_only"] = true
		}
	}

	jsonOK(w, resp)
}

// handleSPA serves the SPA index.html for client-side routing. The bytes
// are templated once at startup (see injectBasePath) so the <base href>
// reflects the configured UI base path.
func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	if s.indexHTML == nil {
		http.Error(w, "Frontend not built", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(s.indexHTML)
}
