package server

import (
	"encoding/json"
	"io/fs"
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

	// Only the explicit AGENT_VAULT_ADDR is on the MITM SAN; auto-derived
	// fallbacks (Fly, bind-addr) would fail TLS verification from a remote
	// agent, so we don't expose them and let the client show a placeholder.
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

// handleSPA serves the SPA index.html for client-side routing.
func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	indexHTML, err := fs.ReadFile(webDistFS, "webdist/index.html")
	if err != nil {
		http.Error(w, "Frontend not built", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(indexHTML)
}
