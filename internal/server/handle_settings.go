package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// handleEmailTest sends a test email to verify SMTP configuration.
// Owner-only. Accepts optional JSON body {"to": "recipient@example.com"}.
// If "to" is omitted, sends to the owner's own email address.
func (s *Server) handleEmailTest(w http.ResponseWriter, r *http.Request) {
	user, err := s.requireOwner(w, r)
	if err != nil {
		return
	}

	if !s.notifier.Enabled() {
		jsonError(w, http.StatusBadRequest, "SMTP is not configured")
		return
	}

	// Parse optional recipient override.
	to := user.Email
	if r.Body != nil && r.ContentLength > 0 {
		var body struct {
			To string `json:"to"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil && body.To != "" {
			to = body.To
		}
	}

	if err := s.notifier.SendHTMLMail(
		[]string{to},
		"Agent Vault \u2014 Test Email",
		testEmailHTML,
	); err != nil {
		jsonError(w, http.StatusBadGateway, fmt.Sprintf("Failed to send test email: %v", err))
		return
	}

	jsonOK(w, map[string]string{
		"message": "Test email sent",
		"to":      to,
	})
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwner(w, r); err != nil {
		return
	}
	s.writeSettingsResponse(w, r.Context())
}

// writeSettingsResponse reads all settings and writes the JSON response.
func (s *Server) writeSettingsResponse(w http.ResponseWriter, ctx context.Context) {
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to read settings")
		return
	}

	resp := map[string]interface{}{
		"allowed_email_domains": []string{},
		"invite_only":           false,
		"smtp_configured":       s.notifier.Enabled(),
	}
	if raw, ok := settings[settingAllowedDomains]; ok {
		var domains []string
		if json.Unmarshal([]byte(raw), &domains) == nil {
			resp["allowed_email_domains"] = domains
		}
	}
	if raw, ok := settings[settingInviteOnly]; ok {
		resp["invite_only"] = raw == "true"
	}

	jsonOK(w, resp)
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwner(w, r); err != nil {
		return
	}

	var req struct {
		AllowedEmailDomains *[]string `json:"allowed_email_domains"`
		InviteOnly          *bool     `json:"invite_only"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ctx := r.Context()

	if req.InviteOnly != nil {
		val := "false"
		if *req.InviteOnly {
			val = "true"
		}
		if err := s.store.SetSetting(ctx, settingInviteOnly, val); err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to save settings")
			return
		}
	}

	if req.AllowedEmailDomains != nil {
		// Normalize: lowercase, trim whitespace, deduplicate, reject empty.
		seen := make(map[string]bool)
		var cleaned []string
		for _, d := range *req.AllowedEmailDomains {
			d = strings.ToLower(strings.TrimSpace(d))
			if d == "" {
				continue
			}
			// Basic domain validation: must contain at least one dot, no spaces.
			if !strings.Contains(d, ".") || strings.ContainsAny(d, " \t@") {
				jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid domain: %q", d))
				return
			}
			if !seen[d] {
				seen[d] = true
				cleaned = append(cleaned, d)
			}
		}

		if len(cleaned) == 0 {
			// Empty list = unrestricted, delete the setting.
			if err := s.store.SetSetting(ctx, settingAllowedDomains, "[]"); err != nil {
				jsonError(w, http.StatusInternalServerError, "Failed to save settings")
				return
			}
		} else {
			encoded, _ := json.Marshal(cleaned)
			if err := s.store.SetSetting(ctx, settingAllowedDomains, string(encoded)); err != nil {
				jsonError(w, http.StatusInternalServerError, "Failed to save settings")
				return
			}
		}
	}

	// Return the updated settings.
	s.writeSettingsResponse(w, r.Context())
}

// getAllowedDomains reads the allowed_email_domains setting from the store.
// Returns (nil, nil) if the setting is not set or is an empty array (unrestricted).
// Returns a non-nil error on database or parse failures so callers can fail closed.
func (s *Server) getAllowedDomains(ctx context.Context) ([]string, error) {
	raw, err := s.store.GetSetting(ctx, settingAllowedDomains)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // setting not configured — unrestricted
		}
		return nil, fmt.Errorf("failed to read allowed domains setting: %w", err)
	}
	var domains []string
	if err := json.Unmarshal([]byte(raw), &domains); err != nil {
		return nil, fmt.Errorf("failed to parse allowed domains setting: %w", err)
	}
	if len(domains) == 0 {
		return nil, nil
	}
	return domains, nil
}

// checkEmailDomain returns an error message if the email's domain is not in the allowed list.
// Returns "" if the domain is allowed or no restrictions are set.
// Returns a non-empty string on domain mismatch or on internal errors (fail-closed).
func (s *Server) checkEmailDomain(ctx context.Context, email string) string {
	domains, err := s.getAllowedDomains(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[agent-vault] %v\n", err)
		return "unable to verify email domain restrictions, please try again later"
	}
	if domains == nil {
		return ""
	}

	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return "invalid email address"
	}
	emailDomain := strings.ToLower(parts[1])

	for _, d := range domains {
		if emailDomain == d {
			return ""
		}
	}

	if len(domains) == 1 {
		return fmt.Sprintf("signups are restricted to @%s email addresses", domains[0])
	}
	return "signups are restricted to specific email domains"
}

// isInviteOnly returns true if invite-only registration mode is enabled.
// Fails closed: returns true on database/parse errors to prevent accidental open registration.
func (s *Server) isInviteOnly(ctx context.Context) bool {
	raw, err := s.store.GetSetting(ctx, settingInviteOnly)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false // setting not configured — open registration
		}
		fmt.Fprintf(os.Stderr, "[agent-vault] failed to read invite_only setting: %v\n", err)
		return true // fail closed
	}
	return raw == "true"
}
