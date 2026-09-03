package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/store"
)

// A skill is a named markdown instruction document scoped to one vault.
// Reads are open to any vault grant (including `proxy`, so an agent's own
// token can pull the skills it should be following); mutations are vault
// admin only. Skills are deliberately outside the proposal system: agents
// cannot propose skill changes, so nothing here touches internal/proposal.
//
// Bodies are stored in plaintext, unlike credentials.

const (
	// maxSkillDescriptionChars matches the Agent Skills frontmatter limit for
	// a skill's `description` field, so a skill authored here stays valid when
	// `vault run` writes it out as SKILL.md. Mirrored as
	// MAX_DESCRIPTION_CHARS in web/src/pages/vault/SkillsTab.tsx.
	//
	// The companion `name` limit from that spec (64 characters) is already
	// enforced by broker.ValidateSlug, which is also stricter about the
	// charset because the name becomes a directory name on disk.
	maxSkillDescriptionChars = 1024
	// maxSkillContentChars caps the markdown body, counted in characters
	// (runes) rather than bytes so the limit means the same thing to the
	// author as it does here — the dashboard shows this exact number. Also
	// bounds the payload: at UTF-8's worst case of 4 bytes per rune this is
	// 400 KB, comfortably under limitBody's 1 MB ceiling, so an oversized
	// paste gets a precise error instead of a generic decode failure.
	// Mirrored as MAX_CONTENT_CHARS in web/src/pages/vault/SkillsTab.tsx —
	// update both together.
	maxSkillContentChars = 100_000
)

// skillResponse is the wire shape for a single skill. Content is omitted
// from list responses so the payload stays small regardless of body size.
type skillResponse struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Content     string    `json:"content,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func skillToResponse(sk *store.Skill) skillResponse {
	return skillResponse{
		Name:        sk.Name,
		Description: sk.Description,
		Content:     sk.Content,
		CreatedAt:   sk.CreatedAt,
		UpdatedAt:   sk.UpdatedAt,
	}
}

// normalizeSkillContent makes bodies stable across platforms: skills are
// written to disk verbatim by `vault run`, so CRLF would leak into files.
func normalizeSkillContent(content string) string {
	return strings.ReplaceAll(content, "\r\n", "\n")
}

// validateSkillPayload enforces the skill field rules. Names reuse
// broker.ValidateSlug because a skill name becomes a directory name when
// `vault run` writes the skill to an agent's filesystem.
func validateSkillPayload(name, description, content string) error {
	if err := broker.ValidateSlug(name); err != nil {
		return err
	}
	if !utf8.ValidString(description) || !utf8.ValidString(content) {
		return errors.New("description and content must be valid UTF-8")
	}
	// NUL bytes are a genuine dialect divergence: SQLite stores them in
	// TEXT while Postgres rejects them outright, so without this check the
	// same request succeeds on SQLite and 500s on Postgres. Name needs no
	// check — ValidateSlug already restricts it to [a-z0-9-].
	if strings.ContainsRune(description, 0) || strings.ContainsRune(content, 0) {
		return errors.New("description and content must not contain NUL bytes")
	}
	// Counted in runes, not bytes, so a limit stated to the author in
	// characters is the limit actually enforced regardless of script.
	if utf8.RuneCountInString(description) > maxSkillDescriptionChars {
		return fmt.Errorf("description must be at most %d characters", maxSkillDescriptionChars)
	}
	if strings.TrimSpace(content) == "" {
		return errors.New("content is required")
	}
	if n := utf8.RuneCountInString(content); n > maxSkillContentChars {
		return fmt.Errorf("content must be at most %d characters (got %d)", maxSkillContentChars, n)
	}
	return nil
}

// handleSkillsList returns the vault's skills without their markdown bodies.
func (s *Server) handleSkillsList(w http.ResponseWriter, r *http.Request) {
	ns := s.resolveVaultByPath(w, r)
	if ns == nil {
		return
	}
	name := ns.Name
	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	metas, err := s.store.ListSkills(r.Context(), ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list skills")
		return
	}

	out := make([]skillResponse, 0, len(metas))
	for _, m := range metas {
		out = append(out, skillResponse{
			Name:        m.Name,
			Description: m.Description,
			CreatedAt:   m.CreatedAt,
			UpdatedAt:   m.UpdatedAt,
		})
	}
	jsonOK(w, map[string]interface{}{"vault": name, "skills": out})
}

// handleSkillGet returns one skill including its markdown body.
func (s *Server) handleSkillGet(w http.ResponseWriter, r *http.Request) {
	ns := s.resolveVaultByPath(w, r)
	if ns == nil {
		return
	}
	name := ns.Name
	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	skillName := r.PathValue("skill")
	sk, err := s.store.GetSkill(r.Context(), ns.ID, skillName)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Skill %q not found", skillName))
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to load skill")
		return
	}
	jsonOK(w, map[string]interface{}{"vault": name, "skill": skillToResponse(sk)})
}

// handleSkillCreate adds a skill to the vault. Vault admin only.
func (s *Server) handleSkillCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ns := s.resolveVaultByPath(w, r)
	if ns == nil {
		return
	}
	name := ns.Name
	actor, err := s.requireVaultAdmin(w, r, ns.ID)
	if err != nil {
		return
	}

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Content     string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	req.Content = normalizeSkillContent(req.Content)
	if err := validateSkillPayload(req.Name, req.Description, req.Content); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	// No vault lock needed: InsertSkill is a single INSERT ... ON CONFLICT
	// DO NOTHING, and the (vault_id, name) primary key is the uniqueness
	// guard. Only handleSkillPatch does a read-modify-write.
	sk, err := s.store.InsertSkill(ctx, store.Skill{
		VaultID:     ns.ID,
		Name:        req.Name,
		Description: req.Description,
		Content:     req.Content,
	})
	if errors.Is(err, store.ErrSkillExists) {
		jsonError(w, http.StatusConflict, fmt.Sprintf("A skill named %q already exists", req.Name))
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create skill")
		return
	}

	s.captureEvent(r, "av.skill-add", actor, map[string]string{"vault": name})
	jsonCreated(w, map[string]interface{}{"vault": name, "skill": skillToResponse(sk)})
}

// handleSkillPatch updates a skill's name, description, and/or body.
// Vault admin only. Omitted fields are left as-is.
func (s *Server) handleSkillPatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ns := s.resolveVaultByPath(w, r)
	if ns == nil {
		return
	}
	name := ns.Name
	actor, err := s.requireVaultAdmin(w, r, ns.ID)
	if err != nil {
		return
	}

	skillName := r.PathValue("skill")
	var req struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		Content     *string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Name == nil && req.Description == nil && req.Content == nil {
		jsonError(w, http.StatusBadRequest, "At least one field is required (name, description, content)")
		return
	}

	unlock, err := s.lockVault(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "lock failed")
		return
	}
	defer unlock()

	existing, err := s.store.GetSkill(ctx, ns.ID, skillName)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Skill %q not found", skillName))
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to load skill")
		return
	}

	merged := *existing
	if req.Name != nil {
		merged.Name = strings.TrimSpace(*req.Name)
	}
	if req.Description != nil {
		merged.Description = strings.TrimSpace(*req.Description)
	}
	if req.Content != nil {
		merged.Content = normalizeSkillContent(*req.Content)
	}
	if err := validateSkillPayload(merged.Name, merged.Description, merged.Content); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	updated, err := s.store.UpdateSkill(ctx, ns.ID, skillName, merged)
	if errors.Is(err, store.ErrSkillExists) {
		jsonError(w, http.StatusConflict, fmt.Sprintf("A skill named %q already exists", merged.Name))
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Skill %q not found", skillName))
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to update skill")
		return
	}

	s.captureEvent(r, "av.skill-update", actor, map[string]string{"vault": name})
	jsonOK(w, map[string]interface{}{"vault": name, "skill": skillToResponse(updated)})
}

// handleSkillDelete removes a skill from the vault. Vault admin only.
func (s *Server) handleSkillDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ns := s.resolveVaultByPath(w, r)
	if ns == nil {
		return
	}
	name := ns.Name
	actor, err := s.requireVaultAdmin(w, r, ns.ID)
	if err != nil {
		return
	}

	skillName := r.PathValue("skill")

	// Single atomic DELETE; no vault lock needed (see handleSkillCreate).
	err = s.store.DeleteSkill(ctx, ns.ID, skillName)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Skill %q not found", skillName))
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to delete skill")
		return
	}

	s.captureEvent(r, "av.skill-remove", actor, map[string]string{"vault": name})
	jsonOK(w, map[string]interface{}{"vault": name, "removed": skillName})
}
