package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/store"
)

// skillReq issues an authenticated request against the skills API.
func skillReq(t *testing.T, srv *Server, token, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, r)
	return rec
}

// setupSkillsServer returns a server whose session actor is vault admin on
// `default`, plus that session token.
func setupSkillsServer(t *testing.T) (*mockStore, *Server, string) {
	t.Helper()
	ms, token := setupMockStoreWithSession(t)
	return ms, newTestServer(withStore(ms)), token
}

func TestSkillCreateAndList(t *testing.T) {
	ms, srv, token := setupSkillsServer(t)

	body := `{"name":"deploy-staging","description":"How to deploy","content":"# Deploy\n\nRun tests first.\n"}`
	rec := skillReq(t, srv, token, http.MethodPost, "/v1/vaults/default/skills", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// The skill actually landed in the store.
	stored, ok := ms.skills["root-ns-id"]["deploy-staging"]
	if !ok {
		t.Fatal("skill was not stored")
	}
	if stored.Content != "# Deploy\n\nRun tests first.\n" {
		t.Fatalf("stored content = %q", stored.Content)
	}

	rec = skillReq(t, srv, token, http.MethodGet, "/v1/vaults/default/skills", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// The list must not carry markdown bodies. Assert on the raw JSON so a
	// future refactor that adds `content` back to the list shape fails here.
	var raw struct {
		Vault  string                       `json:"vault"`
		Skills []map[string]json.RawMessage `json:"skills"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if raw.Vault != "default" {
		t.Fatalf("vault = %q", raw.Vault)
	}
	if len(raw.Skills) != 1 {
		t.Fatalf("expected 1 skill, got %d", len(raw.Skills))
	}
	if _, present := raw.Skills[0]["content"]; present {
		t.Fatal("list response leaked the markdown body")
	}
	for _, field := range []string{"name", "description", "created_at", "updated_at"} {
		if _, present := raw.Skills[0][field]; !present {
			t.Fatalf("list response missing %q", field)
		}
	}
}

func TestSkillListEmptyIsArrayNotNull(t *testing.T) {
	_, srv, token := setupSkillsServer(t)

	rec := skillReq(t, srv, token, http.MethodGet, "/v1/vaults/default/skills", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	// A null would break `data.skills.map(...)` in the dashboard.
	if !strings.Contains(rec.Body.String(), `"skills":[]`) {
		t.Fatalf("expected an empty array, got %s", rec.Body.String())
	}
}

func TestSkillGetReturnsContent(t *testing.T) {
	ms, srv, token := setupSkillsServer(t)
	seedSkill(t, ms, "audit-logs", "Read the logs", "# Audit\n\nbody\n")

	rec := skillReq(t, srv, token, http.MethodGet, "/v1/vaults/default/skills/audit-logs", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Skill skillResponse `json:"skill"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Skill.Content != "# Audit\n\nbody\n" {
		t.Fatalf("content = %q", resp.Skill.Content)
	}
	if resp.Skill.Description != "Read the logs" {
		t.Fatalf("description = %q", resp.Skill.Description)
	}
}

func TestSkillGetNotFound(t *testing.T) {
	_, srv, token := setupSkillsServer(t)

	rec := skillReq(t, srv, token, http.MethodGet, "/v1/vaults/default/skills/nope-skill", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSkillCreateRejectsInvalidPayloads(t *testing.T) {
	cases := []struct {
		label string
		body  string
	}{
		{"uppercase name", `{"name":"DeployStaging","content":"x"}`},
		{"too short name", `{"name":"ab","content":"x"}`},
		{"leading hyphen", `{"name":"-deploy","content":"x"}`},
		{"doubled hyphen", `{"name":"de--ploy","content":"x"}`},
		{"empty name", `{"name":"","content":"x"}`},
		{"empty content", `{"name":"deploy-staging","content":""}`},
		{"whitespace-only content", `{"name":"deploy-staging","content":"   \n  "}`},
		{"nul byte in content", `{"name":"deploy-staging","content":"a\u0000b"}`},
		{"nul byte in description", `{"name":"deploy-staging","description":"a\u0000b","content":"x"}`},
	}
	// All nine are rejected in validateSkillPayload before any store access,
	// so one server serves every case.
	_, srv, token := setupSkillsServer(t)
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			rec := skillReq(t, srv, token, http.MethodPost, "/v1/vaults/default/skills", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestSkillCreateRejectsOversizedContent(t *testing.T) {
	_, srv, token := setupSkillsServer(t)

	oversized := strings.Repeat("a", maxSkillContentChars+1)
	body, _ := json.Marshal(map[string]string{"name": "big-skill", "content": oversized})
	rec := skillReq(t, srv, token, http.MethodPost, "/v1/vaults/default/skills", string(body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	// The message must name the limit, not fall through to the generic
	// decode error that limitBody's MaxBytesReader would produce.
	if !strings.Contains(rec.Body.String(), "at most") {
		t.Fatalf("expected a limit message, got %s", rec.Body.String())
	}
}

// The cap counts characters, not bytes, so a multi-byte body is accepted
// right up to the same character count an ASCII body would be.
func TestSkillContentLimitCountsCharactersNotBytes(t *testing.T) {
	_, srv, token := setupSkillsServer(t)

	// 3 bytes per rune: ~300 KB of UTF-8, which a 256 KiB byte cap would
	// have rejected. Still under the 1 MB request ceiling.
	atLimit := strings.Repeat("日", maxSkillContentChars)
	body, _ := json.Marshal(map[string]string{"name": "cjk-skill", "content": atLimit})
	rec := skillReq(t, srv, token, http.MethodPost, "/v1/vaults/default/skills", string(body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 for %d chars (%d bytes), got %d: %s",
			maxSkillContentChars, len(atLimit), rec.Code, rec.Body.String())
	}

	// One character over is rejected, whatever the script.
	overBody, _ := json.Marshal(map[string]string{
		"name":    "cjk-over",
		"content": strings.Repeat("日", maxSkillContentChars+1),
	})
	rec = skillReq(t, srv, token, http.MethodPost, "/v1/vaults/default/skills", string(overBody))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 one char over, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSkillCreateRejectsOversizedDescription(t *testing.T) {
	_, srv, token := setupSkillsServer(t)

	body, _ := json.Marshal(map[string]string{
		"name":        "big-desc",
		"description": strings.Repeat("d", maxSkillDescriptionChars+1),
		"content":     "x",
	})
	rec := skillReq(t, srv, token, http.MethodPost, "/v1/vaults/default/skills", string(body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// The name and description caps track the Agent Skills frontmatter limits, so
// a skill authored here is still valid once `vault run` writes it as SKILL.md.
func TestSkillFieldLimitsMatchAgentSkillsSpec(t *testing.T) {
	const (
		specNameChars        = 64
		specDescriptionChars = 1024
	)
	if maxSkillDescriptionChars != specDescriptionChars {
		t.Errorf("description cap = %d, want the spec's %d", maxSkillDescriptionChars, specDescriptionChars)
	}
	// The name cap comes from broker.ValidateSlug rather than a local const.
	if err := broker.ValidateSlug(strings.Repeat("a", specNameChars)); err != nil {
		t.Errorf("a %d-character name should be valid: %v", specNameChars, err)
	}
	if err := broker.ValidateSlug(strings.Repeat("a", specNameChars+1)); err == nil {
		t.Errorf("a %d-character name should be rejected", specNameChars+1)
	}

	// And the boundaries hold over HTTP, counted in characters not bytes.
	_, srv, token := setupSkillsServer(t)
	for _, tc := range []struct {
		label string
		name  string
		chars int
		want  int
	}{
		{"description at limit", "spec-at-limit", specDescriptionChars, http.StatusCreated},
		{"description one over", "spec-over-limit", specDescriptionChars + 1, http.StatusBadRequest},
	} {
		// Multi-byte runes: a byte-based cap would reject both.
		body, _ := json.Marshal(map[string]string{
			"name":        tc.name,
			"description": strings.Repeat("é", tc.chars),
			"content":     "# body\n",
		})
		rec := skillReq(t, srv, token, http.MethodPost, "/v1/vaults/default/skills", string(body))
		if rec.Code != tc.want {
			t.Errorf("%s (%d chars): expected %d, got %d: %s",
				tc.label, tc.chars, tc.want, rec.Code, rec.Body.String())
		}
	}
}

// The description is emitted as one YAML scalar in SKILL.md frontmatter, so
// newlines must not survive into storage.
func TestSkillDescriptionIsFlattenedToOneLine(t *testing.T) {
	ms, srv, token := setupSkillsServer(t)

	body, _ := json.Marshal(map[string]string{
		"name":        "multiline-desc",
		"description": "  first line\nsecond   line\r\nthird\t line  ",
		"content":     "# body\n",
	})
	rec := skillReq(t, srv, token, http.MethodPost, "/v1/vaults/default/skills", string(body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	got := ms.skills["root-ns-id"]["multiline-desc"].Description
	if want := "first line second line third line"; got != want {
		t.Fatalf("description = %q, want %q", got, want)
	}
	if strings.ContainsAny(got, "\n\r\t") {
		t.Fatalf("description still carries line breaks: %q", got)
	}

	// The same normalization applies on the patch path.
	patch, _ := json.Marshal(map[string]string{"description": "one\ntwo"})
	rec = skillReq(t, srv, token, http.MethodPatch, "/v1/vaults/default/skills/multiline-desc", string(patch))
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := ms.skills["root-ns-id"]["multiline-desc"].Description; got != "one two" {
		t.Fatalf("patched description = %q, want %q", got, "one two")
	}
}

func TestSkillCreateNormalizesCRLF(t *testing.T) {
	ms, srv, token := setupSkillsServer(t)

	body, _ := json.Marshal(map[string]string{"name": "crlf-skill", "content": "line one\r\nline two\r\n"})
	rec := skillReq(t, srv, token, http.MethodPost, "/v1/vaults/default/skills", string(body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	got := ms.skills["root-ns-id"]["crlf-skill"].Content
	if strings.Contains(got, "\r") {
		t.Fatalf("CRLF survived normalization: %q", got)
	}
	if got != "line one\nline two\n" {
		t.Fatalf("content = %q", got)
	}
}

func TestSkillCreateDuplicate(t *testing.T) {
	ms, srv, token := setupSkillsServer(t)
	seedSkill(t, ms, "dup-skill", "", "a")

	rec := skillReq(t, srv, token, http.MethodPost, "/v1/vaults/default/skills",
		`{"name":"dup-skill","content":"b"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSkillPatchUpdatesFields(t *testing.T) {
	ms, srv, token := setupSkillsServer(t)
	seedSkill(t, ms, "patch-skill", "old desc", "old body")

	rec := skillReq(t, srv, token, http.MethodPatch, "/v1/vaults/default/skills/patch-skill",
		`{"description":"new desc"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	stored := ms.skills["root-ns-id"]["patch-skill"]
	if stored.Description != "new desc" {
		t.Fatalf("description = %q", stored.Description)
	}
	// An omitted field must be left alone, not blanked.
	if stored.Content != "old body" {
		t.Fatalf("omitted content field was overwritten: %q", stored.Content)
	}
}

func TestSkillPatchRenameSucceeds(t *testing.T) {
	ms, srv, token := setupSkillsServer(t)
	seedSkill(t, ms, "old-name", "d", "body")

	rec := skillReq(t, srv, token, http.MethodPatch, "/v1/vaults/default/skills/old-name",
		`{"name":"new-name"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, stillThere := ms.skills["root-ns-id"]["old-name"]; stillThere {
		t.Fatal("old name still present after rename")
	}
	moved, ok := ms.skills["root-ns-id"]["new-name"]
	if !ok {
		t.Fatal("renamed skill missing")
	}
	if moved.Content != "body" {
		t.Fatalf("rename lost the body: %q", moved.Content)
	}
}

func TestSkillPatchRenameCollision(t *testing.T) {
	ms, srv, token := setupSkillsServer(t)
	seedSkill(t, ms, "first-skill", "", "a")
	seedSkill(t, ms, "second-skill", "", "b")

	rec := skillReq(t, srv, token, http.MethodPatch, "/v1/vaults/default/skills/first-skill",
		`{"name":"second-skill"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
	if ms.skills["root-ns-id"]["second-skill"].Content != "b" {
		t.Fatal("collision clobbered the target skill")
	}
}

func TestSkillPatchNoFields(t *testing.T) {
	ms, srv, token := setupSkillsServer(t)
	seedSkill(t, ms, "patch-skill", "", "a")

	rec := skillReq(t, srv, token, http.MethodPatch, "/v1/vaults/default/skills/patch-skill", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSkillPatchRejectsInvalidMergedName(t *testing.T) {
	ms, srv, token := setupSkillsServer(t)
	seedSkill(t, ms, "patch-skill", "", "a")

	rec := skillReq(t, srv, token, http.MethodPatch, "/v1/vaults/default/skills/patch-skill",
		`{"name":"Bad Name"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSkillPatchNotFound(t *testing.T) {
	_, srv, token := setupSkillsServer(t)

	rec := skillReq(t, srv, token, http.MethodPatch, "/v1/vaults/default/skills/nope-skill",
		`{"description":"x"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSkillDelete(t *testing.T) {
	ms, srv, token := setupSkillsServer(t)
	seedSkill(t, ms, "gone-skill", "", "a")

	rec := skillReq(t, srv, token, http.MethodDelete, "/v1/vaults/default/skills/gone-skill", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, stillThere := ms.skills["root-ns-id"]["gone-skill"]; stillThere {
		t.Fatal("skill was not deleted")
	}

	rec = skillReq(t, srv, token, http.MethodDelete, "/v1/vaults/default/skills/gone-skill", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on second delete, got %d", rec.Code)
	}
}

// TestSkillMutationsRequireVaultAdmin is the core permission guard: member
// and proxy roles read but cannot mutate.
func TestSkillMutationsRequireVaultAdmin(t *testing.T) {
	for _, role := range []string{"member", "proxy"} {
		t.Run(role, func(t *testing.T) {
			ms := newMockStore()
			ms.users["actor@test.com"] = &store.User{
				ID: "actor-user-id", Email: "actor@test.com",
				Role: "member", IsActive: true,
			}
			ms.GrantVaultRole(context.Background(), "actor-user-id", "user", "root-ns-id", role)
			sess, err := ms.CreateSession(context.Background(), "actor-user-id", time.Now().Add(time.Hour))
			if err != nil {
				t.Fatalf("CreateSession: %v", err)
			}
			srv := newTestServer(withStore(ms))
			seedSkill(t, ms, "read-me", "desc", "body")

			// Reads succeed at every role, including proxy — an agent's own
			// token must be able to pull the skills it should follow.
			if rec := skillReq(t, srv, sess.ID, http.MethodGet, "/v1/vaults/default/skills", ""); rec.Code != http.StatusOK {
				t.Fatalf("list: expected 200, got %d: %s", rec.Code, rec.Body.String())
			}
			if rec := skillReq(t, srv, sess.ID, http.MethodGet, "/v1/vaults/default/skills/read-me", ""); rec.Code != http.StatusOK {
				t.Fatalf("get: expected 200, got %d: %s", rec.Code, rec.Body.String())
			}

			// Mutations are refused.
			mutations := []struct {
				method, path, body string
			}{
				{http.MethodPost, "/v1/vaults/default/skills", `{"name":"new-skill","content":"x"}`},
				{http.MethodPatch, "/v1/vaults/default/skills/read-me", `{"description":"x"}`},
				{http.MethodDelete, "/v1/vaults/default/skills/read-me", ""},
			}
			for _, m := range mutations {
				rec := skillReq(t, srv, sess.ID, m.method, m.path, m.body)
				if rec.Code != http.StatusForbidden {
					t.Fatalf("%s %s: expected 403, got %d: %s", m.method, m.path, rec.Code, rec.Body.String())
				}
			}
			// Nothing was written.
			if len(ms.skills["root-ns-id"]) != 1 {
				t.Fatalf("expected the store untouched, got %d skills", len(ms.skills["root-ns-id"]))
			}
		})
	}
}

func TestSkillsUnknownVault(t *testing.T) {
	_, srv, token := setupSkillsServer(t)

	for _, path := range []string{"/v1/vaults/nope/skills", "/v1/vaults/nope/skills/some-skill"} {
		rec := skillReq(t, srv, token, http.MethodGet, path, "")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: expected 404, got %d: %s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestSkillsRequireAuth(t *testing.T) {
	_, srv, _ := setupSkillsServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/vaults/default/skills", nil)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without a token, got %d: %s", rec.Code, rec.Body.String())
	}
}

// seedSkill inserts a skill directly into the mock store.
func seedSkill(t *testing.T, ms *mockStore, name, description, content string) {
	t.Helper()
	if _, err := ms.InsertSkill(context.Background(), store.Skill{
		VaultID:     "root-ns-id",
		Name:        name,
		Description: description,
		Content:     content,
	}); err != nil {
		t.Fatalf("seedSkill(%s): %v", name, err)
	}
}
