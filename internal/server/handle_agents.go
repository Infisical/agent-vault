package server

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/store"
)

//go:embed persistent_instructions_admin.txt
var persistentInstructionsAdmin string

// reservedVaultNames are names that conflict with /vaults/* frontend routes.
// Keep in sync with vaultsLayoutRoute children in web/src/router.tsx.
var reservedVaultNames = map[string]struct{}{
	"users": {},
}

func isReservedVaultName(name string) bool {
	_, ok := reservedVaultNames[name]
	return ok
}

// handleAgentCreate creates a new instance-level agent and returns its token directly.
// Replaces the old invite-create + redeem ceremony.
func (s *Server) handleAgentCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	type vaultReq struct {
		VaultName string `json:"vault_name"`
		VaultRole string `json:"vault_role"`
	}
	var req struct {
		Name              string     `json:"name"`
		Role              string     `json:"role"` // instance-level role: "owner", "member", or "no-access" (default: "member")
		SessionTTLSeconds *int       `json:"session_ttl_seconds,omitempty"`
		Vaults            []vaultReq `json:"vaults"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Name == "" {
		jsonError(w, http.StatusBadRequest, "Agent name is required")
		return
	}
	if err := broker.ValidateSlug(req.Name); err != nil {
		jsonError(w, http.StatusBadRequest, "Agent name must be 3-64 characters, lowercase alphanumeric and hyphens only")
		return
	}

	// Cap finite session TTL.
	if req.SessionTTLSeconds != nil && *req.SessionTTLSeconds > 0 {
		minSecs := int(scopedSessionMinTTL.Seconds())
		maxSecs := int(scopedSessionMaxTTL.Seconds())
		ttl := *req.SessionTTLSeconds
		if ttl < minSecs {
			ttl = minSecs
		} else if ttl > maxSecs {
			ttl = maxSecs
		}
		req.SessionTTLSeconds = &ttl
	}

	actor, err := s.requireInstanceMember(w, r)
	if err != nil {
		return
	}

	if existing, _ := s.store.GetAgentByName(ctx, req.Name); existing != nil {
		jsonError(w, http.StatusConflict, fmt.Sprintf("An agent named %q already exists", req.Name))
		return
	}

	// Validate and resolve vault pre-assignments.
	type resolvedVault struct {
		VaultID   string
		VaultName string
		VaultRole string
	}
	var vaultGrants []resolvedVault
	for _, v := range req.Vaults {
		if v.VaultRole == "" {
			v.VaultRole = "proxy"
		}
		if v.VaultRole != "proxy" && v.VaultRole != "member" && v.VaultRole != "admin" {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid vault role %q for vault %q", v.VaultRole, v.VaultName))
			return
		}
		ns, err := s.store.GetVault(ctx, v.VaultName)
		if err != nil || ns == nil {
			jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", v.VaultName))
			return
		}
		// Caller must be admin of the vault (or instance owner).
		if !actor.IsOwner() {
			role, err := s.store.GetVaultRole(ctx, actor.ID, ns.ID)
			if err != nil || role != "admin" {
				jsonError(w, http.StatusForbidden, fmt.Sprintf("You must be an admin of vault %q to assign it", v.VaultName))
				return
			}
		}
		vaultGrants = append(vaultGrants, resolvedVault{
			VaultID:   ns.ID,
			VaultName: v.VaultName,
			VaultRole: v.VaultRole,
		})
	}

	// Validate and default agent instance role.
	agentRole := req.Role
	if agentRole == "" {
		agentRole = "member"
	}
	if !validInstanceRole(agentRole) {
		jsonError(w, http.StatusBadRequest, "Role must be one of: owner, member, no-access")
		return
	}
	if agentRole == "owner" && !actor.IsOwner() {
		jsonError(w, http.StatusForbidden, "Only owners can create owner-role agents")
		return
	}

	agent, err := s.store.CreateAgent(ctx, req.Name, actor.ID, agentRole)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			jsonError(w, http.StatusConflict, fmt.Sprintf("An agent named %q already exists", req.Name))
			return
		}
		fmt.Fprintf(os.Stderr, "[agent-vault] ERROR: CreateAgent(%q): %v\n", req.Name, err)
		jsonError(w, http.StatusInternalServerError, "Failed to create agent")
		return
	}

	vaultInfos := make([]agentVaultJSON, 0, len(vaultGrants))
	for _, v := range vaultGrants {
		if err := s.store.GrantVaultRole(ctx, agent.ID, "agent", v.VaultID, v.VaultRole); err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to grant vault access")
			return
		}
		vaultInfos = append(vaultInfos, agentVaultJSON{VaultName: v.VaultName, VaultRole: v.VaultRole})
	}

	var tokenExpiry *time.Time
	if req.SessionTTLSeconds != nil && *req.SessionTTLSeconds > 0 {
		tokenExpiry = timePtr(time.Now().Add(time.Duration(*req.SessionTTLSeconds) * time.Second))
	}
	sess, err := s.store.CreateAgentToken(ctx, agent.ID, tokenExpiry)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create agent token")
		return
	}

	jsonCreated(w, map[string]interface{}{
		"av_addr":        s.baseURL,
		"av_agent_token": sess.ID,
		"name":           agent.Name,
		"role":           agent.Role,
		"vaults":         vaultInfos,
		"created_at":     agent.CreatedAt.Format(time.RFC3339),
		"instructions":   persistentInstructionsAdmin,
	})
}

func (s *Server) handleAgentList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Owners see all agents; members see agents that share at least one vault.
	// no-access actors are blocked — the agent directory is instance-scoped.
	actor, err := s.requireInstanceMember(w, r)
	if err != nil {
		return
	}

	agents, agentErr := s.store.ListAllAgents(ctx)
	if agentErr != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list agents")
		return
	}

	// For non-owner actors, filter to agents sharing at least one vault.
	if !actor.IsOwner() {
		grants, _ := s.store.ListActorGrants(ctx, actor.ID)
		accessibleVaults := make(map[string]bool, len(grants))
		for _, g := range grants {
			accessibleVaults[g.VaultID] = true
		}
		var filtered []store.Agent
		for _, ag := range agents {
			for _, v := range ag.Vaults {
				if accessibleVaults[v.VaultID] {
					filtered = append(filtered, ag)
					break
				}
			}
		}
		agents = filtered
	}

	type agentItem struct {
		Name           string           `json:"name"`
		Role           string           `json:"role"`
		Status         string           `json:"status"`
		Vaults         []agentVaultJSON `json:"vaults"`
		CreatedAt      string           `json:"created_at"`
		RevokedAt      *string          `json:"revoked_at,omitempty"`
		TokenExpiresAt *string          `json:"token_expires_at,omitempty"`
	}

	items := make([]agentItem, 0, len(agents))
	for _, ag := range agents {
		vaults := make([]agentVaultJSON, 0, len(ag.Vaults))
		for _, v := range ag.Vaults {
			vaults = append(vaults, agentVaultJSON{VaultName: v.VaultName, VaultRole: v.Role})
		}
		item := agentItem{
			Name:      ag.Name,
			Role:      ag.Role,
			Status:    ag.Status,
			Vaults:    vaults,
			CreatedAt: ag.CreatedAt.Format(time.RFC3339),
		}
		if ag.RevokedAt != nil {
			s := ag.RevokedAt.Format(time.RFC3339)
			item.RevokedAt = &s
		}
		if ag.Status == "active" {
			if expiry, err := s.store.GetLatestAgentTokenExpiry(ctx, ag.ID); err == nil && expiry != nil {
				e := expiry.Format(time.RFC3339)
				item.TokenExpiresAt = &e
			}
		}
		items = append(items, item)
	}

	jsonOK(w, map[string]interface{}{"agents": items})
}

func (s *Server) handleAgentGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	if _, err := s.requireInstanceMember(w, r); err != nil {
		return
	}

	agent, err := s.store.GetAgentByName(ctx, name)
	if err != nil {
		jsonError(w, http.StatusNotFound, "Agent not found")
		return
	}

	vaults := make([]agentVaultJSON, 0, len(agent.Vaults))
	for _, v := range agent.Vaults {
		vaults = append(vaults, agentVaultJSON{VaultName: v.VaultName, VaultRole: v.Role})
	}

	resp := map[string]interface{}{
		"name":       agent.Name,
		"role":       agent.Role,
		"status":     agent.Status,
		"vaults":     vaults,
		"created_by": agent.CreatedBy,
		"created_at": agent.CreatedAt.Format(time.RFC3339),
		"updated_at": agent.UpdatedAt.Format(time.RFC3339),
	}
	if agent.RevokedAt != nil {
		resp["revoked_at"] = agent.RevokedAt.Format(time.RFC3339)
	}

	tokenCount, _ := s.store.CountAgentTokens(ctx, agent.ID)
	resp["active_tokens"] = tokenCount
	if expiry, err := s.store.GetLatestAgentTokenExpiry(ctx, agent.ID); err == nil && expiry != nil {
		resp["token_expires_at"] = expiry.Format(time.RFC3339)
	}

	jsonOK(w, resp)
}

func (s *Server) handleAgentRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	actor, err := s.requireInstanceMember(w, r)
	if err != nil {
		return
	}

	agent, err := s.store.GetAgentByName(ctx, name)
	if err != nil {
		jsonError(w, http.StatusNotFound, "Agent not found")
		return
	}

	if !actor.IsOwner() && agent.CreatedBy != actor.ID {
		jsonError(w, http.StatusForbidden, "Only the owner or agent creator can revoke agents")
		return
	}
	if agent.Status != "active" {
		jsonError(w, http.StatusConflict, "Agent is already revoked")
		return
	}

	if agent.Role == "owner" && s.guardLastOwner(ctx, w, "revoke") {
		return
	}

	if err := s.store.RevokeAgent(ctx, agent.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to revoke agent")
		return
	}

	jsonOK(w, map[string]string{"message": fmt.Sprintf("agent %q revoked", name)})
}

// handleAgentRotate invalidates the agent's existing tokens and mints a new one.
func (s *Server) handleAgentRotate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	actor, err := s.requireInstanceMember(w, r)
	if err != nil {
		return
	}

	agent, err := s.store.GetAgentByName(ctx, name)
	if err != nil {
		jsonError(w, http.StatusNotFound, "Agent not found")
		return
	}

	if !actor.IsOwner() && agent.CreatedBy != actor.ID {
		jsonError(w, http.StatusForbidden, "Only the owner or agent creator can rotate agents")
		return
	}
	if agent.Status != "active" {
		jsonError(w, http.StatusConflict, "Agent is revoked — cannot rotate")
		return
	}

	if err := s.store.DeleteAgentTokens(ctx, agent.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to invalidate old agent tokens")
		return
	}

	sess, err := s.store.CreateAgentToken(ctx, agent.ID, nil)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create agent token")
		return
	}

	jsonOK(w, map[string]interface{}{
		"av_agent_token": sess.ID,
		"name":           agent.Name,
		"rotated_at":     time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleAgentRename(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	actor, err := s.requireInstanceMember(w, r)
	if err != nil {
		return
	}

	agent, err := s.store.GetAgentByName(ctx, name)
	if err != nil {
		jsonError(w, http.StatusNotFound, "Agent not found")
		return
	}

	if !actor.IsOwner() && agent.CreatedBy != actor.ID {
		jsonError(w, http.StatusForbidden, "Only the owner or agent creator can rename agents")
		return
	}

	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		jsonError(w, http.StatusBadRequest, "Request body must include {\"name\": \"new-name\"}")
		return
	}
	if err := broker.ValidateSlug(body.Name); err != nil {
		jsonError(w, http.StatusBadRequest, "Agent name must be 3-64 characters, lowercase alphanumeric and hyphens only")
		return
	}

	existing, _ := s.store.GetAgentByName(ctx, body.Name)
	if existing != nil {
		jsonError(w, http.StatusConflict, fmt.Sprintf("An agent named %q already exists", body.Name))
		return
	}

	if err := s.store.RenameAgent(ctx, agent.ID, body.Name); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to rename agent")
		return
	}

	jsonOK(w, map[string]string{
		"message":  fmt.Sprintf("agent renamed from %q to %q", name, body.Name),
		"old_name": name,
		"new_name": body.Name,
	})
}

func (s *Server) handleVaultAgentList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	nsName := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, nsName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", nsName))
		return
	}

	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	agents, err := s.store.ListAgents(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list vault agents")
		return
	}

	type item struct {
		Name      string `json:"name"`
		AgentID   string `json:"agent_id"`
		VaultRole string `json:"vault_role"`
		Status    string `json:"status"`
	}
	items := make([]item, 0, len(agents))
	for _, ag := range agents {
		var role string
		for _, v := range ag.Vaults {
			if v.VaultID == ns.ID {
				role = v.Role
				break
			}
		}
		items = append(items, item{
			Name:      ag.Name,
			AgentID:   ag.ID,
			VaultRole: role,
			Status:    ag.Status,
		})
	}

	jsonOK(w, map[string]interface{}{"agents": items})
}

func (s *Server) handleVaultAgentAdd(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	nsName := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, nsName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", nsName))
		return
	}

	if _, err := s.requireVaultAdmin(w, r, ns.ID); err != nil {
		return
	}

	var body struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		jsonError(w, http.StatusBadRequest, `Request body must include {"name": "agent-name"}`)
		return
	}
	if body.Role == "" {
		body.Role = "proxy"
	}
	if body.Role != "proxy" && body.Role != "member" && body.Role != "admin" {
		jsonError(w, http.StatusBadRequest, "Role must be one of: proxy, member, admin")
		return
	}

	agent, err := s.store.GetAgentByName(ctx, body.Name)
	if err != nil || agent == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Agent %q not found", body.Name))
		return
	}
	if agent.Status != "active" {
		jsonError(w, http.StatusConflict, "Agent is revoked")
		return
	}

	if has, _ := s.store.HasVaultAccess(ctx, agent.ID, ns.ID); has {
		jsonError(w, http.StatusConflict, fmt.Sprintf("Agent %q already has access to vault %q", body.Name, nsName))
		return
	}

	if err := s.store.GrantVaultRole(ctx, agent.ID, "agent", ns.ID, body.Role); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to add agent to vault")
		return
	}

	jsonCreated(w, map[string]string{
		"message": fmt.Sprintf("agent %q added to vault %q with role %q", body.Name, nsName, body.Role),
	})
}

func (s *Server) handleVaultAgentRemove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	nsName := r.PathValue("name")
	agentName := r.PathValue("agentName")

	ns, err := s.store.GetVault(ctx, nsName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", nsName))
		return
	}

	if _, err := s.requireVaultAdmin(w, r, ns.ID); err != nil {
		return
	}

	agent, err := s.store.GetAgentByName(ctx, agentName)
	if err != nil || agent == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Agent %q not found", agentName))
		return
	}

	if err := s.store.RevokeVaultAccess(ctx, agent.ID, ns.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to remove agent from vault")
		return
	}

	jsonOK(w, map[string]string{
		"message": fmt.Sprintf("agent %q removed from vault %q", agentName, nsName),
	})
}

func (s *Server) handleVaultAgentSetRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	nsName := r.PathValue("name")
	agentName := r.PathValue("agentName")

	ns, err := s.store.GetVault(ctx, nsName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", nsName))
		return
	}

	if _, err := s.requireVaultAdmin(w, r, ns.ID); err != nil {
		return
	}

	var body struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Role == "" {
		jsonError(w, http.StatusBadRequest, `Request body must include {"role": "proxy|member|admin"}`)
		return
	}
	if body.Role != "proxy" && body.Role != "member" && body.Role != "admin" {
		jsonError(w, http.StatusBadRequest, "Role must be one of: proxy, member, admin")
		return
	}

	agent, err := s.store.GetAgentByName(ctx, agentName)
	if err != nil || agent == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Agent %q not found", agentName))
		return
	}

	oldRole, err := s.store.GetVaultRole(ctx, agent.ID, ns.ID)
	if err != nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Agent %q does not have access to vault %q", agentName, nsName))
		return
	}

	if err := s.store.GrantVaultRole(ctx, agent.ID, "agent", ns.ID, body.Role); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to update agent role")
		return
	}

	jsonOK(w, map[string]string{
		"message":  fmt.Sprintf("agent %q role in vault %q updated to %q", agentName, nsName, body.Role),
		"old_role": oldRole,
		"new_role": body.Role,
	})
}

// handleAgentSetRole changes an agent's instance-level role (owner/member/no-access).
func (s *Server) handleAgentSetRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	if _, err := s.requireOwnerActor(w, r); err != nil {
		return
	}

	var body struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Role == "" {
		jsonError(w, http.StatusBadRequest, `Request body must include {"role": "owner|member|no-access"}`)
		return
	}
	if !validInstanceRole(body.Role) {
		jsonError(w, http.StatusBadRequest, "Role must be one of: owner, member, no-access")
		return
	}

	agent, err := s.store.GetAgentByName(ctx, name)
	if err != nil || agent == nil {
		jsonError(w, http.StatusNotFound, "Agent not found")
		return
	}
	if agent.Status != "active" {
		jsonError(w, http.StatusConflict, "Agent is revoked")
		return
	}

	if agent.Role == "owner" && body.Role != "owner" && s.guardLastOwner(ctx, w, "demote") {
		return
	}

	if err := s.store.UpdateAgentRole(ctx, agent.ID, body.Role); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to update agent role")
		return
	}

	jsonOK(w, map[string]string{
		"agent":    name,
		"old_role": agent.Role,
		"new_role": body.Role,
	})
}
