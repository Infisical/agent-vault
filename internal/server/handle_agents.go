package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/store"
)

// reservedVaultNames are names that conflict with /vaults/* frontend routes.
// Keep in sync with vaultsLayoutRoute children in web/src/router.tsx.
var reservedVaultNames = map[string]struct{}{
	"users": {},
}

func isReservedVaultName(name string) bool {
	_, ok := reservedVaultNames[name]
	return ok
}

// validVaultRole reports whether s is a recognized vault role.
func validVaultRole(s string) bool {
	return s == "proxy" || s == "member" || s == "admin"
}

func (s *Server) handleAgentCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	actor, err := s.requireInstanceMember(w, r)
	if err != nil {
		return
	}

	type vaultReq struct {
		VaultName string `json:"vault_name"`
		VaultRole string `json:"vault_role"`
	}
	var req struct {
		Name   string     `json:"name"`
		Role   string     `json:"role"` // instance-level role: "owner", "member", or "no-access" (default: "no-access")
		Vaults []vaultReq `json:"vaults"`
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
		if !validVaultRole(v.VaultRole) {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid vault role %q for vault %q", v.VaultRole, v.VaultName))
			return
		}
		ns, err := s.store.GetVault(ctx, v.VaultName)
		if err != nil || ns == nil {
			jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", v.VaultName))
			return
		}
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

	agentRole := req.Role
	if agentRole == "" {
		agentRole = "no-access"
	}
	if !validInstanceRole(agentRole) {
		jsonError(w, http.StatusBadRequest, "Role must be one of: owner, member, no-access")
		return
	}
	if agentRole == "owner" && !actor.IsOwner() {
		jsonError(w, http.StatusForbidden, "Only owners can create owner-role agents")
		return
	}

	grantSpecs := make([]store.AgentVaultGrantSpec, 0, len(vaultGrants))
	vaultInfos := make([]agentVaultJSON, 0, len(vaultGrants))
	for _, v := range vaultGrants {
		grantSpecs = append(grantSpecs, store.AgentVaultGrantSpec{VaultID: v.VaultID, Role: v.VaultRole})
		vaultInfos = append(vaultInfos, agentVaultJSON{VaultName: v.VaultName, VaultRole: v.VaultRole})
	}
	agent, sess, err := s.store.CreateAgentWithGrantsAndToken(ctx, req.Name, actor.ID, agentRole, grantSpecs, nil)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			jsonError(w, http.StatusConflict, fmt.Sprintf("An agent named %q already exists", req.Name))
			return
		}
		fmt.Fprintf(os.Stderr, "[agent-vault] ERROR: CreateAgentWithGrantsAndToken(%q): %v\n", req.Name, err)
		jsonError(w, http.StatusInternalServerError, "Failed to create agent")
		return
	}

	s.captureEvent(r, "av.agent-create", actor, map[string]string{"agent_name": agent.Name})
	jsonCreated(w, map[string]interface{}{
		"av_agent_token": sess.ID,
		"name":           agent.Name,
		"role":           agent.Role,
		"vaults":         vaultInfos,
		"created_at":     agent.CreatedAt.Format(time.RFC3339),
	})
}

func (s *Server) handleAgentList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	actor, err := s.requireInstanceMember(w, r)
	if err != nil {
		return
	}

	agents, agentErr := s.store.ListAllAgents(ctx)
	if agentErr != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list agents")
		return
	}

	if !actor.IsOwner() {
		accessible, accErr := s.actorAccessibleVaultIDs(ctx, actor.ID)
		if accErr != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to list agents")
			return
		}
		var filtered []store.Agent
		for i := range agents {
			if agentDirectoryRowVisibleToNonOwner(&agents[i], actor, accessible) {
				filtered = append(filtered, agents[i])
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
		item := agentItem{
			Name:      ag.Name,
			Role:      ag.Role,
			Status:    ag.Status,
			Vaults:    agentVaultsJSON(&ag),
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

	actor, err := s.requireInstanceMember(w, r)
	if err != nil {
		return
	}

	agent, err := s.store.GetAgentByName(ctx, name)
	if err != nil {
		jsonError(w, http.StatusNotFound, "Agent not found")
		return
	}

	if !actor.IsOwner() {
		accessible, accErr := s.actorAccessibleVaultIDs(ctx, actor.ID)
		if accErr != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to load agent")
			return
		}
		if !agentDirectoryRowVisibleToNonOwner(agent, actor, accessible) {
			jsonError(w, http.StatusNotFound, "Agent not found")
			return
		}
	}

	resp := map[string]interface{}{
		"name":       agent.Name,
		"role":       agent.Role,
		"status":     agent.Status,
		"vaults":     agentVaultsJSON(agent),
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

	if !actor.IsOwner() && agent.Role == "owner" {
		jsonError(w, http.StatusForbidden, "Only instance owners can manage owner-role agents")
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

	s.captureEvent(r, "av.agent-revoke", actor, map[string]string{"agent_name": name})
	jsonOK(w, map[string]string{"message": fmt.Sprintf("agent %q revoked", name)})
}

func (s *Server) handleAgentDelete(w http.ResponseWriter, r *http.Request) {
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

	if !actor.IsOwner() && agent.Role == "owner" {
		jsonError(w, http.StatusForbidden, "Only instance owners can manage owner-role agents")
		return
	}
	if !actor.IsOwner() && agent.CreatedBy != actor.ID {
		jsonError(w, http.StatusForbidden, "Only the owner or agent creator can delete agents")
		return
	}

	if agent.Role == "owner" && s.guardLastOwner(ctx, w, "delete") {
		return
	}

	if err := s.store.DeleteAgent(ctx, agent.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to delete agent")
		return
	}

	s.captureEvent(r, "av.agent-delete", actor, map[string]string{"agent_name": name})
	jsonOK(w, map[string]string{"message": fmt.Sprintf("agent %q deleted", name)})
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

	if !actor.IsOwner() && agent.Role == "owner" {
		jsonError(w, http.StatusForbidden, "Only instance owners can manage owner-role agents")
		return
	}
	if !actor.IsOwner() && agent.CreatedBy != actor.ID {
		jsonError(w, http.StatusForbidden, "Only the owner or agent creator can rotate agents")
		return
	}

	sess, err := s.store.RotateAgentToken(ctx, agent.ID, nil)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to rotate agent token")
		return
	}

	s.captureEvent(r, "av.agent-rotate", actor, map[string]string{"agent_name": agent.Name})
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

	if !actor.IsOwner() && agent.Role == "owner" {
		jsonError(w, http.StatusForbidden, "Only instance owners can manage owner-role agents")
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

	actor, err := s.requireVaultAdmin(w, r, ns.ID)
	if err != nil {
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
	if !validVaultRole(body.Role) {
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

	s.captureEvent(r, "av.vault-agent-add", actor, map[string]string{"vault": nsName, "agent_name": body.Name})
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

	actor, err := s.requireVaultAdmin(w, r, ns.ID)
	if err != nil {
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

	s.captureEvent(r, "av.vault-agent-remove", actor, map[string]string{"vault": nsName, "agent_name": agentName})
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
	if !validVaultRole(body.Role) {
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

func agentVaultsJSON(ag *store.Agent) []agentVaultJSON {
	out := make([]agentVaultJSON, 0, len(ag.Vaults))
	for _, v := range ag.Vaults {
		out = append(out, agentVaultJSON{VaultName: v.VaultName, VaultRole: v.Role})
	}
	return out
}

func (s *Server) actorAccessibleVaultIDs(ctx context.Context, actorID string) (map[string]bool, error) {
	grants, err := s.store.ListActorGrants(ctx, actorID)
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool, len(grants))
	for _, g := range grants {
		m[g.VaultID] = true
	}
	return m, nil
}

// agentDirectoryRowVisibleToNonOwner is the non-owner directory filter (see handleAgentList).
func agentDirectoryRowVisibleToNonOwner(ag *store.Agent, actor *Actor, accessibleVaults map[string]bool) bool {
	if ag.CreatedBy == actor.ID {
		return true
	}
	for _, v := range ag.Vaults {
		if accessibleVaults[v.VaultID] {
			return true
		}
	}
	return false
}
