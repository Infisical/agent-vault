package server

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// handleInviteRedeem serves the SPA for browser-based invite acceptance.
// All agent invites are now redeemed via POST /invite/{token} (handlePersistentInviteRedeem).
// GET /invite/{token} serves the browser page OR returns a redirect hint for agents.
func (s *Server) handleInviteRedeem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.PathValue("token")

	// Check if this is a user invite (av_uinv_ prefix) — delegate to SPA.
	if strings.HasPrefix(token, "av_uinv_") {
		s.handleSPA(w, r)
		return
	}

	inv, err := s.store.GetInviteByToken(ctx, token)
	if err != nil || inv == nil {
		proxyError(w, http.StatusNotFound, "invite_not_found", "Invite not found")
		return
	}

	switch inv.Status {
	case "redeemed":
		proxyError(w, http.StatusGone, "invite_redeemed", "This invite has already been used — ask for a new one")
		return
	case "revoked":
		proxyError(w, http.StatusGone, "invite_revoked", "This invite was revoked — ask for a new one")
		return
	case "expired":
		proxyError(w, http.StatusGone, "invite_expired", "This invite has expired — ask for a new one")
		return
	}

	if time.Now().After(inv.ExpiresAt) {
		proxyError(w, http.StatusGone, "invite_expired", "This invite has expired — ask for a new one")
		return
	}

	// All agent invites must be redeemed via POST.
	jsonStatus(w, http.StatusMethodNotAllowed, map[string]string{
		"error":   "use_post",
		"message": "Agent invites must be redeemed via POST /invite/{token} with a JSON body.",
	})
}

func (s *Server) handleAgentInviteList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	actor, err := s.requireActor(w, r)
	if err != nil {
		return
	}

	status := r.URL.Query().Get("status")
	invites, err := s.store.ListInvites(ctx, status)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list invites")
		return
	}

	// Filter: owners see all; others see invites they created or with pre-assignments to vaults they admin.
	var actorAdminVaults map[string]bool
	if !actor.IsOwner() {
		actorAdminVaults = make(map[string]bool)
		if grants, err := s.store.ListActorGrants(ctx, actor.ID); err == nil {
			for _, g := range grants {
				if g.Role == "admin" {
					actorAdminVaults[g.VaultID] = true
				}
			}
		}
	}

	var filtered []store.Invite
	for _, inv := range invites {
		if actor.IsOwner() || inv.CreatedBy == actor.ID {
			filtered = append(filtered, inv)
			continue
		}
		for _, v := range inv.Vaults {
			if actorAdminVaults[v.VaultID] {
				filtered = append(filtered, inv)
				break
			}
		}
	}

	type inviteItem struct {
		ID               int              `json:"id"`
		Token            string           `json:"token,omitempty"`
		AgentName        string           `json:"agent_name"`
		AgentRole        string           `json:"agent_role"`
		Status           string           `json:"status"`
		Vaults           []agentVaultJSON `json:"vaults"`
		CreatedAt        string           `json:"created_at"`
		ExpiresAt        string           `json:"expires_at"`
		RedeemedAt       *string          `json:"redeemed_at,omitempty"`
		TokenExpiresAt *string          `json:"token_expires_at,omitempty"`
	}

	items := make([]inviteItem, len(filtered))
	for i, inv := range filtered {
		var vaults []agentVaultJSON
		for _, v := range inv.Vaults {
			vaults = append(vaults, agentVaultJSON{VaultName: v.VaultName, VaultRole: v.VaultRole})
		}
		items[i] = inviteItem{
			ID:        inv.ID,
			AgentName: inv.AgentName,
			AgentRole: inv.AgentRole,
			Status:    inv.Status,
			Vaults:    vaults,
			CreatedAt: inv.CreatedAt.Format(time.RFC3339),
			ExpiresAt: inv.ExpiresAt.Format(time.RFC3339),
		}
		if inv.RedeemedAt != nil {
			r := inv.RedeemedAt.Format(time.RFC3339)
			items[i].RedeemedAt = &r
		}
		if inv.Status == "redeemed" && inv.SessionID != "" {
			if session, err := s.store.GetSession(ctx, inv.SessionID); err == nil && session != nil {
				e := formatExpiresAt(session.ExpiresAt)
				items[i].TokenExpiresAt = &e
			}
		}
	}

	jsonOK(w, map[string]interface{}{"invites": items})
}

func (s *Server) handleAgentInviteRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.PathValue("token")

	actor, err := s.requireActor(w, r)
	if err != nil {
		return
	}

	inv, err := s.store.GetInviteByToken(ctx, token)
	if err != nil || inv == nil {
		proxyError(w, http.StatusNotFound, "invite_not_found", "Invite not found")
		return
	}

	if !s.canRevokeAgentInvite(ctx, actor, inv) {
		jsonError(w, http.StatusForbidden, "You do not have permission to revoke this invite")
		return
	}

	if inv.Status != "pending" {
		jsonError(w, http.StatusConflict, fmt.Sprintf("Invite is already %s", inv.Status))
		return
	}

	if err := s.store.RevokeInvite(ctx, token); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to revoke invite")
		return
	}

	jsonOK(w, map[string]string{"status": "revoked"})
}

func (s *Server) handleAgentInviteRevokeByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	actor, err := s.requireActor(w, r)
	if err != nil {
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid invite ID")
		return
	}

	inv, err := s.store.GetInviteByID(ctx, id)
	if err != nil || inv == nil {
		proxyError(w, http.StatusNotFound, "invite_not_found", "Invite not found")
		return
	}

	if !s.canRevokeAgentInvite(ctx, actor, inv) {
		jsonError(w, http.StatusForbidden, "You do not have permission to revoke this invite")
		return
	}

	if inv.Status != "pending" {
		jsonError(w, http.StatusConflict, fmt.Sprintf("Invite is already %s", inv.Status))
		return
	}

	if err := s.store.RevokeInviteByID(ctx, id); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to revoke invite")
		return
	}

	jsonOK(w, map[string]string{"status": "revoked"})
}

// canRevokeAgentInvite checks if the user is the invite creator, an owner, or admin of a pre-assigned vault.
func (s *Server) canRevokeAgentInvite(ctx context.Context, actor *Actor, inv *store.Invite) bool {
	if actor.IsOwner() || inv.CreatedBy == actor.ID {
		return true
	}
	for _, v := range inv.Vaults {
		if role, err := s.store.GetVaultRole(ctx, actor.ID, v.VaultID); err == nil && role == "admin" {
			return true
		}
	}
	return false
}

//go:embed persistent_instructions_admin.txt
var persistentInstructionsAdmin string


// validateSlug checks that a name is 3-64 lowercase alphanumeric + hyphens.
func validateSlug(name string) bool {
	if len(name) < 3 || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// reservedVaultNames are names that conflict with /vaults/* frontend routes.
// Keep in sync with vaultsLayoutRoute children in web/src/router.tsx.
var reservedVaultNames = map[string]struct{}{
	"users": {},
}

func isReservedVaultName(name string) bool {
	_, ok := reservedVaultNames[name]
	return ok
}

// handlePersistentInviteRedeem handles POST /invite/{token} for agent invite redemption.
func (s *Server) handlePersistentInviteRedeem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.PathValue("token")

	inv, err := s.store.GetInviteByToken(ctx, token)
	if err != nil || inv == nil {
		proxyError(w, http.StatusNotFound, "invite_not_found", "Invite not found")
		return
	}

	switch inv.Status {
	case "redeemed":
		proxyError(w, http.StatusGone, "invite_redeemed", "This invite has already been used — ask for a new one")
		return
	case "revoked":
		proxyError(w, http.StatusGone, "invite_revoked", "This invite was revoked — ask for a new one")
		return
	case "expired":
		proxyError(w, http.StatusGone, "invite_expired", "This invite has expired — ask for a new one")
		return
	}
	if time.Now().After(inv.ExpiresAt) {
		proxyError(w, http.StatusGone, "invite_expired", "This invite has expired — ask for a new one")
		return
	}

	// Rotation invite: agent_id is set, no new agent creation needed.
	if inv.AgentID != "" {
		s.handleRotationRedeem(w, r, inv, token)
		return
	}

	// New agent invite: determine name.
	var body struct {
		Name string `json:"name"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}

	agentName := inv.AgentName
	if agentName == "" && body.Name != "" {
		agentName = body.Name
	}
	if agentName == "" {
		proxyError(w, http.StatusBadRequest, "name_required", "Agent name is required — provide {\"name\": \"my-agent\"} in the request body")
		return
	}
	if !validateSlug(agentName) {
		proxyError(w, http.StatusBadRequest, "invalid_name", "Agent name must be 3-64 characters, lowercase alphanumeric and hyphens only")
		return
	}

	// Check name uniqueness.
	existing, _ := s.store.GetAgentByName(ctx, agentName)
	if existing != nil {
		proxyError(w, http.StatusConflict, "name_taken", fmt.Sprintf("An agent named %q already exists", agentName))
		return
	}

	// Burn the invite (atomic CAS via status='pending' guard).
	if err := s.store.RedeemInvite(ctx, token, ""); err != nil {
		proxyError(w, http.StatusGone, "invite_redeemed", "This invite has already been used — ask for a new one")
		return
	}

	// Create instance-level agent with the invite's instance role.
	agent, err := s.store.CreateAgent(ctx, agentName, inv.CreatedBy, inv.AgentRole)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			proxyError(w, http.StatusConflict, "name_taken", fmt.Sprintf("An agent named %q already exists", agentName))
			return
		}
		fmt.Fprintf(os.Stderr, "[agent-vault] ERROR: CreateAgent(%q): %v\n", agentName, err)
		jsonError(w, http.StatusInternalServerError, "Failed to create agent")
		return
	}

	// Apply vault pre-assignments from the invite.
	var vaultInfos []agentVaultJSON
	for _, v := range inv.Vaults {
		if err := s.store.GrantVaultRole(ctx, agent.ID, "agent", v.VaultID, v.VaultRole); err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to grant vault access")
			return
		}
		vaultInfos = append(vaultInfos, agentVaultJSON{VaultName: v.VaultName, VaultRole: v.VaultRole})
	}

	// Create instance-level agent token (no vault_id).
	var tokenExpiry *time.Time
	if inv.SessionTTLSeconds > 0 {
		tokenExpiry = timePtr(time.Now().Add(time.Duration(inv.SessionTTLSeconds) * time.Second))
	}
	sess, err := s.store.CreateAgentToken(ctx, agent.ID, tokenExpiry)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create agent token")
		return
	}

	// Link token back to invite so invite list can show token expiry.
	_ = s.store.UpdateInviteSessionID(ctx, inv.ID, sess.ID)

	baseURL := s.baseURL

	jsonOK(w, map[string]interface{}{
		"av_addr":          baseURL,
		"av_agent_token": sess.ID,
		"agent_name":       agentName,
		"proxy_url":        baseURL + "/proxy",
		"vaults":           vaultInfos,
		"instructions":     persistentInstructionsAdmin,
	})
}

// handleRotationRedeem handles redemption of a rotation invite (invite with agent_id set).
func (s *Server) handleRotationRedeem(w http.ResponseWriter, r *http.Request, inv *store.Invite, token string) {
	ctx := r.Context()

	agent, err := s.store.GetAgentByID(ctx, inv.AgentID)
	if err != nil || agent == nil || agent.Status != "active" {
		proxyError(w, http.StatusGone, "agent_not_found", "The agent for this rotation invite no longer exists or has been revoked")
		return
	}

	// Burn the invite.
	if err := s.store.RedeemInvite(ctx, token, ""); err != nil {
		proxyError(w, http.StatusGone, "invite_redeemed", "This invite has already been used — ask for a new one")
		return
	}

	// Invalidate existing tokens for this agent (rotation replaces access).
	if err := s.store.DeleteAgentTokens(ctx, agent.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to invalidate old agent tokens")
		return
	}

	// Create a new instance-level agent token.
	sess, err := s.store.CreateAgentToken(ctx, agent.ID, nil)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create agent token")
		return
	}

	// Link token back to invite so invite list can show token expiry.
	_ = s.store.UpdateInviteSessionID(ctx, inv.ID, sess.ID)

	var vaultInfos []agentVaultJSON
	for _, v := range agent.Vaults {
		vaultInfos = append(vaultInfos, agentVaultJSON{VaultName: v.VaultName, VaultRole: v.Role})
	}

	baseURL := s.baseURL

	jsonOK(w, map[string]interface{}{
		"av_addr":          baseURL,
		"av_agent_token": sess.ID,
		"agent_name":       agent.Name,
		"proxy_url":        baseURL + "/proxy",
		"vaults":           vaultInfos,
		"instructions":     persistentInstructionsAdmin,
	})
}

func (s *Server) handleAgentList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Any authenticated user can list agents.
	// Owners see all; members see agents that share at least one vault.
	sess := sessionFromContext(ctx)
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return
	}

	agents, agentErr := s.store.ListAllAgents(ctx)
	if agentErr != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list agents")
		return
	}

	// For non-owner actors, filter to agents sharing at least one vault.
	actor, _ := s.actorFromSession(ctx, sess)
	isOwner := actor != nil && actor.IsOwner()
	var accessibleVaults map[string]bool
	if !isOwner && actor != nil {
		grants, _ := s.store.ListActorGrants(ctx, actor.ID)
		accessibleVaults = make(map[string]bool, len(grants))
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
		Name             string           `json:"name"`
		Role             string           `json:"role"`
		Status           string           `json:"status"`
		Vaults           []agentVaultJSON `json:"vaults"`
		CreatedAt        string           `json:"created_at"`
		RevokedAt        *string          `json:"revoked_at,omitempty"`
		TokenExpiresAt *string          `json:"token_expires_at,omitempty"`
	}

	items := make([]agentItem, 0, len(agents))
	seen := make(map[string]bool)
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
		seen[ag.Name] = true
	}

	// Include agents with pending invites (not yet redeemed).
	// Non-owners only see invites targeting vaults they can access.
	pendingInvites, _ := s.store.ListInvites(ctx, "pending")
	for _, inv := range pendingInvites {
		if seen[inv.AgentName] {
			continue
		}
		if !isOwner && accessibleVaults != nil {
			hasOverlap := false
			for _, v := range inv.Vaults {
				if accessibleVaults[v.VaultID] {
					hasOverlap = true
					break
				}
			}
			if !hasOverlap {
				continue
			}
		}
		vaults := make([]agentVaultJSON, 0, len(inv.Vaults))
		for _, v := range inv.Vaults {
			vaults = append(vaults, agentVaultJSON{VaultName: v.VaultName, VaultRole: v.VaultRole})
		}
		items = append(items, agentItem{
			Name:      inv.AgentName,
			Role:      inv.AgentRole,
			Status:    "pending",
			Vaults:    vaults,
			CreatedAt: inv.CreatedAt.Format(time.RFC3339),
		})
		seen[inv.AgentName] = true
	}

	jsonOK(w, map[string]interface{}{"agents": items})
}

func (s *Server) handleAgentGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	// Any authenticated user can view an agent.
	sess := sessionFromContext(ctx)
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
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

	// Count active tokens.
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

	// Owner or agent's creator can revoke.
	actor, err := s.requireActor(w, r)
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

	// Safety: cannot revoke the last owner.
	if agent.Role == "owner" && s.guardLastOwner(ctx, w, "revoke") {
		return
	}

	if err := s.store.RevokeAgent(ctx, agent.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to revoke agent")
		return
	}

	jsonOK(w, map[string]string{"message": fmt.Sprintf("agent %q revoked", name)})
}

func (s *Server) handleAgentRotate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	// Owner or agent's creator can rotate.
	actor, err := s.requireActor(w, r)
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

	// Create a rotation invite.
	inv, err := s.store.CreateRotationInvite(ctx, agent.ID, actor.ID, time.Now().Add(15*time.Minute))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create rotation invite")
		return
	}

	inviteURL := s.baseURL + "/invite/" + inv.Token
	prompt := fmt.Sprintf(`Your Agent Vault session is being rotated. To accept the new session, make the following HTTP request:

  POST %s
  Content-Type: application/json

  {}

The response contains your new agent token and usage instructions.

This link expires in 15 minutes and can only be used once.
`, inviteURL)

	jsonOK(w, map[string]interface{}{
		"invite_url": inviteURL,
		"prompt":     prompt,
		"expires_in": "15m",
	})
}

func (s *Server) handleAgentRename(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	// Owner or agent's creator can rename.
	actor, err := s.requireActor(w, r)
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
	if !validateSlug(body.Name) {
		jsonError(w, http.StatusBadRequest, "Agent name must be 3-64 characters, lowercase alphanumeric and hyphens only")
		return
	}

	// Check uniqueness.
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

	// Any vault member can list agents.
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
	seen := make(map[string]bool)
	for _, ag := range agents {
		// Find this vault's role from the agent's grants.
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
		seen[ag.Name] = true
	}

	// Include pending invite pre-assignments for this vault.
	pendingInvites, _ := s.store.ListInvitesByVault(ctx, ns.ID, "pending")
	for _, inv := range pendingInvites {
		if seen[inv.AgentName] {
			continue
		}
		for _, v := range inv.Vaults {
			if v.VaultID == ns.ID {
				items = append(items, item{
					Name:      inv.AgentName,
					VaultRole: v.VaultRole,
					Status:    "pending",
				})
				seen[inv.AgentName] = true
				break
			}
		}
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

	// Vault admin required.
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
		// Agent doesn't exist yet — check for a pending invite and add a vault pre-assignment.
		inv, invErr := s.store.GetPendingInviteByAgentName(ctx, body.Name)
		if invErr != nil || inv == nil {
			jsonError(w, http.StatusNotFound, fmt.Sprintf("Agent %q not found", body.Name))
			return
		}
		// Check not already pre-assigned to this vault.
		for _, v := range inv.Vaults {
			if v.VaultID == ns.ID {
				jsonError(w, http.StatusConflict, fmt.Sprintf("Agent %q is already pre-assigned to vault %q", body.Name, nsName))
				return
			}
		}
		if err := s.store.AddAgentInviteVault(ctx, inv.ID, ns.ID, body.Role); err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to add vault pre-assignment to agent invite")
			return
		}
		jsonCreated(w, map[string]string{
			"message": fmt.Sprintf("agent %q pre-assigned to vault %q with role %q (pending invite acceptance)", body.Name, nsName, body.Role),
		})
		return
	}
	if agent.Status != "active" {
		jsonError(w, http.StatusConflict, "Agent is revoked")
		return
	}

	// Check not already granted.
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

	// Vault admin required.
	if _, err := s.requireVaultAdmin(w, r, ns.ID); err != nil {
		return
	}

	agent, err := s.store.GetAgentByName(ctx, agentName)
	if err != nil || agent == nil {
		// Agent doesn't exist yet — check for a pending invite pre-assignment.
		inv, invErr := s.store.GetPendingInviteByAgentName(ctx, agentName)
		if invErr != nil || inv == nil {
			jsonError(w, http.StatusNotFound, fmt.Sprintf("Agent %q not found", agentName))
			return
		}
		if err := s.store.RemoveAgentInviteVault(ctx, inv.ID, ns.ID); err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to remove vault pre-assignment")
			return
		}
		jsonOK(w, map[string]string{
			"message": fmt.Sprintf("agent %q pre-assignment removed from vault %q", agentName, nsName),
		})
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

	// Vault admin required.
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
		// Agent doesn't exist yet — check for a pending invite pre-assignment.
		inv, invErr := s.store.GetPendingInviteByAgentName(ctx, agentName)
		if invErr != nil || inv == nil {
			jsonError(w, http.StatusNotFound, fmt.Sprintf("Agent %q not found", agentName))
			return
		}
		// Verify pre-assignment exists for this vault.
		found := false
		for _, v := range inv.Vaults {
			if v.VaultID == ns.ID {
				found = true
				break
			}
		}
		if !found {
			jsonError(w, http.StatusNotFound, fmt.Sprintf("Agent %q does not have access to vault %q", agentName, nsName))
			return
		}
		if err := s.store.UpdateAgentInviteVaultRole(ctx, inv.ID, ns.ID, body.Role); err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to update agent role")
			return
		}
		jsonOK(w, map[string]string{
			"message": fmt.Sprintf("agent %q vault %q pre-assignment role updated to %q", agentName, nsName, body.Role),
		})
		return
	}

	// Verify agent has access to this vault.
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

func (s *Server) handleAgentInviteCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	type vaultReq struct {
		VaultName string `json:"vault_name"`
		VaultRole string `json:"vault_role"`
	}
	var req struct {
		Name              string     `json:"name"`
		Role              string     `json:"role"` // instance-level role: "owner" or "member" (default: "member")
		TTLSeconds        int        `json:"ttl_seconds"`
		SessionTTLSeconds *int       `json:"session_ttl_seconds,omitempty"`
		Vaults            []vaultReq `json:"vaults"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Agent name is required.
	if req.Name == "" {
		jsonError(w, http.StatusBadRequest, "Agent name is required")
		return
	}
	if !validateSlug(req.Name) {
		jsonError(w, http.StatusBadRequest, "Agent name must be 3-64 characters, lowercase alphanumeric and hyphens only")
		return
	}

	if req.TTLSeconds <= 0 {
		req.TTLSeconds = 7 * 24 * 60 * 60 // 7 days default
	}
	maxTTL := 7 * 24 * 60 * 60
	if req.TTLSeconds > maxTTL {
		req.TTLSeconds = maxTTL
	}

	// Cap finite session TTL.
	if req.SessionTTLSeconds != nil && *req.SessionTTLSeconds > 0 {
		ttl := *req.SessionTTLSeconds
		if ttl < scopedSessionMinTTL {
			ttl = scopedSessionMinTTL
			req.SessionTTLSeconds = &ttl
		} else if ttl > scopedSessionMaxTTL {
			ttl = scopedSessionMaxTTL
			req.SessionTTLSeconds = &ttl
		}
	}

	// Any authenticated actor can create agent invites.
	actor, err := s.requireActor(w, r)
	if err != nil {
		return
	}

	// Check for duplicate agent name (existing agent or pending invite).
	existing, _ := s.store.GetAgentByName(ctx, req.Name)
	if existing != nil {
		jsonError(w, http.StatusConflict, fmt.Sprintf("An agent named %q already exists", req.Name))
		return
	}
	if hasPending, _ := s.store.HasPendingInviteByAgentName(ctx, req.Name); hasPending {
		jsonError(w, http.StatusConflict, fmt.Sprintf("A pending invite for agent %q already exists", req.Name))
		return
	}

	// Check pending invite limit.
	count, err := s.store.CountPendingInvites(ctx)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to check pending invites")
		return
	}
	if count >= 50 {
		jsonError(w, http.StatusTooManyRequests, fmt.Sprintf("Too many pending invites (%d) — revoke some before creating new ones", count))
		return
	}

	// Validate and resolve vault pre-assignments.
	var inviteVaults []store.AgentInviteVault
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
		// Inviter must be admin of the vault (or instance owner).
		if !actor.IsOwner() {
			role, err := s.store.GetVaultRole(ctx, actor.ID, ns.ID)
			if err != nil || role != "admin" {
				jsonError(w, http.StatusForbidden, fmt.Sprintf("You must be an admin of vault %q to pre-assign it", v.VaultName))
				return
			}
		}
		inviteVaults = append(inviteVaults, store.AgentInviteVault{
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
	if agentRole != "owner" && agentRole != "member" {
		jsonError(w, http.StatusBadRequest, "Role must be one of: owner, member")
		return
	}
	// Only owner actors can create owner-role agent invites.
	if agentRole == "owner" && !actor.IsOwner() {
		jsonError(w, http.StatusForbidden, "Only owners can create owner-role agent invites")
		return
	}

	sessionTTL := 0
	if req.SessionTTLSeconds != nil {
		sessionTTL = *req.SessionTTLSeconds
	}

	expiresAt := time.Now().Add(time.Duration(req.TTLSeconds) * time.Second)
	inv, err := s.store.CreateAgentInvite(ctx, req.Name, actor.ID, expiresAt, sessionTTL, agentRole, inviteVaults)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create agent invite")
		return
	}

	inviteURL := s.baseURL + "/invite/" + inv.Token

	type vaultResp struct {
		VaultName string `json:"vault_name"`
		VaultRole string `json:"vault_role"`
	}
	vaults := make([]vaultResp, 0, len(inviteVaults))
	for _, v := range inviteVaults {
		vaults = append(vaults, vaultResp{VaultName: v.VaultName, VaultRole: v.VaultRole})
	}

	jsonCreated(w, map[string]interface{}{
		"token":       inv.Token,
		"agent_name":  req.Name,
		"vaults":      vaults,
		"invite_link": inviteURL,
		"expires_at":  inv.ExpiresAt.Format(time.RFC3339),
	})
}

// handleAgentSetRole changes an agent's instance-level role (owner/member).
func (s *Server) handleAgentSetRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	// Only owners can change agent instance roles.
	if _, err := s.requireOwnerActor(w, r); err != nil {
		return
	}

	var body struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Role == "" {
		jsonError(w, http.StatusBadRequest, `Request body must include {"role": "owner|member"}`)
		return
	}
	if body.Role != "owner" && body.Role != "member" {
		jsonError(w, http.StatusBadRequest, "Role must be one of: owner, member")
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

	// Safety: cannot demote the last owner (user or agent).
	if agent.Role == "owner" && body.Role == "member" && s.guardLastOwner(ctx, w, "demote") {
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
