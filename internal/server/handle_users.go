package server

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/store"
)

// handleUserInviteDetails returns instance-level invite details as JSON (token-based, no auth).
func (s *Server) handleUserInviteDetails(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.PathValue("token")

	inv, err := s.store.GetUserInviteByToken(ctx, token)
	if err != nil || inv == nil {
		jsonError(w, http.StatusNotFound, "Invite not found")
		return
	}

	switch inv.Status {
	case "accepted":
		jsonOK(w, map[string]interface{}{
			"error": true, "error_title": "Already Accepted",
			"error_message": "This invitation has already been accepted. You can log in.",
		})
		return
	case "revoked":
		jsonOK(w, map[string]interface{}{
			"error": true, "error_title": "Invite Revoked",
			"error_message": "This invitation was revoked. Please ask for a new one.",
		})
		return
	case "expired":
		jsonOK(w, map[string]interface{}{
			"error": true, "error_title": "Invite Expired",
			"error_message": "This invitation has expired. Please ask for a new one.",
		})
		return
	}

	if time.Now().After(inv.ExpiresAt) {
		jsonOK(w, map[string]interface{}{
			"error": true, "error_title": "Invite Expired",
			"error_message": "This invitation has expired. Please ask for a new one.",
		})
		return
	}

	existing, _ := s.store.GetUserByEmail(ctx, inv.Email)
	needsAccount := existing == nil

	jsonOK(w, map[string]interface{}{
		"email":         inv.Email,
		"role":          inv.Role,
		"vaults":        vaultsToJSON(inv.Vaults),
		"needs_account": needsAccount,
	})
}

// buildOwnerUserList returns enriched user data with vault memberships.
// Pre-fetches all vaults to avoid N*M queries.
func (s *Server) buildOwnerUserList(ctx context.Context, users []store.User) []map[string]interface{} {
	// Pre-fetch all vaults into a lookup map to avoid per-grant queries.
	allVaults, _ := s.store.ListVaults(ctx)
	vaultNameByID := make(map[string]string, len(allVaults))
	for _, v := range allVaults {
		vaultNameByID[v.ID] = v.Name
	}

	type vaultEntry struct {
		VaultName string `json:"vault_name"`
		VaultRole string `json:"vault_role"`
	}
	items := make([]map[string]interface{}, len(users))
	for i, u := range users {
		grants, _ := s.store.ListActorGrants(ctx, u.ID)
		vaults := make([]vaultEntry, 0, len(grants))
		for _, g := range grants {
			if name, ok := vaultNameByID[g.VaultID]; ok {
				vaults = append(vaults, vaultEntry{VaultName: name, VaultRole: g.Role})
			}
		}
		items[i] = map[string]interface{}{
			"email":      u.Email,
			"role":       u.Role,
			"vaults":     vaults,
			"created_at": u.CreatedAt.Format(time.RFC3339),
		}
	}
	return items
}

// handlePublicUserList returns all users to any authenticated user.
// Owners get full data (including vault memberships); members get a reduced view.
func (s *Server) handlePublicUserList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actor, err := s.requireActor(w, r)
	if err != nil {
		return
	}

	users, err := s.store.ListUsers(ctx)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list users")
		return
	}

	if actor.IsOwner() {
		jsonOK(w, map[string]interface{}{"users": s.buildOwnerUserList(ctx, users)})
		return
	}

	type userItem struct {
		Email     string `json:"email"`
		Role      string `json:"role"`
		CreatedAt string `json:"created_at"`
	}
	items := make([]userItem, len(users))
	for i, u := range users {
		items[i] = userItem{
			Email:     u.Email,
			Role:      u.Role,
			CreatedAt: u.CreatedAt.Format(time.RFC3339),
		}
	}
	jsonOK(w, map[string]interface{}{"users": items})
}

func (s *Server) handleUserGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	email := r.PathValue("email")

	actor, err := s.requireActor(w, r)
	if err != nil {
		return
	}

	// Allow "me" as a shorthand for the caller's own email (only for human users).
	if email == "me" {
		if actor.User == nil {
			jsonError(w, http.StatusBadRequest, "\"me\" shorthand requires a user session")
			return
		}
		email = actor.User.Email
	}

	// Members can only view themselves.
	if !actor.IsOwner() && (actor.User == nil || actor.User.Email != email) {
		jsonError(w, http.StatusForbidden, "Owner role required to view other users")
		return
	}

	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("User %q not found", email))
		return
	}

	grants, _ := s.store.ListActorGrants(ctx, user.ID)
	nsNames := make([]string, 0, len(grants))
	for _, g := range grants {
		nsNames = append(nsNames, g.VaultName)
	}

	jsonOK(w, map[string]interface{}{
		"email":      user.Email,
		"role":       user.Role,
		"vaults":     nsNames,
		"created_at": user.CreatedAt.Format(time.RFC3339),
	})
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwnerActor(w, r); err != nil {
		return
	}

	ctx := r.Context()
	email := r.PathValue("email")

	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("User %q not found", email))
		return
	}

	// Prevent deleting the last owner.
	if user.Role == "owner" && s.guardLastOwner(ctx, w, "remove") {
		return
	}

	// Delete sessions, then user (grants cascade via FK).
	_ = s.store.DeleteUserSessions(ctx, user.ID)
	if err := s.store.DeleteUser(ctx, user.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to delete user")
		return
	}

	jsonOK(w, map[string]string{"status": "removed", "email": email})
}

type setRoleRequest struct {
	Role string `json:"role"`
}

func (s *Server) handleUserSetRole(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwnerActor(w, r); err != nil {
		return
	}

	ctx := r.Context()
	email := r.PathValue("email")

	var req setRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Role != "owner" && req.Role != "member" {
		jsonError(w, http.StatusBadRequest, "Role must be 'owner' or 'member'")
		return
	}

	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("User %q not found", email))
		return
	}

	// Prevent demoting the last owner.
	if user.Role == "owner" && req.Role == "member" && s.guardLastOwner(ctx, w, "demote") {
		return
	}

	if err := s.store.UpdateUserRole(ctx, user.ID, req.Role); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to update role")
		return
	}

	jsonOK(w, map[string]string{"email": email, "role": req.Role})
}

const userInviteTTL = 48 * time.Hour

const maxPendingUserInvites = 50

// userInviteVaultJSON is the JSON response shape for vault pre-assignments on invites.
type userInviteVaultJSON struct {
	VaultName string `json:"vault_name"`
	VaultRole string `json:"vault_role"`
}

func vaultsToJSON(vaults []store.UserInviteVault) []userInviteVaultJSON {
	items := make([]userInviteVaultJSON, len(vaults))
	for i, v := range vaults {
		items[i] = userInviteVaultJSON{VaultName: v.VaultName, VaultRole: v.VaultRole}
	}
	return items
}

// sendUserInviteEmail sends the invite email. Returns true if sent.
// On send failure, writes a JSON response directly and returns false.
func (s *Server) sendUserInviteEmail(w http.ResponseWriter, recipientEmail, inviterEmail, inviteLink, subject string, vaults []store.UserInviteVault, expiresAt time.Time) bool {
	if !s.notifier.Enabled() {
		return false
	}
	vaultNames := make([]string, len(vaults))
	for i, v := range vaults {
		vaultNames[i] = v.VaultName
	}
	vaultsStr := "No vaults pre-assigned"
	if len(vaultNames) > 0 {
		vaultsStr = strings.Join(vaultNames, ", ")
	}

	emailHTML := userInviteEmailHTML
	emailHTML = strings.ReplaceAll(emailHTML, "{{INVITER_EMAIL}}", html.EscapeString(inviterEmail))
	emailHTML = strings.ReplaceAll(emailHTML, "{{VAULTS}}", html.EscapeString(vaultsStr))
	emailHTML = strings.ReplaceAll(emailHTML, "{{INVITE_LINK}}", html.EscapeString(inviteLink))

	if err := s.notifier.SendHTMLMail([]string{recipientEmail}, subject, emailHTML); err != nil {
		jsonCreated(w, map[string]interface{}{
			"email":       recipientEmail,
			"invite_link": inviteLink,
			"email_sent":  false,
			"email_error": fmt.Sprintf("failed to send email: %v", err),
			"expires_at":  expiresAt.Format(time.RFC3339),
		})
		return false
	}
	return true
}

func (s *Server) handleUserInviteCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	actor, err := s.requireActor(w, r)
	if err != nil {
		return
	}

	var req struct {
		Email  string `json:"email"`
		Role   string `json:"role"`
		Vaults []struct {
			VaultName string `json:"vault_name"`
			VaultRole string `json:"vault_role"`
		} `json:"vaults"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if err := auth.ValidateEmail(req.Email); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Validate and default instance role.
	role := req.Role
	if role == "" {
		role = "member"
	}
	if role != "owner" && role != "member" {
		jsonError(w, http.StatusBadRequest, "Role must be one of: owner, member")
		return
	}
	if role == "owner" && !actor.IsOwner() {
		jsonError(w, http.StatusForbidden, "Only owners can create owner-role user invites")
		return
	}

	// Check if user already exists in the instance.
	if existing, _ := s.store.GetUserByEmail(ctx, req.Email); existing != nil {
		jsonError(w, http.StatusConflict, fmt.Sprintf("User %q already has an account. Use vault user management to add them to a vault.", req.Email))
		return
	}

	// Check for existing pending invite for this email.
	if pending, _ := s.store.GetPendingUserInviteByEmail(ctx, req.Email); pending != nil {
		jsonError(w, http.StatusConflict, fmt.Sprintf("A pending invite already exists for %q", req.Email))
		return
	}

	// Check allowed email domains.
	if msg := s.checkEmailDomain(ctx, req.Email); msg != "" {
		jsonError(w, http.StatusForbidden, msg)
		return
	}

	// Check pending invite limit.
	count, err := s.store.CountPendingUserInvites(ctx)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to count pending invites")
		return
	}
	if count >= maxPendingUserInvites {
		jsonError(w, http.StatusTooManyRequests, "Too many pending invites")
		return
	}

	// Resolve and validate vault pre-assignments.
	var vaults []store.UserInviteVault
	for _, v := range req.Vaults {
		if v.VaultRole == "" {
			v.VaultRole = "member"
		}
		if v.VaultRole != "admin" && v.VaultRole != "member" {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("Vault role must be 'admin' or 'member', got %q", v.VaultRole))
			return
		}
		vault, err := s.store.GetVault(ctx, v.VaultName)
		if err != nil || vault == nil {
			jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", v.VaultName))
			return
		}
		// Non-owners must be admin of each pre-assigned vault.
		if !actor.IsOwner() {
			role, _ := s.store.GetVaultRole(ctx, actor.ID, vault.ID)
			if role != "admin" {
				jsonError(w, http.StatusForbidden, fmt.Sprintf("You must be an admin of vault %q to pre-assign it", v.VaultName))
				return
			}
		}
		vaults = append(vaults, store.UserInviteVault{VaultID: vault.ID, VaultName: vault.Name, VaultRole: v.VaultRole})
	}

	inv, err := s.store.CreateUserInvite(ctx, req.Email, actor.ID, role, time.Now().Add(userInviteTTL), vaults)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create invite")
		return
	}

	inviteLink := s.baseURL + "/invite/" + inv.Token

	emailSent := s.sendUserInviteEmail(w, req.Email, actor.DisplayLabel(), inviteLink, "You've been invited to Agent Vault", vaults, inv.ExpiresAt)
	if !emailSent && s.notifier.Enabled() {
		return // error response already written by sendUserInviteEmail
	}

	resp := map[string]interface{}{
		"email":      req.Email,
		"role":       role,
		"vaults":     vaultsToJSON(vaults),
		"email_sent": emailSent,
		"expires_at": inv.ExpiresAt.Format(time.RFC3339),
	}
	if !emailSent {
		resp["invite_link"] = inviteLink
	}

	jsonCreated(w, resp)
}

func (s *Server) handleUserInviteAccept(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !userInviteAcceptLimiter.allow(ip) {
		jsonError(w, http.StatusTooManyRequests, "Too many requests. Please try again later.")
		return
	}

	ctx := r.Context()
	token := r.PathValue("token")

	var req struct {
		Password string `json:"password"`
	}
	// Body may be empty for existing users.
	_ = json.NewDecoder(r.Body).Decode(&req)

	inv, err := s.store.GetUserInviteByToken(ctx, token)
	if err != nil || inv == nil {
		jsonError(w, http.StatusNotFound, "Invite not found")
		return
	}

	switch inv.Status {
	case "accepted":
		jsonError(w, http.StatusGone, "This invite has already been accepted")
		return
	case "revoked":
		jsonError(w, http.StatusGone, "This invite was revoked")
		return
	case "expired":
		jsonError(w, http.StatusGone, "This invite has expired")
		return
	}

	if time.Now().After(inv.ExpiresAt) {
		jsonError(w, http.StatusGone, "This invite has expired")
		return
	}

	// Does the invitee already have an account?
	existing, _ := s.store.GetUserByEmail(ctx, inv.Email)

	// For new users, validate password and domain BEFORE claiming the invite.
	if existing == nil {
		if msg := s.checkEmailDomain(ctx, inv.Email); msg != "" {
			jsonError(w, http.StatusForbidden, msg)
			return
		}
		if len(req.Password) < 8 {
			jsonError(w, http.StatusBadRequest, "Password must be at least 8 characters")
			return
		}
	}

	// Atomically claim the invite (prevents double-spend race).
	if err := s.store.AcceptUserInvite(ctx, token); err != nil {
		jsonError(w, http.StatusGone, "This invite has already been accepted")
		return
	}

	var user *store.User

	if existing != nil {
		user = existing
	} else {
		hash, salt, kdfP, err := auth.HashUserPassword([]byte(req.Password))
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to hash password")
			return
		}

		newUser, err := s.store.CreateUser(ctx, inv.Email, hash, salt, inv.Role, kdfP.Time, kdfP.Memory, kdfP.Threads)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to create user")
			return
		}
		// Activate immediately — invite is the verification.
		if err := s.store.ActivateUser(ctx, newUser.ID); err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to activate user")
			return
		}
		user = newUser
	}

	// Grant pre-assigned vault access.
	for _, v := range inv.Vaults {
		if err := s.store.GrantVaultRole(ctx, user.ID, "user", v.VaultID, v.VaultRole); err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to grant vault access")
			return
		}
	}

	msg := "Account created."
	if existing != nil {
		msg = "Invite accepted."
	}
	if len(inv.Vaults) > 0 {
		msg += " Vault access granted."
	}

	jsonOK(w, map[string]interface{}{
		"email":   user.Email,
		"message": msg,
	})
}

func (s *Server) handleUserInviteList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	actor, err := s.requireActor(w, r)
	if err != nil {
		return
	}

	status := r.URL.Query().Get("status")
	invites, err := s.store.ListUserInvites(ctx, status)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list invites")
		return
	}

	// Non-owners only see invites they created or invites with pre-assignments to vaults they admin.
	if !actor.IsOwner() {
		actorGrants, _ := s.store.ListActorGrants(ctx, actor.ID)
		adminVaultIDs := map[string]bool{}
		for _, g := range actorGrants {
			if g.Role == "admin" {
				adminVaultIDs[g.VaultID] = true
			}
		}

		var filtered []store.UserInvite
		for _, inv := range invites {
			if inv.CreatedBy == actor.ID {
				filtered = append(filtered, inv)
				continue
			}
			for _, v := range inv.Vaults {
				if adminVaultIDs[v.VaultID] {
					filtered = append(filtered, inv)
					break
				}
			}
		}
		invites = filtered
	}

	type inviteItem struct {
		Email     string                `json:"email"`
		Role      string                `json:"role"`
		Token     string                `json:"token"`
		Status    string                `json:"status"`
		CreatedBy string                `json:"created_by"`
		Vaults    []userInviteVaultJSON `json:"vaults"`
		ExpiresAt string                `json:"expires_at"`
		CreatedAt string                `json:"created_at"`
	}

	items := make([]inviteItem, 0, len(invites))
	for _, inv := range invites {
		items = append(items, inviteItem{
			Email:     inv.Email,
			Role:      inv.Role,
			Token:     inv.Token,
			Status:    inv.Status,
			CreatedBy: inv.CreatedBy,
			Vaults:    vaultsToJSON(inv.Vaults),
			ExpiresAt: inv.ExpiresAt.Format(time.RFC3339),
			CreatedAt: inv.CreatedAt.Format(time.RFC3339),
		})
	}

	jsonOK(w, map[string]interface{}{"invites": items})
}

func (s *Server) handleUserInviteRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	actor, err := s.requireActor(w, r)
	if err != nil {
		return
	}

	token := r.PathValue("token")

	inv, err := s.store.GetUserInviteByToken(ctx, token)
	if err != nil || inv == nil || inv.Status != "pending" {
		jsonError(w, http.StatusNotFound, "Invite not found or not pending")
		return
	}

	// Authorization: creator, owner, or admin of a pre-assigned vault
	allowed := inv.CreatedBy == actor.ID || actor.IsOwner()
	if !allowed {
		for _, v := range inv.Vaults {
			role, _ := s.store.GetVaultRole(ctx, actor.ID, v.VaultID)
			if role == "admin" {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		jsonError(w, http.StatusForbidden, "You don't have permission to revoke this invite")
		return
	}

	if err := s.store.RevokeUserInvite(ctx, token); err != nil {
		jsonError(w, http.StatusNotFound, "Invite not found or not pending")
		return
	}

	jsonOK(w, map[string]string{"message": "Invite revoked"})
}

// handleUserInviteReinvite revokes an existing pending invite and creates a
// new one for the same email/vault assignments, generating a fresh token and link.
func (s *Server) handleUserInviteReinvite(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	actor, err := s.requireActor(w, r)
	if err != nil {
		return
	}

	token := r.PathValue("token")

	existing, err := s.store.GetUserInviteByToken(ctx, token)
	if err != nil || existing == nil {
		jsonError(w, http.StatusNotFound, "Invite not found")
		return
	}
	if existing.Status != "pending" {
		jsonError(w, http.StatusConflict, "Invite is not pending")
		return
	}

	// Authorization: creator, owner, or admin of a pre-assigned vault
	allowed := existing.CreatedBy == actor.ID || actor.IsOwner()
	if !allowed {
		for _, v := range existing.Vaults {
			role, _ := s.store.GetVaultRole(ctx, actor.ID, v.VaultID)
			if role == "admin" {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		jsonError(w, http.StatusForbidden, "You don't have permission to reinvite")
		return
	}

	// Revoke the old invite.
	if err := s.store.RevokeUserInvite(ctx, token); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to revoke old invite")
		return
	}

	// Create a new invite with the same email and vault assignments.
	inv, err := s.store.CreateUserInvite(ctx, existing.Email, actor.ID, existing.Role, time.Now().Add(userInviteTTL), existing.Vaults)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create new invite")
		return
	}

	inviteLink := s.baseURL + "/invite/" + inv.Token

	emailSent := s.sendUserInviteEmail(w, existing.Email, actor.DisplayLabel(), inviteLink, "You've been re-invited to Agent Vault", existing.Vaults, inv.ExpiresAt)
	if !emailSent && s.notifier.Enabled() {
		return // error response already written by sendUserInviteEmail
	}

	resp := map[string]interface{}{
		"email":      existing.Email,
		"email_sent": emailSent,
		"expires_at": inv.ExpiresAt.Format(time.RFC3339),
	}
	if !emailSent {
		resp["invite_link"] = inviteLink
	}

	jsonCreated(w, resp)
}
