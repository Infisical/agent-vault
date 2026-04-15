package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/store"
)

// handleVaultContext returns the current user's membership context for a vault.
func (s *Server) handleVaultContext(w http.ResponseWriter, r *http.Request) {
	vaultName := r.PathValue("name")
	ctx := r.Context()

	sess := sessionFromContext(ctx)
	if sess == nil || sess.UserID == "" {
		jsonError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}
	user, err := s.userFromSession(ctx, sess)
	if err != nil || user == nil {
		jsonError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	vault, err := s.store.GetVault(ctx, vaultName)
	if err != nil || vault == nil {
		jsonError(w, http.StatusNotFound, "Vault not found")
		return
	}

	has, err := s.store.HasVaultAccess(ctx, user.ID, vault.ID)
	if err != nil || !has {
		jsonError(w, http.StatusForbidden, "No vault access")
		return
	}

	vaultRole, _ := s.store.GetVaultRole(ctx, user.ID, vault.ID)

	jsonOK(w, map[string]interface{}{
		"vault_name": vault.Name,
		"vault_role": vaultRole,
	})
}

func (s *Server) handleVaultUserList(w http.ResponseWriter, r *http.Request) {
	vaultName := r.PathValue("name")
	ctx := r.Context()

	vault, err := s.store.GetVault(ctx, vaultName)
	if err != nil || vault == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", vaultName))
		return
	}

	if _, err := s.requireVaultAccess(w, r, vault.ID); err != nil {
		return
	}

	grants, err := s.store.ListVaultUsers(ctx, vault.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list vault users")
		return
	}

	type userItem struct {
		Email  string `json:"email"`
		Role   string `json:"role"`
		Status string `json:"status"`
	}

	var users []userItem
	for _, g := range grants {
		u, err := s.store.GetUserByID(ctx, g.UserID)
		if err != nil || u == nil {
			continue
		}
		users = append(users, userItem{Email: u.Email, Role: g.Role, Status: "active"})
	}

	// Include pending invite entries for this vault.
	pendingInvites, _ := s.store.ListUserInvitesByVault(ctx, vault.ID, "pending")
	for _, inv := range pendingInvites {
		for _, v := range inv.Vaults {
			if v.VaultID == vault.ID {
				users = append(users, userItem{Email: inv.Email, Role: v.VaultRole, Status: "pending"})
				break
			}
		}
	}

	jsonOK(w, map[string]interface{}{"users": users})
}

// handleVaultUserAdd adds an existing instance user to a vault directly.
func (s *Server) handleVaultUserAdd(w http.ResponseWriter, r *http.Request) {
	vaultName := r.PathValue("name")
	ctx := r.Context()

	vault, err := s.store.GetVault(ctx, vaultName)
	if err != nil || vault == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", vaultName))
		return
	}

	if _, err := s.requireVaultAdminSession(w, r, vault.ID); err != nil {
		return
	}

	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if err := auth.ValidateEmail(req.Email); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Role == "" {
		req.Role = "member"
	}
	if req.Role != "admin" && req.Role != "member" {
		jsonError(w, http.StatusBadRequest, "Role must be 'admin' or 'member'")
		return
	}

	target, err := s.store.GetUserByEmail(ctx, req.Email)
	if err != nil || target == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("User %q not found in this instance", req.Email))
		return
	}

	has, _ := s.store.HasVaultAccess(ctx, target.ID, vault.ID)
	if has {
		jsonError(w, http.StatusConflict, fmt.Sprintf("User %q already has access to vault %q", req.Email, vaultName))
		return
	}

	if err := s.store.GrantVaultRole(ctx, target.ID, vault.ID, req.Role); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to grant vault access")
		return
	}

	jsonCreated(w, map[string]interface{}{
		"email": req.Email,
		"role":  req.Role,
	})
}

func (s *Server) handleVaultUserRemove(w http.ResponseWriter, r *http.Request) {
	vaultName := r.PathValue("name")
	email := r.PathValue("email")
	ctx := r.Context()

	vault, err := s.store.GetVault(ctx, vaultName)
	if err != nil || vault == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", vaultName))
		return
	}

	if _, err := s.requireVaultAdminSession(w, r, vault.ID); err != nil {
		return
	}

	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("User %q not found", email))
		return
	}

	// Guard: can't remove last admin.
	role, _ := s.store.GetVaultRole(ctx, user.ID, vault.ID)
	if role == "admin" {
		adminCount, _ := s.store.CountVaultAdmins(ctx, vault.ID)
		if adminCount <= 1 {
			jsonError(w, http.StatusConflict, "Cannot remove the last admin from this vault")
			return
		}
	}

	if err := s.store.RevokeVaultAccess(ctx, user.ID, vault.ID); err != nil {
		jsonError(w, http.StatusNotFound, "User does not belong to this vault")
		return
	}

	jsonOK(w, map[string]string{"message": fmt.Sprintf("removed %s from vault %s", email, vaultName)})
}

func (s *Server) handleVaultUserSetRole(w http.ResponseWriter, r *http.Request) {
	vaultName := r.PathValue("name")
	email := r.PathValue("email")
	ctx := r.Context()

	vault, err := s.store.GetVault(ctx, vaultName)
	if err != nil || vault == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", vaultName))
		return
	}

	if _, err := s.requireVaultAdminSession(w, r, vault.ID); err != nil {
		return
	}

	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Role != "admin" && req.Role != "member" {
		jsonError(w, http.StatusBadRequest, "Role must be 'admin' or 'member'")
		return
	}

	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("User %q not found", email))
		return
	}

	// Guard: can't demote last admin.
	currentRole, _ := s.store.GetVaultRole(ctx, user.ID, vault.ID)
	if currentRole == "" {
		jsonError(w, http.StatusNotFound, "User does not belong to this vault")
		return
	}
	if currentRole == "admin" && req.Role == "member" {
		adminCount, _ := s.store.CountVaultAdmins(ctx, vault.ID)
		if adminCount <= 1 {
			jsonError(w, http.StatusConflict, "Cannot demote the last admin of this vault")
			return
		}
	}

	if err := s.store.GrantVaultRole(ctx, user.ID, vault.ID, req.Role); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to update role")
		return
	}

	jsonOK(w, map[string]string{
		"email":   email,
		"role":    req.Role,
		"message": fmt.Sprintf("updated %s's role to %s in vault %s", email, req.Role, vaultName),
	})
}

func (s *Server) handleVaultCreate(w http.ResponseWriter, r *http.Request) {
	// Any auth'd user can create vaults.
	sess := sessionFromContext(r.Context())
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return
	}
	user, err := s.userFromSession(r.Context(), sess)
	if err != nil || user == nil {
		jsonError(w, http.StatusForbidden, "User session required")
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Name == "" {
		jsonError(w, http.StatusBadRequest, "Name is required")
		return
	}
	if !validateSlug(req.Name) {
		jsonError(w, http.StatusBadRequest, "Vault name must be 3-64 characters, lowercase alphanumeric and hyphens only")
		return
	}
	if isReservedVaultName(req.Name) {
		jsonError(w, http.StatusBadRequest, "This vault name is reserved")
		return
	}

	ctx := r.Context()
	ns, err := s.store.CreateVault(ctx, req.Name)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			jsonError(w, http.StatusConflict, fmt.Sprintf("Vault %q already exists", req.Name))
			return
		}
		jsonError(w, http.StatusInternalServerError, "Failed to create vault")
		return
	}

	// Creator becomes vault admin.
	_ = s.store.GrantVaultRole(ctx, user.ID, ns.ID, "admin")

	jsonCreated(w, map[string]interface{}{
		"id":         ns.ID,
		"name":       ns.Name,
		"created_at": ns.CreatedAt.Format(time.RFC3339),
	})
}

func (s *Server) handleVaultList(w http.ResponseWriter, r *http.Request) {
	// Any auth'd user can list vaults.
	sess := sessionFromContext(r.Context())
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return
	}
	user, err := s.userFromSession(r.Context(), sess)
	if err != nil || user == nil {
		jsonError(w, http.StatusForbidden, "User session required")
		return
	}

	ctx := r.Context()

	type nsItem struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		Role             string `json:"role,omitempty"`
		Membership       string `json:"membership"`
		CreatedAt        string `json:"created_at"`
		PendingProposals int    `json:"pending_proposals"`
	}

	var items []nsItem

	if user.Role == "owner" {
		// Owners see all vaults. Vaults they have explicit grants for are
		// "explicit"; the rest are "implicit" (visible but not yet joined).
		vaults, err := s.store.ListVaults(ctx)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to list vaults")
			return
		}
		for _, v := range vaults {
			pending, _ := s.store.CountPendingProposals(ctx, v.ID)
			role, _ := s.store.GetVaultRole(ctx, user.ID, v.ID)
			membership := "implicit"
			if role != "" {
				membership = "explicit"
			}
			items = append(items, nsItem{
				ID:               v.ID,
				Name:             v.Name,
				Role:             role,
				Membership:       membership,
				CreatedAt:        v.CreatedAt.Format(time.RFC3339),
				PendingProposals: pending,
			})
		}
	} else {
		// Non-owners see only vaults they have explicit grants for.
		grants, err := s.store.ListUserGrants(ctx, user.ID)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to list vaults")
			return
		}
		for _, g := range grants {
			ns, err := s.store.GetVaultByID(ctx, g.VaultID)
			if err != nil || ns == nil {
				continue
			}
			pending, _ := s.store.CountPendingProposals(ctx, ns.ID)
			items = append(items, nsItem{
				ID:               ns.ID,
				Name:             ns.Name,
				Role:             g.Role,
				Membership:       "explicit",
				CreatedAt:        ns.CreatedAt.Format(time.RFC3339),
				PendingProposals: pending,
			})
		}
	}
	if items == nil {
		items = []nsItem{}
	}

	jsonOK(w, map[string]interface{}{"vaults": items})
}

func (s *Server) handleAdminVaultList(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwner(w, r); err != nil {
		return
	}

	ctx := r.Context()
	vaults, err := s.store.ListVaults(ctx)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list vaults")
		return
	}

	type vaultItem struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		IsDefault bool   `json:"is_default"`
		CreatedAt string `json:"created_at"`
	}

	items := make([]vaultItem, len(vaults))
	for i, v := range vaults {
		items[i] = vaultItem{
			ID:        v.ID,
			Name:      v.Name,
			IsDefault: v.Name == store.DefaultVault,
			CreatedAt: v.CreatedAt.Format(time.RFC3339),
		}
	}

	jsonOK(w, map[string]interface{}{"vaults": items})
}

func (s *Server) handleVaultDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == store.DefaultVault {
		jsonError(w, http.StatusBadRequest, "Cannot delete the default vault")
		return
	}

	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return
	}

	// Vault admin OR instance owner can delete.
	sess := sessionFromContext(ctx)
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return
	}
	user, err := s.userFromSession(ctx, sess)
	if err != nil || user == nil {
		jsonError(w, http.StatusForbidden, "User session required")
		return
	}

	isVaultAdmin := false
	if role, _ := s.store.GetVaultRole(ctx, user.ID, ns.ID); role == "admin" {
		isVaultAdmin = true
	}
	if !isVaultAdmin && user.Role != "owner" {
		jsonError(w, http.StatusForbidden, "Vault admin or instance owner required")
		return
	}

	if err := s.store.DeleteVault(ctx, name); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to delete vault")
		return
	}

	jsonOK(w, map[string]interface{}{"name": name, "deleted": true})
}

func (s *Server) handleVaultRename(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == store.DefaultVault {
		jsonError(w, http.StatusBadRequest, "Cannot rename the default vault")
		return
	}

	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return
	}

	// Vault admin OR instance owner can rename.
	sess := sessionFromContext(ctx)
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return
	}
	user, err := s.userFromSession(ctx, sess)
	if err != nil || user == nil {
		jsonError(w, http.StatusForbidden, "User session required")
		return
	}

	isVaultAdmin := false
	if role, _ := s.store.GetVaultRole(ctx, user.ID, ns.ID); role == "admin" {
		isVaultAdmin = true
	}
	if !isVaultAdmin && user.Role != "owner" {
		jsonError(w, http.StatusForbidden, "Vault admin or instance owner required")
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
		jsonError(w, http.StatusBadRequest, "Vault name must be 3-64 characters, lowercase alphanumeric and hyphens only")
		return
	}
	if isReservedVaultName(body.Name) {
		jsonError(w, http.StatusBadRequest, "This vault name is reserved")
		return
	}

	// Check uniqueness.
	existing, _ := s.store.GetVault(ctx, body.Name)
	if existing != nil {
		jsonError(w, http.StatusConflict, fmt.Sprintf("A vault named %q already exists", body.Name))
		return
	}

	if err := s.store.RenameVault(ctx, name, body.Name); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to rename vault")
		return
	}

	jsonOK(w, map[string]string{
		"message":  fmt.Sprintf("vault renamed from %q to %q", name, body.Name),
		"old_name": name,
		"new_name": body.Name,
	})
}

func (s *Server) handleVaultJoin(w http.ResponseWriter, r *http.Request) {
	user, err := s.requireOwner(w, r)
	if err != nil {
		return
	}

	name := r.PathValue("name")
	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return
	}

	has, err := s.store.HasVaultAccess(ctx, user.ID, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to check vault access")
		return
	}
	if has {
		jsonError(w, http.StatusConflict, "Already a member of this vault")
		return
	}

	if err := s.store.GrantVaultRole(ctx, user.ID, ns.ID, "admin"); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to join vault")
		return
	}

	jsonOK(w, map[string]interface{}{
		"vault":  name,
		"role":   "admin",
		"joined": true,
	})
}
