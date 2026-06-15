package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/infisical"
	"github.com/Infisical/agent-vault/internal/store"
)

// resolveVaultForAdminOrOwner loads the vault and verifies the caller is
// either a vault admin or the instance owner — the auth scope shared by
// vault rename, delete, and settings handlers. On failure it writes the
// error response and returns nil; callers should `return` immediately.
func (s *Server) resolveVaultForAdminOrOwner(w http.ResponseWriter, r *http.Request, name string) *store.Vault {
	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return nil
	}
	actor, err := s.requireActor(w, r)
	if err != nil {
		return nil
	}
	role, _ := s.store.GetVaultRole(ctx, actor.ID, ns.ID)
	if role != "admin" && !actor.IsOwner() {
		jsonError(w, http.StatusForbidden, "Vault admin or instance owner required")
		return nil
	}
	return ns
}

// readUnmatchedHostPolicy returns the per-vault unmatched_host_policy,
// defaulting to PolicyPassthrough when the row is absent or holds an
// unrecognised value. A non-nil error means the underlying store read
// failed for a reason other than "not present".
func readUnmatchedHostPolicy(ctx context.Context, st interface {
	GetVaultSetting(ctx context.Context, vaultID, key string) (string, error)
}, vaultID string) (brokercore.UnmatchedHostPolicy, error) {
	raw, err := st.GetVaultSetting(ctx, vaultID, settingUnmatchedHostPolicy)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return brokercore.PolicyPassthrough, nil
		}
		return brokercore.PolicyPassthrough, err
	}
	policy := brokercore.UnmatchedHostPolicy(raw)
	if !brokercore.IsValidUnmatchedHostPolicy(policy) {
		return brokercore.PolicyPassthrough, nil
	}
	return policy, nil
}

// handleVaultContext returns the current user's membership context for a vault.
func (s *Server) handleVaultContext(w http.ResponseWriter, r *http.Request) {
	vaultName := r.PathValue("name")
	ctx := r.Context()

	actor, err := s.requireActor(w, r)
	if err != nil {
		return
	}

	vault, err := s.store.GetVault(ctx, vaultName)
	if err != nil || vault == nil {
		jsonError(w, http.StatusNotFound, "Vault not found")
		return
	}

	vaultRole, err := s.store.GetVaultRole(ctx, actor.ID, vault.ID)
	if err != nil {
		jsonError(w, http.StatusForbidden, "No vault access")
		return
	}

	resp := map[string]interface{}{
		"vault_name": vault.Name,
		"vault_role": vaultRole,
	}
	// Fail closed on real DB errors: silently treating an external vault as
	// builtin would expose mutation buttons that then 409 on click.
	cs, err := s.store.GetVaultCredentialStore(ctx, vault.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusInternalServerError, "Failed to read credential store")
		return
	}
	if cs != nil && cs.Kind != "" {
		summary := credentialStoreDetailSummary(cs)
		// Config and LastSyncError can both carry upstream topology
		// (paths/keys); gate on the same role check that gates create.
		if vaultRole != "admin" && !actor.IsOwner() {
			summary.Config = nil
			summary.LastSyncError = ""
		}
		resp["credential_store"] = summary
	}
	jsonOK(w, resp)
}

// handleVaultSyncNow forces an immediate refresh and returns the post-refresh
// credential_store summary. Any vault member; broker identity authorizes upstream.
func (s *Server) handleVaultSyncNow(w http.ResponseWriter, r *http.Request) {
	vaultName := r.PathValue("name")
	ctx := r.Context()

	vault, err := s.store.GetVault(ctx, vaultName)
	if err != nil || vault == nil {
		jsonError(w, http.StatusNotFound, "Vault not found")
		return
	}

	// requireVaultMember enforces member+ and returns the actor for instance
	// sessions; scoped sessions return (nil, nil) and we resolve via requireActor.
	actor, err := s.requireVaultMember(w, r, vault.ID)
	if err != nil {
		return
	}
	if actor == nil {
		actor, err = s.requireActor(w, r)
		if err != nil {
			return
		}
	}

	cs, err := s.store.GetVaultCredentialStore(ctx, vault.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusInternalServerError, "Failed to read credential store")
		return
	}
	if cs == nil || cs.Kind == "" {
		jsonError(w, http.StatusBadRequest, "Vault has no external credential store")
		return
	}

	if s.infisicalSyncer == nil {
		jsonCodedError(w, http.StatusServiceUnavailable, "infisical_not_configured",
			"Infisical is not configured on this server. Set INFISICAL_URL to enable external-store vaults.")
		return
	}

	if err := s.infisicalSyncer.RefreshOnce(ctx, *cs); err != nil {
		switch {
		case errors.Is(err, infisical.ErrSyncerDisabled):
			jsonCodedError(w, http.StatusServiceUnavailable, "infisical_not_configured",
				"Infisical is not configured on this server.")
		case errors.Is(err, infisical.ErrNotExternal):
			jsonError(w, http.StatusBadRequest, "Vault has no external credential store")
		case errors.Is(err, infisical.ErrSyncInFlight):
			jsonError(w, http.StatusConflict, "Sync already in flight for this vault")
		case errors.Is(err, infisical.ErrInvalidKey):
			// Upstream key name is topology; redact for non-admin/non-owner
			// viewers, mirroring handleVaultContext's last_sync_error gate.
			if s.callerCanSeeVaultUpstream(ctx, actor, vault.ID) {
				jsonCodedError(w, http.StatusBadRequest, "external_store_invalid_key", err.Error())
			} else {
				s.logger.Warn("manual infisical sync rejected invalid upstream key",
					slog.String("vault_id", vault.ID),
					slog.String("err", err.Error()))
				jsonCodedError(w, http.StatusBadRequest, "external_store_invalid_key",
					"Upstream secret key does not match the required UPPER_SNAKE_CASE pattern. See server logs for the offending key.")
			}
		case errors.Is(err, context.Canceled):
			return // caller went away
		default:
			s.logger.Warn("manual infisical sync failed",
				slog.String("vault_id", vault.ID),
				slog.String("err", err.Error()))
			jsonCodedError(w, http.StatusBadGateway, "infisical_fetch_failed",
				"Infisical sync failed. See server logs for details.")
		}
		return
	}

	// Manual sync forces fresh dynamic-secret leases (the periodic poll does not):
	// drop the cached ones so the next list/use mints new values.
	if s.infisicalDynamic != nil {
		s.infisicalDynamic.RevokeVault(ctx, vault.ID)
	}

	// Re-read the row so the response reflects the freshly-written health.
	cs, err = s.store.GetVaultCredentialStore(ctx, vault.ID)
	if err != nil || cs == nil {
		jsonError(w, http.StatusInternalServerError, "Failed to read credential store after sync")
		return
	}
	summary := credentialStoreDetailSummary(cs)
	if !s.callerCanSeeVaultUpstream(ctx, actor, vault.ID) {
		summary.Config = nil
		summary.LastSyncError = ""
	}
	jsonOK(w, map[string]interface{}{"credential_store": summary})
}

// callerCanSeeVaultUpstream gates upstream topology (config, last_sync_error,
// ErrInvalidKey messages) on instance owner or vault-admin grant.
func (s *Server) callerCanSeeVaultUpstream(ctx context.Context, actor *Actor, vaultID string) bool {
	if actor.IsOwner() {
		return true
	}
	if sess := sessionFromContext(ctx); sess != nil && sess.VaultID != "" {
		return sess.VaultRole == "admin"
	}
	role, _ := s.store.GetVaultRole(ctx, actor.ID, vaultID)
	return role == "admin"
}

// credentialStoreSummary is the shared shape for vault list (kind + sync
// status only) and vault context (full body, when full=true).
type credentialStoreSummary struct {
	Kind                string          `json:"kind"`
	Config              json.RawMessage `json:"config,omitempty"`
	PollIntervalSeconds int             `json:"poll_interval_seconds,omitempty"`
	LastSyncStatus      string          `json:"last_sync_status,omitempty"`
	LastSyncedAt        string          `json:"last_synced_at,omitempty"`
	LastSyncError       string          `json:"last_sync_error,omitempty"`
}

// credentialStoreListSummary is the slim shape returned in GET /v1/vaults:
// only kind + sync health, no config or error detail.
func credentialStoreListSummary(cs *store.VaultCredentialStore) *credentialStoreSummary {
	out := &credentialStoreSummary{Kind: cs.Kind, LastSyncStatus: cs.LastSyncStatus}
	if cs.LastSyncedAt != nil {
		out.LastSyncedAt = cs.LastSyncedAt.Format(time.RFC3339)
	}
	return out
}

// credentialStoreDetailSummary is the full shape for vault context and
// post-sync responses. Callers must redact Config and LastSyncError for
// non-admin/non-owner viewers (upstream topology leak).
func credentialStoreDetailSummary(cs *store.VaultCredentialStore) *credentialStoreSummary {
	out := credentialStoreListSummary(cs)
	out.PollIntervalSeconds = cs.PollIntervalSeconds
	out.LastSyncError = cs.LastSyncError
	if cs.ConfigJSON != "" {
		out.Config = json.RawMessage(cs.ConfigJSON)
	}
	return out
}

// handleInstanceCredentialStores lists credential-store kinds the caller
// may create. Always "builtin"; "infisical" only for owners when the server
// has an Infisical client (matches the create gate).
func (s *Server) handleInstanceCredentialStores(w http.ResponseWriter, r *http.Request) {
	actor, err := s.requireActor(w, r)
	if err != nil {
		return
	}
	available := []string{store.CredentialStoreBuiltin}
	if actor.IsOwner() && s.infisicalClient != nil {
		available = append(available, store.CredentialStoreInfisical)
	}
	jsonOK(w, map[string]interface{}{
		"available": available,
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

	grants, err := s.store.ListVaultMembersByType(ctx, vault.ID, "user")
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
		u, err := s.store.GetUserByID(ctx, g.ActorID)
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

	if _, err := s.requireVaultAdmin(w, r, vault.ID); err != nil {
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

	if err := s.store.GrantVaultRole(ctx, target.ID, "user", vault.ID, req.Role); err != nil {
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

	if _, err := s.requireVaultAdmin(w, r, vault.ID); err != nil {
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

	if _, err := s.requireVaultAdmin(w, r, vault.ID); err != nil {
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

	if err := s.store.GrantVaultRole(ctx, user.ID, "user", vault.ID, req.Role); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to update role")
		return
	}

	jsonOK(w, map[string]string{
		"email":   email,
		"role":    req.Role,
		"message": fmt.Sprintf("updated %s's role to %s in vault %s", email, req.Role, vaultName),
	})
}

type vaultCreateCredentialStoreRequest struct {
	Kind                string          `json:"kind"`
	Config              json.RawMessage `json:"config"`
	PollIntervalSeconds int             `json:"poll_interval_seconds"`
}

type vaultCreateRequest struct {
	Name            string                             `json:"name"`
	CredentialStore *vaultCreateCredentialStoreRequest `json:"credential_store,omitempty"`
}

func (s *Server) handleVaultCreate(w http.ResponseWriter, r *http.Request) {
	// no-access actors are blocked so they can't escalate by becoming admin
	// of a brand-new vault they just created.
	actor, err := s.requireInstanceMember(w, r)
	if err != nil {
		return
	}

	var req vaultCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Name == "" {
		jsonError(w, http.StatusBadRequest, "Name is required")
		return
	}
	if err := broker.ValidateSlug(req.Name); err != nil {
		jsonError(w, http.StatusBadRequest, "Vault name must be 3-64 characters, lowercase alphanumeric and hyphens only")
		return
	}
	if isReservedVaultName(req.Name) {
		jsonError(w, http.StatusBadRequest, "This vault name is reserved")
		return
	}

	ctx := r.Context()

	// External-store branch: probe + atomic create. Owner-only so a member
	// can't use the broker's machine identity to exfiltrate upstream secrets.
	if req.CredentialStore != nil && req.CredentialStore.Kind != "" {
		if !actor.IsOwner() {
			jsonError(w, http.StatusForbidden, "Owner role required to create external-store vaults")
			return
		}
		s.createExternalVault(w, ctx, actor, req)
		return
	}

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
	_ = s.store.GrantVaultRole(ctx, actor.ID, actor.Type, ns.ID, "admin")

	s.captureEvent(r, "av.vault-create", actor, map[string]string{"vault": req.Name})
	jsonCreated(w, map[string]interface{}{
		"id":         ns.ID,
		"name":       ns.Name,
		"created_at": ns.CreatedAt.Format(time.RFC3339),
	})
}

// infisicalSnapshot is the validated, probed, and encrypted state needed to
// back a vault with Infisical — shared by the create and switch paths.
type infisicalSnapshot struct {
	ConfigJSON          string
	PollIntervalSeconds int
	Credentials         []store.EncryptedKV
}

// prepareInfisicalSnapshot validates the requested config, probes Infisical to
// catch auth/topology errors early, and encrypts the fetched secrets. On any
// failure it writes the appropriate HTTP error response and returns ok=false;
// callers should return immediately. logName is used only for log context.
func (s *Server) prepareInfisicalSnapshot(w http.ResponseWriter, ctx context.Context, logName string, cs *vaultCreateCredentialStoreRequest) (infisicalSnapshot, bool) {
	if s.infisicalClient == nil {
		jsonCodedError(w, http.StatusServiceUnavailable, "infisical_not_configured",
			"Infisical is not configured on this Agent Vault instance. Set INFISICAL_URL and a supported auth method's env vars.")
		return infisicalSnapshot{}, false
	}
	if cs.Kind != store.CredentialStoreInfisical {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("Unknown credential store kind %q", cs.Kind))
		return infisicalSnapshot{}, false
	}

	cfg, err := infisical.ParseConfigJSON(string(cs.Config))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid credential_store.config JSON")
		return infisicalSnapshot{}, false
	}
	if err := cfg.Validate(); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return infisicalSnapshot{}, false
	}

	pollInterval := cs.PollIntervalSeconds
	if pollInterval == 0 {
		pollInterval = infisical.DefaultPollIntervalSeconds
	} else if pollInterval < infisical.MinPollIntervalSeconds {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("poll_interval_seconds must be at least %d", infisical.MinPollIntervalSeconds))
		return infisicalSnapshot{}, false
	}

	secs, err := s.infisicalClient.FetchSecrets(ctx, cfg)
	if err != nil {
		// SDK error embeds INFISICAL_URL + upstream rejection body; scrub it.
		s.logger.Warn("infisical fetch failed",
			slog.String("vault", logName),
			slog.String("err", err.Error()))
		jsonCodedError(w, http.StatusBadGateway, "infisical_fetch_failed",
			"Failed to fetch secrets from Infisical. See server logs for details.")
		return infisicalSnapshot{}, false
	}

	items, err := infisical.EncryptSecrets(secs, s.encKey)
	if err != nil {
		if errors.Is(err, infisical.ErrInvalidKey) {
			jsonCodedError(w, http.StatusBadRequest, "external_store_invalid_key", err.Error())
			return infisicalSnapshot{}, false
		}
		jsonError(w, http.StatusInternalServerError, "Failed to encrypt fetched secrets")
		return infisicalSnapshot{}, false
	}

	configJSON, err := infisical.MarshalConfigJSON(cfg)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to marshal credential store config")
		return infisicalSnapshot{}, false
	}
	return infisicalSnapshot{ConfigJSON: configJSON, PollIntervalSeconds: pollInterval, Credentials: items}, true
}

// createExternalVault validates + probes + commits the vault,
// credential-store row, initial snapshot, and admin grant in one
// transaction. Any failure leaves the DB untouched.
func (s *Server) createExternalVault(w http.ResponseWriter, ctx context.Context, actor *Actor, req vaultCreateRequest) {
	snap, ok := s.prepareInfisicalSnapshot(w, ctx, req.Name, req.CredentialStore)
	if !ok {
		return
	}

	vault, err := s.store.CreateExternalVault(ctx, store.CreateExternalVaultParams{
		Name:                req.Name,
		Kind:                store.CredentialStoreInfisical,
		ConfigJSON:          snap.ConfigJSON,
		PollIntervalSeconds: snap.PollIntervalSeconds,
		Credentials:         snap.Credentials,
		CreatorActorID:      actor.ID,
		CreatorActorType:    actor.Type,
	})
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			jsonError(w, http.StatusConflict, fmt.Sprintf("Vault %q already exists", req.Name))
			return
		}
		jsonError(w, http.StatusInternalServerError, "Failed to create vault")
		return
	}

	now := vault.CreatedAt
	jsonCreated(w, map[string]interface{}{
		"id":         vault.ID,
		"name":       vault.Name,
		"created_at": now.Format(time.RFC3339),
		"credential_store": &credentialStoreSummary{
			Kind:                store.CredentialStoreInfisical,
			Config:              json.RawMessage(snap.ConfigJSON),
			PollIntervalSeconds: snap.PollIntervalSeconds,
			LastSyncStatus:      store.SyncStatusOK,
			LastSyncedAt:        now.Format(time.RFC3339),
		},
	})
}

// handleVaultCredentialStorePatch switches the credential store backing an
// existing vault. Switching to "infisical" (owner-only) probes + fetches the
// upstream snapshot and OVERWRITES the vault's built-in credentials. Switching
// to "builtin" (vault admin or owner) disconnects the external store; polling
// stops but the last synced credentials are KEPT as built-in credentials.
func (s *Server) handleVaultCredentialStorePatch(w http.ResponseWriter, r *http.Request) {
	ns := s.resolveVaultForAdminOrOwner(w, r, r.PathValue("name"))
	if ns == nil {
		return
	}
	ctx := r.Context()

	// The patch body has the same shape as the create credential_store block.
	var req vaultCreateCredentialStoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	switch req.Kind {
	case store.CredentialStoreBuiltin:
		// Disconnect: drop the external-store row so polling stops; the last
		// synced credentials remain as ordinary built-in credentials.
		if err := s.store.DeleteVaultCredentialStore(ctx, ns.ID); err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to switch credential store")
			return
		}
		s.revokeDynamicLeases(ns.ID)
		jsonOK(w, map[string]interface{}{
			"credential_store": &credentialStoreSummary{Kind: store.CredentialStoreBuiltin},
		})
	case store.CredentialStoreInfisical:
		// Owner-only, mirroring handleVaultCreate: otherwise a vault admin could
		// use the broker's machine identity to fetch upstream secrets into a
		// vault they control.
		actor, err := s.requireActor(w, r)
		if err != nil {
			return
		}
		if !actor.IsOwner() {
			jsonError(w, http.StatusForbidden, "Owner role required to connect a vault to an external store")
			return
		}
		snap, ok := s.prepareInfisicalSnapshot(w, ctx, ns.Name, &req)
		if !ok {
			return
		}
		cs, err := s.store.SetVaultExternalStore(ctx, store.SetVaultExternalStoreParams{
			VaultID:             ns.ID,
			Kind:                store.CredentialStoreInfisical,
			ConfigJSON:          snap.ConfigJSON,
			PollIntervalSeconds: snap.PollIntervalSeconds,
			Credentials:         snap.Credentials,
		})
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to switch credential store")
			return
		}
		// Config may have changed (new project/env/path); drop leases minted
		// against the old config so they don't linger.
		s.revokeDynamicLeases(ns.ID)
		// Caller is admin/owner (gated above), so full detail is permitted.
		jsonOK(w, map[string]interface{}{"credential_store": credentialStoreDetailSummary(cs)})
	default:
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("Unknown credential store kind %q (expected %q or %q)", req.Kind, store.CredentialStoreBuiltin, store.CredentialStoreInfisical))
	}
}

func (s *Server) handleVaultList(w http.ResponseWriter, r *http.Request) {
	// Any authenticated actor can list vaults.
	actor, err := s.requireActor(w, r)
	if err != nil {
		return
	}

	ctx := r.Context()

	type nsItem struct {
		ID               string                  `json:"id"`
		Name             string                  `json:"name"`
		Role             string                  `json:"role,omitempty"`
		Membership       string                  `json:"membership"`
		CreatedAt        string                  `json:"created_at"`
		PendingProposals int                     `json:"pending_proposals"`
		CredentialStore  *credentialStoreSummary `json:"credential_store,omitempty"`
	}

	// Single query → map to avoid N+1 in the per-vault loop. On error we
	// still serve the list (mutation gate stays closed) and log for ops.
	csByVault := map[string]*store.VaultCredentialStore{}
	if rows, err := s.store.ListVaultCredentialStores(ctx); err != nil {
		s.logger.Warn("listing credential stores failed; vault list will omit credential_store fields",
			slog.String("err", err.Error()))
	} else {
		for i := range rows {
			csByVault[rows[i].VaultID] = &rows[i]
		}
	}
	credStoreFor := func(vaultID string) *credentialStoreSummary {
		cs := csByVault[vaultID]
		if cs == nil || cs.Kind == "" {
			return nil
		}
		return credentialStoreListSummary(cs)
	}

	var items []nsItem

	if actor.IsOwner() {
		// Owners see all vaults. Vaults they have explicit grants for are
		// "explicit"; the rest are "implicit" (visible but not yet joined).
		vaults, err := s.store.ListVaults(ctx)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to list vaults")
			return
		}
		for _, v := range vaults {
			pending, _ := s.store.CountPendingProposals(ctx, v.ID)
			role, _ := s.store.GetVaultRole(ctx, actor.ID, v.ID)
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
				CredentialStore:  credStoreFor(v.ID),
			})
		}
	} else {
		// Non-owners see only vaults they have explicit grants for.
		grants, err := s.store.ListActorGrants(ctx, actor.ID)
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
				CredentialStore:  credStoreFor(ns.ID),
			})
		}
	}
	if items == nil {
		items = []nsItem{}
	}

	jsonOK(w, map[string]interface{}{"vaults": items})
}

func (s *Server) handleAdminVaultList(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwnerActor(w, r); err != nil {
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
	v := s.resolveVaultForAdminOrOwner(w, r, name)
	if v == nil {
		return
	}
	// Revoke leases before deleting: DeleteVault's FK cascade drops the lease
	// rows, so the set to revoke (incl. DB-only orphans) must be captured first.
	// revokeDynamicLeases collects synchronously, then revokes in the background.
	s.revokeDynamicLeases(v.ID)
	if err := s.store.DeleteVault(r.Context(), name); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to delete vault")
		return
	}
	actor, _ := s.actorFromSession(r.Context(), sessionFromContext(r.Context()))
	s.captureEvent(r, "av.vault-delete", actor, map[string]string{"vault": name})
	jsonOK(w, map[string]interface{}{"name": name, "deleted": true})
}

func (s *Server) handleVaultRename(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == store.DefaultVault {
		jsonError(w, http.StatusBadRequest, "Cannot rename the default vault")
		return
	}
	if s.resolveVaultForAdminOrOwner(w, r, name) == nil {
		return
	}
	ctx := r.Context()

	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		jsonError(w, http.StatusBadRequest, "Request body must include {\"name\": \"new-name\"}")
		return
	}
	if err := broker.ValidateSlug(body.Name); err != nil {
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

// handleVaultSettingsGet is a read-only view, gated at vault-member scope
// so non-admin users can see the actual policy (the toggle is disabled
// for them via canManage on the frontend). PATCH stays at admin/owner.
func (s *Server) handleVaultSettingsGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, r.PathValue("name"))
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, "Vault not found")
		return
	}
	actor, err := s.requireVaultAccess(w, r, ns.ID)
	if err != nil {
		return
	}
	policy, err := readUnmatchedHostPolicy(ctx, s.store, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to read vault settings")
		return
	}
	// infisical_available enables the Infisical option in the credential-store
	// switcher. Only owners can connect a vault to Infisical (see
	// handleVaultCredentialStorePatch), so report it owner-gated — otherwise a
	// non-owner admin would see an option that 403s on submit.
	jsonOK(w, map[string]interface{}{
		"unmatched_host_policy": string(policy),
		"infisical_available":   s.infisicalClient != nil && actor != nil && actor.IsOwner(),
	})
}

func (s *Server) handleVaultSettingsPatch(w http.ResponseWriter, r *http.Request) {
	ns := s.resolveVaultForAdminOrOwner(w, r, r.PathValue("name"))
	if ns == nil {
		return
	}
	ctx := r.Context()

	var body struct {
		UnmatchedHostPolicy *string `json:"unmatched_host_policy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// On the write path, echo the validated input. The follow-up read
	// only fires for no-op PATCHes (no field set) — otherwise a transient
	// read failure after a committed write would desync the UI from the
	// DB on a security-relevant control.
	if body.UnmatchedHostPolicy != nil {
		val := strings.TrimSpace(*body.UnmatchedHostPolicy)
		var effective brokercore.UnmatchedHostPolicy
		if val == "" {
			if err := s.store.DeleteVaultSetting(ctx, ns.ID, settingUnmatchedHostPolicy); err != nil {
				jsonError(w, http.StatusInternalServerError, "Failed to update vault settings")
				return
			}
			effective = brokercore.PolicyPassthrough
		} else {
			policy := brokercore.UnmatchedHostPolicy(val)
			if !brokercore.IsValidUnmatchedHostPolicy(policy) {
				jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid unmatched_host_policy %q (expected \"passthrough\" or \"deny\")", val))
				return
			}
			if err := s.store.SetVaultSetting(ctx, ns.ID, settingUnmatchedHostPolicy, string(policy)); err != nil {
				jsonError(w, http.StatusInternalServerError, "Failed to update vault settings")
				return
			}
			effective = policy
		}
		jsonOK(w, map[string]interface{}{"unmatched_host_policy": string(effective)})
		return
	}

	policy, err := readUnmatchedHostPolicy(ctx, s.store, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to read vault settings")
		return
	}
	jsonOK(w, map[string]interface{}{"unmatched_host_policy": string(policy)})
}

func (s *Server) handleVaultJoin(w http.ResponseWriter, r *http.Request) {
	actor, err := s.requireOwnerActor(w, r)
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

	has, err := s.store.HasVaultAccess(ctx, actor.ID, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to check vault access")
		return
	}
	if has {
		jsonError(w, http.StatusConflict, "Already a member of this vault")
		return
	}

	if err := s.store.GrantVaultRole(ctx, actor.ID, actor.Type, ns.ID, "admin"); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to join vault")
		return
	}

	jsonOK(w, map[string]interface{}{
		"vault":  name,
		"role":   "admin",
		"joined": true,
	})
}
