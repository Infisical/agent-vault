package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"slices"
	"strconv"

	"github.com/Infisical/agent-vault/internal/store"
)

const settingCredentialAcquisitionPolicy = store.VaultSettingCredentialAcquisitionPolicy

type vaultAcquisitionPolicy = store.VaultAcquisitionPolicy

type vaultAcquisitionHandlerSummary struct {
	ID              string   `json:"id"`
	Kind            string   `json:"kind"`
	AllowedKeys     []string `json:"allowed_keys"`
	AllowedProfiles []string `json:"allowed_profiles"`
}

func defaultVaultAcquisitionPolicy() vaultAcquisitionPolicy {
	return vaultAcquisitionPolicy{EnabledHandlers: []string{}}
}

func readVaultAcquisitionPolicy(ctx context.Context, st interface {
	GetVaultSetting(context.Context, string, string) (string, error)
}, vaultID string) (vaultAcquisitionPolicy, error) {
	raw, err := st.GetVaultSetting(ctx, vaultID, settingCredentialAcquisitionPolicy)
	if errors.Is(err, sql.ErrNoRows) {
		return defaultVaultAcquisitionPolicy(), nil
	}
	if err != nil {
		return vaultAcquisitionPolicy{}, err
	}
	policy, err := store.ParseVaultAcquisitionPolicyJSON(raw)
	if err != nil {
		return vaultAcquisitionPolicy{}, err
	}
	return policy, nil
}

func validateVaultAcquisitionPolicy(ctx context.Context, st interface {
	GetAcquisitionHandler(context.Context, string) (*store.AcquisitionHandler, error)
}, vaultID string, policy vaultAcquisitionPolicy) error {
	if policy.BrowserDOMEnabled {
		return store.ErrBrowserDOMAcquisitionUnavailable
	}
	if len(policy.EnabledHandlers) > 64 {
		return store.ErrAcquisitionPolicyHandlerUnavailable
	}
	ids := append([]string(nil), policy.EnabledHandlers...)
	slices.Sort(ids)
	for index, id := range ids {
		if store.ValidateAcquisitionHandlerID(id) != nil || index > 0 && ids[index-1] == id {
			return store.ErrAcquisitionPolicyHandlerUnavailable
		}
		handler, err := st.GetAcquisitionHandler(ctx, id)
		if handler != nil && handler.Kind == store.AcquisitionHandlerKindBrowserDOM {
			return store.ErrBrowserDOMAcquisitionUnavailable
		}
		if err != nil || handler == nil || !handler.Enabled || !containsExact(handler.AllowedVaults, vaultID) {
			return store.ErrAcquisitionPolicyHandlerUnavailable
		}
	}
	return nil
}

func (s *Server) handleVaultAcquisitionPolicyGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vault, err := s.store.GetVault(ctx, r.PathValue("name"))
	if err != nil || vault == nil {
		jsonError(w, http.StatusNotFound, "Vault not found")
		return
	}
	if _, err := s.requireVaultMember(w, r, vault.ID); err != nil {
		return
	}
	policy, err := readVaultAcquisitionPolicy(ctx, s.store, vault.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to read acquisition policy")
		return
	}
	if err := validateVaultAcquisitionPolicy(ctx, s.store, vault.ID, policy); err != nil {
		// Reads remain recoverable so a vault administrator can remove a
		// disabled/deleted handler. Start and PATCH admission still fail closed.
		w.Header().Set("X-Agent-Vault-Policy-Stale", "true")
	}
	jsonOK(w, policy)
}

// handleVaultAcquisitionHandlerCatalog returns only the non-sensitive fields a
// vault administrator needs to configure policy. The instance registry remains
// owner-only because it also contains executable paths, hashes, signing
// identities, and cross-vault allowlists.
func (s *Server) handleVaultAcquisitionHandlerCatalog(w http.ResponseWriter, r *http.Request) {
	vault := s.resolveVaultForAdminOrOwner(w, r, r.PathValue("name"))
	if vault == nil {
		return
	}
	handlers, err := s.store.ListAcquisitionHandlers(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list acquisition handlers")
		return
	}
	result := make([]vaultAcquisitionHandlerSummary, 0, len(handlers))
	for _, handler := range handlers {
		if !handler.Enabled || handler.Kind == store.AcquisitionHandlerKindBrowserDOM || !containsExact(handler.AllowedVaults, vault.ID) {
			continue
		}
		result = append(result, vaultAcquisitionHandlerSummary{
			ID:              handler.ID,
			Kind:            handler.Kind,
			AllowedKeys:     append([]string(nil), handler.AllowedKeys...),
			AllowedProfiles: append([]string(nil), handler.AllowedProfiles...),
		})
	}
	jsonOK(w, map[string]any{"handlers": result})
}

func (s *Server) handleVaultAcquisitionPolicyPatch(w http.ResponseWriter, r *http.Request) {
	vault := s.resolveVaultForAdminOrOwner(w, r, r.PathValue("name"))
	if vault == nil {
		return
	}
	var policy *vaultAcquisitionPolicy
	if err := decodeStrictJSON(r, &policy); err != nil || policy == nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if policy.EnabledHandlers == nil {
		policy.EnabledHandlers = []string{}
	}
	if policy.BrowserDOMEnabled {
		jsonCodedError(w, http.StatusConflict, "browser_dom_unavailable", "Browser DOM acquisition is not available in this build")
		return
	}
	if len(policy.EnabledHandlers) > 64 {
		jsonError(w, http.StatusBadRequest, "Too many enabled handlers")
		return
	}
	slices.Sort(policy.EnabledHandlers)
	for index, id := range policy.EnabledHandlers {
		if err := store.ValidateAcquisitionHandlerID(id); err != nil {
			jsonError(w, http.StatusBadRequest, "Invalid handler ID")
			return
		}
		if index > 0 && policy.EnabledHandlers[index-1] == id {
			jsonError(w, http.StatusBadRequest, "Duplicate handler ID")
			return
		}
	}
	for _, id := range policy.EnabledHandlers {
		handler, err := s.store.GetAcquisitionHandler(r.Context(), id)
		if handler != nil && handler.Kind == store.AcquisitionHandlerKindBrowserDOM {
			jsonCodedError(w, http.StatusConflict, "browser_dom_unavailable", "Browser DOM acquisition is not available in this build")
			return
		}
		if err != nil || handler == nil || !handler.Enabled || !containsExact(handler.AllowedVaults, vault.ID) {
			jsonCodedError(w, http.StatusConflict, "handler_unavailable", "Handler is unavailable for this vault")
			return
		}
	}
	if err := s.store.SetVaultAcquisitionPolicy(r.Context(), vault.ID, *policy); errors.Is(err, store.ErrBrowserDOMAcquisitionUnavailable) {
		jsonCodedError(w, http.StatusConflict, "browser_dom_unavailable", "Browser DOM acquisition is not available in this build")
		return
	} else if errors.Is(err, store.ErrAcquisitionPolicyHandlerUnavailable) {
		jsonCodedError(w, http.StatusConflict, "handler_unavailable", "Handler is unavailable for this vault")
		return
	} else if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to update acquisition policy")
		return
	}
	actor, _ := s.actorFromSession(r.Context(), sessionFromContext(r.Context()))
	s.captureEvent(r, "av.acquisition_policy_updated", actor, map[string]string{
		"vault": vault.Name, "handler_count": strconv.Itoa(len(policy.EnabledHandlers)),
		"browser_dom_enabled": strconv.FormatBool(policy.BrowserDOMEnabled),
	})
	jsonOK(w, policy)
}

func containsExact(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
