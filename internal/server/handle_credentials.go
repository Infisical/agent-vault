package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

type credentialsSetRequest struct {
	Vault       string            `json:"vault"`
	Credentials map[string]string `json:"credentials"`
}

type credentialsSetResponse struct {
	Set []string `json:"set"`
}

func (s *Server) handleCredentialsSet(w http.ResponseWriter, r *http.Request) {
	var req credentialsSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}
	if len(req.Credentials) == 0 {
		jsonError(w, http.StatusBadRequest, "Credentials map is required")
		return
	}

	ctx := r.Context()

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}

	// Setting credentials requires member+ role.
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	for key := range req.Credentials {
		if !broker.CredentialKeyPattern.MatchString(key) {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid credential key %q: must be SCREAMING_SNAKE_CASE (e.g. STRIPE_KEY)", key))
			return
		}
	}

	var setKeys []string
	for key, value := range req.Credentials {
		ciphertext, nonce, err := crypto.Encrypt([]byte(value), s.encKey)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Encryption failed")
			return
		}
		if _, err := s.store.SetCredential(ctx, ns.ID, key, ciphertext, nonce); err != nil {
			jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to set credential %q", key))
			return
		}
		setKeys = append(setKeys, key)
	}

	jsonOK(w, credentialsSetResponse{Set: setKeys})
}

type credentialEntry struct {
	Key   string `json:"key"`
	Value string `json:"value,omitempty"`
}

type credentialsListResponse struct {
	Keys        []string          `json:"keys"`
	Credentials []credentialEntry `json:"credentials,omitempty"`
}

func (s *Server) handleCredentialsList(w http.ResponseWriter, r *http.Request) {
	vault := r.URL.Query().Get("vault")
	if vault == "" {
		vault = store.DefaultVault
	}
	reveal := r.URL.Query().Get("reveal") == "true"
	keyFilter := r.URL.Query().Get("key")

	ctx := r.Context()

	ns, err := s.store.GetVault(ctx, vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", vault))
		return
	}

	if reveal {
		// Revealing values requires member+ role (blocks proxy-role agents).
		if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
			return
		}
	} else {
		// Listing keys only requires any vault access.
		if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
			return
		}
	}

	// Single-key reveal: fetch and decrypt one credential.
	if reveal && keyFilter != "" {
		cred, err := s.store.GetCredential(ctx, ns.ID, keyFilter)
		if err != nil {
			jsonError(w, http.StatusNotFound, fmt.Sprintf("Credential %q not found", keyFilter))
			return
		}
		plaintext, err := crypto.Decrypt(cred.Ciphertext, cred.Nonce, s.encKey)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to decrypt credential")
			return
		}
		jsonOK(w, credentialsListResponse{
			Keys:        []string{cred.Key},
			Credentials: []credentialEntry{{Key: cred.Key, Value: string(plaintext)}},
		})
		return
	}

	creds, err := s.store.ListCredentials(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list credentials")
		return
	}

	keys := make([]string, len(creds))
	for i, cred := range creds {
		keys[i] = cred.Key
	}

	resp := credentialsListResponse{Keys: keys}

	// Bulk reveal: decrypt all credential values.
	if reveal {
		entries := make([]credentialEntry, len(creds))
		for i, cred := range creds {
			plaintext, err := crypto.Decrypt(cred.Ciphertext, cred.Nonce, s.encKey)
			if err != nil {
				jsonError(w, http.StatusInternalServerError, "Failed to decrypt credential")
				return
			}
			entries[i] = credentialEntry{Key: cred.Key, Value: string(plaintext)}
		}
		resp.Credentials = entries
	}

	jsonOK(w, resp)
}

type credentialsDeleteRequest struct {
	Vault string   `json:"vault"`
	Keys  []string `json:"keys"`
}

type credentialsDeleteResponse struct {
	Deleted []string `json:"deleted"`
}

func (s *Server) handleCredentialsDelete(w http.ResponseWriter, r *http.Request) {
	var req credentialsDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}
	if len(req.Keys) == 0 {
		jsonError(w, http.StatusBadRequest, "Keys list is required")
		return
	}

	ctx := r.Context()

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}

	// Deleting credentials requires member+ role.
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	for _, key := range req.Keys {
		if !broker.CredentialKeyPattern.MatchString(key) {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid credential key %q: must be SCREAMING_SNAKE_CASE (e.g. STRIPE_KEY)", key))
			return
		}
	}

	var deleted []string
	for _, key := range req.Keys {
		if err := s.store.DeleteCredential(ctx, ns.ID, key); err != nil {
			jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to delete credential %q", key))
			return
		}
		deleted = append(deleted, key)
	}

	jsonOK(w, credentialsDeleteResponse{Deleted: deleted})
}

// listCredentialKeys returns the key names of all credentials in the given vault.
// Returns an empty (non-nil) slice on error so JSON serializes as [].
func (s *Server) listCredentialKeys(ctx context.Context, vaultID string) []string {
	creds, err := s.store.ListCredentials(ctx, vaultID)
	if err != nil || len(creds) == 0 {
		return []string{}
	}
	keys := make([]string, len(creds))
	for i, cred := range creds {
		keys[i] = cred.Key
	}
	return keys
}
