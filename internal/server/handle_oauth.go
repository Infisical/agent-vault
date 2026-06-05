package server

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

const oauthStateTTL = 10 * time.Minute

const oauthSecretSentinel = "••••••••"

type oauthConnectRequest struct {
	Vault            string `json:"vault"`
	Key              string `json:"key"`
	AuthorizationURL string `json:"authorization_url"`
	TokenURL         string `json:"token_url"`
	ClientID         string `json:"client_id"`
	ClientSecret     string `json:"client_secret,omitempty"`
	Scopes           string `json:"scopes,omitempty"`
	ScopeSeparator   string `json:"scope_separator,omitempty"`
	DisablePKCE      bool   `json:"disable_pkce,omitempty"`
	TokenAuthMethod  string `json:"token_auth_method,omitempty"`
}

func (s *Server) handleOAuthConnect(w http.ResponseWriter, r *http.Request) {
	var req oauthConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}
	if req.Key == "" {
		jsonError(w, http.StatusBadRequest, "\"key\" is required")
		return
	}
	if !broker.CredentialKeyPattern.MatchString(req.Key) {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid credential key %q: must be SCREAMING_SNAKE_CASE (e.g. GITHUB_TOKEN)", req.Key))
		return
	}
	if req.AuthorizationURL == "" {
		jsonError(w, http.StatusBadRequest, "\"authorization_url\" is required for the connect flow")
		return
	}
	if !isValidHTTPURL(req.AuthorizationURL) {
		jsonError(w, http.StatusBadRequest, "\"authorization_url\" must be an https:// or http:// URL")
		return
	}
	if !isValidHTTPURL(req.TokenURL) {
		jsonError(w, http.StatusBadRequest, "\"token_url\" must be an https:// or http:// URL")
		return
	}
	if req.TokenURL == "" {
		jsonError(w, http.StatusBadRequest, "\"token_url\" is required")
		return
	}
	if req.ClientID == "" {
		jsonError(w, http.StatusBadRequest, "\"client_id\" is required")
		return
	}

	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}
	if !s.assertBuiltinCredentialStore(w, ctx, ns.ID, ns.Name) {
		return
	}

	// Lazily expire old states.
	_, _ = s.store.ExpireCredentialOAuthStates(ctx, time.Now())

	// Handle client_secret: sentinel = keep current, empty = clear, other = set new.
	var clientSecretCT, clientSecretNonce []byte
	if req.ClientSecret == oauthSecretSentinel {
		existing, _ := s.store.GetCredentialOAuth(ctx, ns.ID, req.Key)
		if existing != nil {
			clientSecretCT = existing.ClientSecretCT
			clientSecretNonce = existing.ClientSecretNonce
		}
	} else if req.ClientSecret != "" {
		clientSecretCT, clientSecretNonce, err = crypto.Encrypt([]byte(req.ClientSecret), s.encKey)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Encryption failed")
			return
		}
	}

	scopeSep := req.ScopeSeparator
	if scopeSep == "" {
		scopeSep = " "
	}
	tokenAuthMethod := req.TokenAuthMethod
	if tokenAuthMethod == "" {
		tokenAuthMethod = "client_secret_post"
	}

	if err := s.store.SetCredentialOAuth(ctx, &store.CredentialOAuth{
		VaultID:          ns.ID,
		CredentialKey:    req.Key,
		AuthorizationURL: req.AuthorizationURL,
		TokenURL:         req.TokenURL,
		ClientID:         req.ClientID,
		ClientSecretCT:   clientSecretCT,
		ClientSecretNonce: clientSecretNonce,
		Scopes:           req.Scopes,
		ScopeSeparator:   scopeSep,
		DisablePKCE:      req.DisablePKCE,
		TokenAuthMethod:  tokenAuthMethod,
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to save OAuth configuration")
		return
	}

	// Generate PKCE verifier and state.
	codeVerifier, err := oauth.GenerateCodeVerifier()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to generate PKCE verifier")
		return
	}
	codeChallenge := oauth.CodeChallengeS256(codeVerifier)

	stateRaw := oauthPrefixedToken("av_oast_")
	stateHash := hashOAuthState(stateRaw)

	now := time.Now().UTC()
	if err := s.store.CreateCredentialOAuthState(ctx, &store.CredentialOAuthState{
		ID:            oauthPublicID(),
		StateHash:     stateHash,
		CodeVerifier:  codeVerifier,
		VaultID:       ns.ID,
		CredentialKey: req.Key,
		RedirectURL:   "",
		CreatedAt:     now,
		ExpiresAt:     now.Add(oauthStateTTL),
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create OAuth state")
		return
	}

	redirectURI := s.baseURL + "/v1/oauth/callback"
	authURL := oauth.BuildAuthorizationURL(
		req.AuthorizationURL, req.ClientID, redirectURI,
		stateRaw, codeChallenge, req.Scopes, scopeSep, req.DisablePKCE,
	)

	jsonOK(w, map[string]string{"authorization_url": authURL})
}

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	stateRaw := r.URL.Query().Get("state")

	if code == "" || stateRaw == "" {
		errMsg := r.URL.Query().Get("error_description")
		if errMsg == "" {
			errMsg = r.URL.Query().Get("error")
		}
		if errMsg == "" {
			errMsg = "Missing code or state parameter"
		}
		s.redirectOAuthComplete(w, r, "", "", "error", errMsg)
		return
	}

	ctx := r.Context()
	stateHash := hashOAuthState(stateRaw)

	st, err := s.store.GetCredentialOAuthStateByHash(ctx, stateHash)
	if err != nil {
		s.redirectOAuthComplete(w, r, "", "", "error", "Invalid or expired OAuth state")
		return
	}

	if time.Now().After(st.ExpiresAt) {
		_ = s.store.DeleteCredentialOAuthState(ctx, st.ID)
		s.redirectOAuthComplete(w, r, "", "", "error", "OAuth state expired — please try again")
		return
	}

	_ = s.store.DeleteCredentialOAuthState(ctx, st.ID)

	// Load OAuth config for token exchange.
	oauthCfg, err := s.store.GetCredentialOAuth(ctx, st.VaultID, st.CredentialKey)
	if err != nil {
		s.redirectOAuthComplete(w, r, "", "", "error", "OAuth configuration not found")
		return
	}

	var clientSecret string
	if len(oauthCfg.ClientSecretCT) > 0 {
		cs, err := crypto.Decrypt(oauthCfg.ClientSecretCT, oauthCfg.ClientSecretNonce, s.encKey)
		if err != nil {
			s.redirectOAuthComplete(w, r, "", "", "error", "Failed to decrypt client secret")
			return
		}
		clientSecret = string(cs)
	}

	redirectURI := s.baseURL + "/v1/oauth/callback"
	tok, err := oauth.Exchange(ctx, oauth.ExchangeConfig{
		TokenURL:        oauthCfg.TokenURL,
		ClientID:        oauthCfg.ClientID,
		ClientSecret:    clientSecret,
		Code:            code,
		RedirectURI:     redirectURI,
		CodeVerifier:    st.CodeVerifier,
		TokenAuthMethod: oauthCfg.TokenAuthMethod,
	})
	if err != nil {
		s.redirectOAuthComplete(w, r, "", "", "error", fmt.Sprintf("Token exchange failed: %v", err))
		return
	}

	accessCT, accessNonce, err := crypto.Encrypt([]byte(tok.AccessToken), s.encKey)
	if err != nil {
		s.redirectOAuthComplete(w, r, "", "", "error", "Failed to encrypt access token")
		return
	}

	var refreshCT, refreshNonce []byte
	if tok.RefreshToken != "" {
		refreshCT, refreshNonce, err = crypto.Encrypt([]byte(tok.RefreshToken), s.encKey)
		if err != nil {
			s.redirectOAuthComplete(w, r, "", "", "error", "Failed to encrypt refresh token")
			return
		}
	}

	var expiresAt *time.Time
	if !tok.ExpiresAt.IsZero() {
		expiresAt = &tok.ExpiresAt
	}

	if err := s.store.UpdateCredentialOAuthTokens(ctx, st.VaultID, st.CredentialKey, accessCT, accessNonce, refreshCT, refreshNonce, expiresAt); err != nil {
		s.redirectOAuthComplete(w, r, "", "", "error", "Failed to store tokens")
		return
	}

	// Resolve vault name for the redirect.
	vaultName := ""
	if v, err := s.store.GetVaultByID(ctx, st.VaultID); err == nil && v != nil {
		vaultName = v.Name
	}

	s.redirectOAuthComplete(w, r, vaultName, st.CredentialKey, "success", "")
}

func (s *Server) handleOAuthStatus(w http.ResponseWriter, r *http.Request) {
	vault := r.URL.Query().Get("vault")
	key := r.URL.Query().Get("key")
	if vault == "" {
		vault = store.DefaultVault
	}
	if key == "" {
		jsonError(w, http.StatusBadRequest, "\"key\" query parameter is required")
		return
	}

	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", vault))
		return
	}
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	oauthCfg, err := s.store.GetCredentialOAuth(ctx, ns.ID, key)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jsonError(w, http.StatusNotFound, fmt.Sprintf("OAuth credential %q not found", key))
			return
		}
		jsonError(w, http.StatusInternalServerError, "Failed to read OAuth state")
		return
	}

	type statusResponse struct {
		Connected   bool    `json:"connected"`
		ConnectedAt *string `json:"connected_at,omitempty"`
		LastError   *string `json:"last_error,omitempty"`
	}

	resp := statusResponse{Connected: oauthCfg.ConnectedAt != nil}
	if oauthCfg.ConnectedAt != nil {
		t := oauthCfg.ConnectedAt.Format(time.RFC3339)
		resp.ConnectedAt = &t
	}
	if oauthCfg.LastRefreshError != "" {
		resp.LastError = &oauthCfg.LastRefreshError
	}

	jsonOK(w, resp)
}

type oauthTokenUploadRequest struct {
	Vault           string `json:"vault"`
	Key             string `json:"key"`
	AccessToken     string `json:"access_token,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	TokenURL        string `json:"token_url,omitempty"`
	ClientID        string `json:"client_id,omitempty"`
	ClientSecret    string `json:"client_secret,omitempty"`
	TokenAuthMethod string `json:"token_auth_method,omitempty"`
}

func (s *Server) handleOAuthTokenUpload(w http.ResponseWriter, r *http.Request) {
	var req oauthTokenUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}
	if req.Key == "" {
		jsonError(w, http.StatusBadRequest, "\"key\" is required")
		return
	}
	if !broker.CredentialKeyPattern.MatchString(req.Key) {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid credential key %q: must be SCREAMING_SNAKE_CASE (e.g. GITHUB_TOKEN)", req.Key))
		return
	}
	if req.AccessToken == "" && req.RefreshToken == "" {
		jsonError(w, http.StatusBadRequest, "\"access_token\" or \"refresh_token\" is required")
		return
	}

	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}
	if !s.assertBuiltinCredentialStore(w, ctx, ns.ID, ns.Name) {
		return
	}

	// Resolve OAuth config: use request fields, fall back to existing config.
	existing, _ := s.store.GetCredentialOAuth(ctx, ns.ID, req.Key)
	tokenURL := req.TokenURL
	clientID := req.ClientID
	clientSecret := req.ClientSecret
	tokenAuthMethod := req.TokenAuthMethod
	if existing != nil {
		if tokenURL == "" {
			tokenURL = existing.TokenURL
		}
		if clientID == "" {
			clientID = existing.ClientID
		}
		if clientSecret == "" && len(existing.ClientSecretCT) > 0 {
			cs, err := crypto.Decrypt(existing.ClientSecretCT, existing.ClientSecretNonce, s.encKey)
			if err == nil {
				clientSecret = string(cs)
			}
		}
		if tokenAuthMethod == "" {
			tokenAuthMethod = existing.TokenAuthMethod
		}
	}

	// Handle sentinel values for edit mode.
	isAccessSentinel := req.AccessToken == oauthSecretSentinel
	isRefreshSentinel := req.RefreshToken == oauthSecretSentinel
	hasNewRefreshToken := req.RefreshToken != "" && !isRefreshSentinel

	// If a new (non-sentinel) refresh token is provided, validate it by
	// refreshing immediately. This gives confidence the setup works and
	// provides the real expires_at.
	if hasNewRefreshToken && tokenURL != "" && tokenURL != "manual" {
		tok, refreshErr := oauth.Refresh(ctx, oauth.RefreshConfig{
			TokenURL:        tokenURL,
			ClientID:        clientID,
			ClientSecret:    clientSecret,
			RefreshToken:    req.RefreshToken,
			TokenAuthMethod: tokenAuthMethod,
		})
		if refreshErr != nil {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("Refresh token validation failed: %v", refreshErr))
			return
		}

		// Refresh succeeded — use the fresh tokens.
		accessCT, accessNonce, err := crypto.Encrypt([]byte(tok.AccessToken), s.encKey)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Encryption failed")
			return
		}
		refreshToken := req.RefreshToken
		if tok.RefreshToken != "" {
			refreshToken = tok.RefreshToken
		}
		refreshCT, refreshNonce, err := crypto.Encrypt([]byte(refreshToken), s.encKey)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Encryption failed")
			return
		}

		var clientSecretCT, clientSecretNonce []byte
		if clientSecret != "" {
			clientSecretCT, clientSecretNonce, err = crypto.Encrypt([]byte(clientSecret), s.encKey)
			if err != nil {
				jsonError(w, http.StatusInternalServerError, "Encryption failed")
				return
			}
		}

		if tokenURL == "" {
			tokenURL = "manual"
		}
		if clientID == "" {
			clientID = "manual"
		}
		oauthRow := &store.CredentialOAuth{
			VaultID:           ns.ID,
			CredentialKey:     req.Key,
			TokenURL:          tokenURL,
			ClientID:          clientID,
			ClientSecretCT:    clientSecretCT,
			ClientSecretNonce: clientSecretNonce,
			TokenAuthMethod:   tokenAuthMethod,
		}
		if existing != nil {
			oauthRow.AuthorizationURL = existing.AuthorizationURL
			oauthRow.Scopes = existing.Scopes
			oauthRow.ScopeSeparator = existing.ScopeSeparator
			oauthRow.DisablePKCE = existing.DisablePKCE
		}
		_ = s.store.SetCredentialOAuth(ctx, oauthRow)

		var expiresAt *time.Time
		if !tok.ExpiresAt.IsZero() {
			expiresAt = &tok.ExpiresAt
		}
		if err := s.store.UpdateCredentialOAuthTokens(ctx, ns.ID, req.Key, accessCT, accessNonce, refreshCT, refreshNonce, expiresAt); err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to store tokens")
			return
		}

		now := time.Now().UTC().Format(time.RFC3339)
		jsonOK(w, map[string]interface{}{"connected": true, "connected_at": now})
		return
	}

	// No new refresh token — store access token as-is (edit mode or access-only upload).
	var accessCT, accessNonce []byte
	if isAccessSentinel {
		cred, _ := s.store.GetCredential(ctx, ns.ID, req.Key)
		if cred != nil && len(cred.Ciphertext) > 0 {
			plaintext, decErr := crypto.Decrypt(cred.Ciphertext, cred.Nonce, s.encKey)
			if decErr == nil && string(plaintext) != "" {
				accessCT = cred.Ciphertext
				accessNonce = cred.Nonce
			}
		}
		if len(accessCT) == 0 && !hasNewRefreshToken {
			jsonError(w, http.StatusBadRequest, "No existing access token to preserve — provide an access_token or refresh_token")
			return
		}
	} else if req.AccessToken != "" {
		accessCT, accessNonce, err = crypto.Encrypt([]byte(req.AccessToken), s.encKey)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Encryption failed")
			return
		}
	}

	var refreshCT, refreshNonce []byte
	if isRefreshSentinel && existing != nil {
		refreshCT = existing.RefreshTokenCT
		refreshNonce = existing.RefreshTokenNonce
	} else if hasNewRefreshToken {
		refreshCT, refreshNonce, err = crypto.Encrypt([]byte(req.RefreshToken), s.encKey)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Encryption failed")
			return
		}
	}

	// Create credential_oauth row if needed.
	if existing == nil {
		if tokenURL == "" {
			tokenURL = "manual"
		}
		if clientID == "" {
			clientID = "manual"
		}
		_ = s.store.SetCredentialOAuth(ctx, &store.CredentialOAuth{
			VaultID:       ns.ID,
			CredentialKey: req.Key,
			TokenURL:      tokenURL,
			ClientID:      clientID,
		})
	}

	// Preserve existing token_expires_at when not uploading a new refresh token.
	var existingExpiresAt *time.Time
	if existing != nil {
		existingExpiresAt = existing.TokenExpiresAt
	}
	if err := s.store.UpdateCredentialOAuthTokens(ctx, ns.ID, req.Key, accessCT, accessNonce, refreshCT, refreshNonce, existingExpiresAt); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to store tokens")
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	jsonOK(w, map[string]interface{}{"connected": true, "connected_at": now})
}

func (s *Server) redirectOAuthComplete(w http.ResponseWriter, r *http.Request, vault, key, status, message string) {
	u := s.baseURL + "/oauth/complete?status=" + url.QueryEscape(status)
	if vault != "" {
		u += "&vault=" + url.QueryEscape(vault)
	}
	if key != "" {
		u += "&key=" + url.QueryEscape(key)
	}
	if message != "" {
		u += "&message=" + url.QueryEscape(message)
	}
	http.Redirect(w, r, u, http.StatusFound)
}


func isValidHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

func hashOAuthState(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func oauthPrefixedToken(prefix string) string {
	var b [32]byte
	if _, err := io.ReadFull(cryptorand.Reader, b[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return prefix + hex.EncodeToString(b[:])
}

func oauthPublicID() string {
	var b [10]byte
	if _, err := io.ReadFull(cryptorand.Reader, b[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
