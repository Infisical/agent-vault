package server

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

const oauthStateTTL = 10 * time.Minute

var oauthLoginLimiter = newSlidingWindowLimiter(5*time.Minute, 20, 10000) // 20 OAuth initiations per IP per 5 min

// handleOAuthProviders returns the list of enabled OAuth providers.
func (s *Server) handleOAuthProviders(w http.ResponseWriter, r *http.Request) {
	type providerInfo struct {
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
	}

	var providers []providerInfo
	for _, p := range s.oauthProviders {
		if p.Enabled() {
			providers = append(providers, providerInfo{Name: p.Name(), DisplayName: p.DisplayName()})
		}
	}
	if providers == nil {
		providers = []providerInfo{} // ensure JSON [] not null
	}

	jsonOK(w, map[string]interface{}{"providers": providers})
}

// handleOAuthLogin initiates an OAuth flow by redirecting to the provider.
func (s *Server) handleOAuthLogin(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	provider, ok := s.oauthProviders[providerName]
	if !ok || !provider.Enabled() {
		jsonError(w, http.StatusNotFound, "Unknown OAuth provider")
		return
	}

	ip := clientIP(r)
	if !oauthLoginLimiter.allow(ip) {
		jsonError(w, http.StatusTooManyRequests, "Too many login attempts, try again later")
		return
	}

	// Generate CSRF state, PKCE code verifier, and OIDC nonce.
	state, err := generateRandomHex(32)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to generate state")
		return
	}
	codeVerifier, err := oauth.GenerateCodeVerifier()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to generate code verifier")
		return
	}
	nonce, err := generateRandomHex(32)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to generate nonce")
		return
	}

	// Validate redirect URL.
	redirectURL := r.URL.Query().Get("redirect")
	if redirectURL != "" && !isValidOAuthRedirect(redirectURL) {
		redirectURL = ""
	}

	// Determine mode: "login" (default) or "connect" (authenticated linking).
	mode := "login"
	var userID string
	if r.URL.Query().Get("mode") == "connect" {
		sess := sessionFromContext(r.Context())
		if sess == nil || sess.UserID == "" {
			jsonError(w, http.StatusUnauthorized, "Authentication required for connect mode")
			return
		}
		mode = "connect"
		userID = sess.UserID
	}

	// Store state in DB.
	stateHash := fmt.Sprintf("%x", sha256.Sum256([]byte(state)))
	_, err = s.store.CreateOAuthState(r.Context(), stateHash, codeVerifier, nonce, redirectURL, mode, userID, time.Now().Add(oauthStateTTL))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to store OAuth state")
		return
	}

	// Redirect to provider.
	authURL := provider.AuthCodeURL(state, codeVerifier, nonce)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOAuthCallback handles the OAuth provider's callback.
func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	providerName := r.PathValue("provider")
	provider, ok := s.oauthProviders[providerName]
	if !ok || !provider.Enabled() {
		s.oauthErrorRedirect(w, r, "unknown_provider")
		return
	}

	// Lazy expiration of old states.
	_, _ = s.store.ExpireOAuthStates(ctx, time.Now())

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		s.oauthErrorRedirect(w, r, "invalid_request")
		return
	}

	// Look up and consume state.
	stateHash := fmt.Sprintf("%x", sha256.Sum256([]byte(state)))
	oauthState, err := s.store.GetOAuthStateByHash(ctx, stateHash)
	if err != nil {
		s.oauthErrorRedirect(w, r, "expired")
		return
	}
	if time.Now().After(oauthState.ExpiresAt) {
		_ = s.store.DeleteOAuthState(ctx, oauthState.ID)
		s.oauthErrorRedirect(w, r, "expired")
		return
	}

	// Single-use: consume the state. If deletion fails, reject the request
	// to preserve the single-use guarantee.
	if err := s.store.DeleteOAuthState(ctx, oauthState.ID); err != nil {
		fmt.Fprintf(os.Stderr, "[agent-vault] failed to consume OAuth state: %v\n", err)
		s.oauthErrorRedirect(w, r, "expired")
		return
	}

	// Exchange code for user info (nonce binds the ID token to this request).
	userInfo, err := provider.Exchange(ctx, code, oauthState.CodeVerifier, oauthState.Nonce)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[agent-vault] OAuth exchange error: %v\n", err)
		s.oauthErrorRedirect(w, r, "exchange_failed")
		return
	}

	if !userInfo.EmailVerified {
		s.oauthErrorRedirect(w, r, "email_not_verified")
		return
	}

	// Branch on mode.
	if oauthState.Mode == "connect" {
		s.handleOAuthCallbackConnect(w, r, oauthState, provider, userInfo)
		return
	}

	// Mode: "login" — sign in or register.
	s.handleOAuthCallbackLogin(w, r, provider, userInfo, oauthState.RedirectURL)
}

func (s *Server) handleOAuthCallbackLogin(w http.ResponseWriter, r *http.Request, provider oauth.Provider, userInfo *oauth.UserInfo, redirectURL string) {
	ctx := r.Context()

	// Check if this OAuth identity is already linked to a user.
	existing, err := s.store.GetOAuthAccount(ctx, provider.Name(), userInfo.ProviderUserID)
	if err == nil && existing != nil {
		// Returning OAuth user — load user and create session.
		user, err := s.store.GetUserByID(ctx, existing.UserID)
		if err != nil || user == nil || !user.IsActive {
			s.oauthErrorRedirect(w, r, "signin_failed")
			return
		}
		s.createOAuthSession(w, r, user, redirectURL)
		return
	}

	// First-time OAuth login — check if email already exists.
	existingUser, _ := s.store.GetUserByEmail(ctx, userInfo.Email)
	if existingUser != nil {
		// Email taken by an existing account. Reject with generic message.
		s.oauthErrorRedirect(w, r, "signin_failed")
		return
	}

	// Owner must be created with email/password — reject if no users exist.
	userCount, _ := s.store.CountUsers(ctx)
	if userCount == 0 {
		s.oauthErrorRedirect(w, r, "owner_required")
		return
	}

	// Check domain restriction. Use generic error to avoid leaking policy info.
	if msg := s.checkEmailDomain(ctx, userInfo.Email); msg != "" {
		s.oauthErrorRedirect(w, r, "signin_failed")
		return
	}

	// Block new OAuth signups when invite-only mode is enabled.
	if s.isInviteOnly(ctx) {
		s.oauthErrorRedirect(w, r, "signin_failed")
		return
	}

	// Atomically create new OAuth user + link identity.
	newUser, _, err := s.store.CreateOAuthUserAndAccount(ctx, userInfo.Email, "member", provider.Name(), userInfo.ProviderUserID, userInfo.Email, userInfo.Name, userInfo.AvatarURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[agent-vault] OAuth user creation error: %v\n", err)
		s.oauthErrorRedirect(w, r, "signin_failed")
		return
	}

	s.createOAuthSession(w, r, newUser, redirectURL)
}

func (s *Server) handleOAuthCallbackConnect(w http.ResponseWriter, r *http.Request, oauthState *store.OAuthState, provider oauth.Provider, userInfo *oauth.UserInfo) {
	ctx := r.Context()

	// Load the authenticated user from the stored user ID.
	user, err := s.store.GetUserByID(ctx, oauthState.UserID)
	if err != nil || user == nil {
		s.oauthErrorRedirect(w, r, "signin_failed")
		return
	}

	// Validate that the OAuth email matches the user's account email.
	if !strings.EqualFold(user.Email, userInfo.Email) {
		s.oauthErrorRedirect(w, r, "email_mismatch")
		return
	}

	// Check this provider identity isn't already linked to another user.
	existingOAuth, _ := s.store.GetOAuthAccount(ctx, provider.Name(), userInfo.ProviderUserID)
	if existingOAuth != nil {
		s.oauthErrorRedirect(w, r, "already_linked")
		return
	}

	// Check user doesn't already have this provider connected.
	existingByUser, _ := s.store.GetOAuthAccountByUser(ctx, user.ID, provider.Name())
	if existingByUser != nil {
		s.oauthErrorRedirect(w, r, "already_linked")
		return
	}

	// Link the OAuth identity.
	_, err = s.store.CreateOAuthAccount(ctx, user.ID, provider.Name(), userInfo.ProviderUserID, userInfo.Email, userInfo.Name, userInfo.AvatarURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[agent-vault] OAuth connect error: %v\n", err)
		s.oauthErrorRedirect(w, r, "connect_failed")
		return
	}

	// Redirect to account settings.
	target := "/account/settings"
	if oauthState.RedirectURL != "" && isValidOAuthRedirect(oauthState.RedirectURL) {
		target = oauthState.RedirectURL
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// handleOAuthConnect initiates an OAuth flow in "connect" mode for authenticated users.
func (s *Server) handleOAuthConnect(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	provider, ok := s.oauthProviders[providerName]
	if !ok || !provider.Enabled() {
		jsonError(w, http.StatusNotFound, "Unknown OAuth provider")
		return
	}

	sess := sessionFromContext(r.Context())
	if sess == nil || sess.UserID == "" {
		jsonError(w, http.StatusUnauthorized, "User session required")
		return
	}

	// Check if already connected.
	existing, _ := s.store.GetOAuthAccountByUser(r.Context(), sess.UserID, providerName)
	if existing != nil {
		jsonError(w, http.StatusConflict, "Provider already connected")
		return
	}

	// Generate state + PKCE and store in "connect" mode.
	state, err := generateRandomHex(32)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to generate state")
		return
	}
	codeVerifier, err := oauth.GenerateCodeVerifier()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to generate code verifier")
		return
	}
	nonce, err := generateRandomHex(32)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to generate nonce")
		return
	}

	stateHash := fmt.Sprintf("%x", sha256.Sum256([]byte(state)))
	_, err = s.store.CreateOAuthState(r.Context(), stateHash, codeVerifier, nonce, "", "connect", sess.UserID, time.Now().Add(oauthStateTTL))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to store OAuth state")
		return
	}

	authURL := provider.AuthCodeURL(state, codeVerifier, nonce)
	jsonOK(w, map[string]string{"redirect_url": authURL})
}

// handleOAuthDisconnect removes an OAuth provider from an authenticated user.
func (s *Server) handleOAuthDisconnect(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	sess := sessionFromContext(r.Context())
	if sess == nil || sess.UserID == "" {
		jsonError(w, http.StatusUnauthorized, "User session required")
		return
	}

	ctx := r.Context()
	user, err := s.store.GetUserByID(ctx, sess.UserID)
	if err != nil || user == nil {
		jsonError(w, http.StatusInternalServerError, "Failed to load user")
		return
	}

	// Cannot disconnect if the user has no password (would lock them out).
	if user.PasswordHash == nil {
		jsonError(w, http.StatusConflict, "Cannot disconnect: no password set. Set a password first.")
		return
	}

	if err := s.store.DeleteOAuthAccount(ctx, user.ID, providerName); err != nil {
		jsonError(w, http.StatusNotFound, "Provider not connected")
		return
	}

	jsonOK(w, map[string]string{"message": "Provider disconnected"})
}

// createOAuthSession creates a session for an OAuth user and redirects.
func (s *Server) createOAuthSession(w http.ResponseWriter, r *http.Request, user *store.User, redirectURL string) {
	session, err := s.store.CreateSession(r.Context(), user.ID, time.Now().Add(sessionTTL))
	if err != nil {
		s.oauthErrorRedirect(w, r, "session_failed")
		return
	}

	http.SetCookie(w, sessionCookie(r, s.baseURL, session.ID, int(sessionTTL.Seconds())))

	target := "/vaults"
	if redirectURL != "" && isValidOAuthRedirect(redirectURL) {
		target = redirectURL
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// oauthErrorRedirect redirects to the frontend OAuth error page.
func (s *Server) oauthErrorRedirect(w http.ResponseWriter, r *http.Request, errorCode string) {
	http.Redirect(w, r, "/oauth/callback?"+url.Values{"error": {errorCode}}.Encode(), http.StatusFound)
}

// isValidOAuthRedirect validates that a redirect URL is a safe relative path.
func isValidOAuthRedirect(u string) bool {
	if u == "" {
		return false
	}
	if !strings.HasPrefix(u, "/") {
		return false
	}
	// Reject protocol-relative URLs and double slashes.
	if strings.HasPrefix(u, "//") {
		return false
	}
	// Reject URLs with scheme.
	if strings.Contains(u, "://") {
		return false
	}
	return true
}

// generateRandomHex generates n random bytes and returns them as a hex string.
func generateRandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(crand.Reader, b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
