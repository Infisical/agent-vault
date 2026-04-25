package server

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/store"
)

const emailVerificationTTL = 15 * time.Minute

const maxPendingVerifications = 3

// generateAndSendVerificationCode creates a new 6-digit verification code for
// the given email and sends it via email (or logs to stderr if SMTP is not configured).
func (s *Server) generateAndSendVerificationCode(ctx context.Context, email string) (bool, error) {
	// Rate limit verification codes per email.
	pendingCount, err := s.store.CountPendingEmailVerifications(ctx, email)
	if err != nil {
		return false, fmt.Errorf("failed to count pending verifications: %w", err)
	}
	if pendingCount >= maxPendingVerifications {
		return false, errTooManyPendingCodes
	}

	// Generate 6-digit verification code (uniform distribution via rejection sampling).
	codeInt, _ := crand.Int(crand.Reader, big.NewInt(1_000_000))
	code := fmt.Sprintf("%06d", codeInt.Int64())

	_, err = s.store.CreateEmailVerification(ctx, email, code, time.Now().Add(emailVerificationTTL))
	if err != nil {
		return false, fmt.Errorf("failed to create verification: %w", err)
	}

	// Send verification code via email or log to stderr.
	emailSent := false
	if s.notifier.Enabled() {
		body := strings.Replace(verificationCodeEmailHTML, "{{CODE}}", html.EscapeString(code), 1)
		if err := s.notifier.SendHTMLMail([]string{email}, "Agent Vault verification code", body); err != nil {
			fmt.Fprintf(os.Stderr, "[agent-vault] Failed to send verification email to %s: %v\n", email, err)
			fmt.Fprintf(os.Stderr, "[agent-vault] Email verification code for %s: %s\n", email, code)
		} else {
			emailSent = true
		}
	} else {
		fmt.Fprintf(os.Stderr, "[agent-vault] Email verification code for %s: %s\n", email, code)
	}

	return emailSent, nil
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email       string `json:"email"`
		Password    string `json:"password"`
		DeviceLabel string `json:"device_label,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if err := auth.ValidateEmail(req.Email); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Password) < 8 {
		jsonError(w, http.StatusBadRequest, "Password must be at least 8 characters")
		return
	}

	ctx := r.Context()

	// Check domain and invite-only restrictions (skip for first user — owner can set any email).
	userCount, _ := s.store.CountUsers(ctx)
	if userCount > 0 {
		if msg := s.checkEmailDomain(ctx, req.Email); msg != "" {
			jsonError(w, http.StatusForbidden, msg)
			return
		}
		if s.isInviteOnly(ctx) {
			jsonError(w, http.StatusForbidden, "This instance is invite-only; accounts can only be created through an invite")
			return
		}
	}

	// Check if email is already taken.
	// Return a uniform response to prevent email enumeration.
	existing, _ := s.store.GetUserByEmail(ctx, req.Email)
	if existing != nil && existing.IsActive {
		// Uniform response — don't reveal that the email is already registered.
		jsonCreated(w, map[string]interface{}{
			"email":                 req.Email,
			"requires_verification": true,
			"email_sent":            s.notifier.Enabled(),
			"message":               "If this email is not already registered, a verification code has been sent.",
		})
		return
	}

	hash, salt, kdfParams, err := auth.HashUserPassword([]byte(req.Password))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	// If an inactive user exists, update their password and resend verification.
	if existing != nil && !existing.IsActive {
		if err := s.store.UpdateUserPassword(ctx, existing.ID, hash, salt, kdfParams.Time, kdfParams.Memory, kdfParams.Threads); err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to update account")
			return
		}

		emailSent, err := s.generateAndSendVerificationCode(ctx, req.Email)
		if errors.Is(err, errTooManyPendingCodes) {
			jsonError(w, http.StatusTooManyRequests, "Too many pending verification codes")
			return
		}
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to create verification")
			return
		}

		msg := "Account updated. Ask your Agent Vault instance owner for the verification code."
		if emailSent {
			msg = "Account updated. Check your email for a new verification code."
		}

		jsonCreated(w, map[string]interface{}{
			"email":                 existing.Email,
			"requires_verification": true,
			"email_sent":            emailSent,
			"message":               msg,
		})
		return
	}

	// Try to register as the first user (atomic: count + create + activate + grant).
	defaultVault, _ := s.store.GetVault(ctx, store.DefaultVault)
	var defaultVaultID string
	if defaultVault != nil {
		defaultVaultID = defaultVault.ID
	}
	user, err := s.store.RegisterFirstUser(ctx, req.Email, hash, salt, defaultVaultID, kdfParams.Time, kdfParams.Memory, kdfParams.Threads)
	if err == nil {
		// First user: owner created successfully.
		s.initialized = true

		// Auto-login: token + expires_at are returned alongside the
		// cookie so non-cookie clients (the CLI) can persist the
		// session without a follow-up /v1/auth/login.
		params := newUserSessionParams(r, user.ID)
		params.DeviceLabel = truncateDeviceLabel(req.DeviceLabel)
		session, err := s.store.CreateUserSession(ctx, params)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to create session")
			return
		}
		http.SetCookie(w, sessionCookie(r, s.baseURL, session.ID, int(userSessionAbsoluteTTL.Seconds())))

		jsonCreated(w, registerResponse{
			Email:                user.Email,
			Role:                 "owner",
			RequiresVerification: false,
			Authenticated:        true,
			Message:              "Owner account created.",
			Token:                session.ID,
			ExpiresAt:            formatExpiresAt(session.ExpiresAt),
		})
		return
	}
	if err != store.ErrNotFirstUser {
		jsonError(w, http.StatusInternalServerError, "Failed to create owner account")
		return
	}

	// Not the first user: re-check domain restriction. This covers the TOCTOU
	// race where two requests both saw CountUsers==0 and skipped the earlier check.
	if msg := s.checkEmailDomain(ctx, req.Email); msg != "" {
		jsonError(w, http.StatusForbidden, msg)
		return
	}

	// Create as inactive member, require email verification.
	_, err = s.store.CreateUser(ctx, req.Email, hash, salt, "member", kdfParams.Time, kdfParams.Memory, kdfParams.Threads)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	emailSent, err := s.generateAndSendVerificationCode(ctx, req.Email)
	if errors.Is(err, errTooManyPendingCodes) {
		jsonError(w, http.StatusTooManyRequests, "Too many pending verification codes")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create verification")
		return
	}

	msg := "Account created. Ask your Agent Vault instance owner for the verification code."
	if emailSent {
		msg = "Account created. Check your email for a verification code."
	}

	jsonCreated(w, map[string]interface{}{
		"email":                 req.Email,
		"requires_verification": true,
		"email_sent":            emailSent,
		"message":               msg,
	})
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email       string `json:"email"`
		Code        string `json:"code"`
		DeviceLabel string `json:"device_label,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Email == "" || req.Code == "" {
		jsonError(w, http.StatusBadRequest, "Email and code are required")
		return
	}

	ctx := r.Context()

	// Rate limit verification attempts per email.
	verifyKey := "v:" + req.Email
	if !s.rateLimit.FailureCheck(ratelimit.TierVerifyFailure, verifyKey) {
		jsonError(w, http.StatusTooManyRequests, "Too many failed verification attempts; request a new code")
		return
	}

	ev, err := s.store.GetPendingEmailVerification(ctx, req.Email, req.Code)
	if err != nil || ev == nil {
		s.rateLimit.FailureRecord(ratelimit.TierVerifyFailure, verifyKey)
		jsonError(w, http.StatusBadRequest, "Invalid or expired verification code")
		return
	}

	user, err := s.store.GetUserByEmail(ctx, req.Email)
	if err != nil || user == nil {
		jsonError(w, http.StatusNotFound, "User not found")
		return
	}

	if user.IsActive {
		jsonError(w, http.StatusConflict, "Account is already verified")
		return
	}

	if err := s.store.MarkEmailVerificationUsed(ctx, ev.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to mark verification used")
		return
	}

	if err := s.store.ActivateUser(ctx, user.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to activate account")
		return
	}

	// Reset rate limit on successful verification.
	s.rateLimit.FailureReset(ratelimit.TierVerifyFailure, verifyKey)

	// Auto-login: token + expires_at are returned alongside the cookie
	// so non-cookie clients (the CLI) can persist the session without a
	// follow-up /v1/auth/login. Mirrors handleRegister's first-user path.
	params := newUserSessionParams(r, user.ID)
	params.DeviceLabel = truncateDeviceLabel(req.DeviceLabel)
	session, err := s.store.CreateUserSession(ctx, params)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create session")
		return
	}
	http.SetCookie(w, sessionCookie(r, s.baseURL, session.ID, int(userSessionAbsoluteTTL.Seconds())))

	jsonOK(w, verifyResponse{
		Email:         user.Email,
		Authenticated: true,
		Message:       "Account verified.",
		Token:         session.ID,
		ExpiresAt:     formatExpiresAt(session.ExpiresAt),
	})
}

// verifyResponse is the JSON shape returned by POST /v1/auth/verify on
// success. Mirrors registerResponse so the CLI's verify path can persist
// the auto-login session without a follow-up /v1/auth/login (which would
// orphan the verify-time row for the full 30-day idle window).
type verifyResponse struct {
	Email         string `json:"email"`
	Authenticated bool   `json:"authenticated"`
	Message       string `json:"message"`
	Token         string `json:"token,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
}

func (s *Server) handleResendVerification(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		jsonError(w, http.StatusBadRequest, "Email is required")
		return
	}

	ctx := r.Context()

	// Uniform response to prevent email enumeration.
	uniformResponse := func(emailSent bool) {
		jsonOK(w, map[string]interface{}{
			"message":    "If an unverified account exists for this email, a new verification code has been sent.",
			"email_sent": emailSent,
		})
	}

	user, err := s.store.GetUserByEmail(ctx, req.Email)
	if err != nil || user == nil || user.IsActive {
		uniformResponse(false)
		return
	}

	emailSent, err := s.generateAndSendVerificationCode(ctx, req.Email)
	if err != nil {
		// Don't reveal whether the email exists — return uniform response.
		uniformResponse(false)
		return
	}

	uniformResponse(emailSent)
}

func (s *Server) handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		jsonError(w, http.StatusBadRequest, "Email is required")
		return
	}

	ctx := r.Context()

	// Lazy expiration of old password resets.
	_, _ = s.store.ExpirePendingPasswordResets(ctx, time.Now())

	// Uniform response to prevent email enumeration.
	uniformResponse := func(emailSent bool) {
		jsonOK(w, map[string]interface{}{
			"message":    "If an account with that email exists, a password reset code has been sent.",
			"email_sent": emailSent,
		})
	}

	user, err := s.store.GetUserByEmail(ctx, req.Email)
	if err != nil || user == nil {
		uniformResponse(false)
		return
	}

	// Only allow reset for active accounts with a password.
	if !user.IsActive || user.PasswordHash == nil {
		uniformResponse(false)
		return
	}

	// Rate limit pending reset codes per email.
	count, err := s.store.CountPendingPasswordResets(ctx, req.Email)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if count >= maxPendingPasswordResets {
		// Still return uniform response (don't reveal that the email exists).
		uniformResponse(false)
		return
	}

	// Generate 6-digit code (uniform distribution via rejection sampling).
	codeInt, _ := crand.Int(crand.Reader, big.NewInt(1_000_000))
	code := fmt.Sprintf("%06d", codeInt.Int64())

	_, err = s.store.CreatePasswordReset(ctx, req.Email, code, time.Now().Add(passwordResetTTL))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create password reset")
		return
	}

	// Send code via email or log to stderr.
	emailSent := false
	if s.notifier.Enabled() {
		body := strings.Replace(passwordResetEmailHTML, "{{CODE}}", html.EscapeString(code), 1)
		if err := s.notifier.SendHTMLMail([]string{req.Email}, "Agent Vault password reset code", body); err != nil {
			fmt.Fprintf(os.Stderr, "[agent-vault] Failed to send password reset email to %s: %v\n", req.Email, err)
			fmt.Fprintf(os.Stderr, "[agent-vault] Password reset code for %s: %s\n", req.Email, code)
		} else {
			emailSent = true
		}
	} else {
		fmt.Fprintf(os.Stderr, "[agent-vault] Password reset code for %s: %s\n", req.Email, code)
	}

	uniformResponse(emailSent)
}

func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email       string `json:"email"`
		Code        string `json:"code"`
		NewPassword string `json:"new_password"`
		DeviceLabel string `json:"device_label,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Email == "" || req.Code == "" || req.NewPassword == "" {
		jsonError(w, http.StatusBadRequest, "Email, code, and new_password are required")
		return
	}
	if len(req.NewPassword) < 8 {
		jsonError(w, http.StatusBadRequest, "New password must be at least 8 characters")
		return
	}

	ctx := r.Context()

	// Rate limit verification attempts per email.
	resetKey := "rp:" + req.Email
	if !s.rateLimit.FailureCheck(ratelimit.TierVerifyFailure, resetKey) {
		jsonError(w, http.StatusTooManyRequests, "Too many failed reset attempts; request a new code")
		return
	}

	pr, err := s.store.GetPendingPasswordReset(ctx, req.Email, req.Code)
	if err != nil || pr == nil {
		s.rateLimit.FailureRecord(ratelimit.TierVerifyFailure, resetKey)
		jsonError(w, http.StatusBadRequest, "Invalid or expired reset code")
		return
	}

	user, err := s.store.GetUserByEmail(ctx, req.Email)
	if err != nil || user == nil {
		jsonError(w, http.StatusBadRequest, "Invalid or expired reset code")
		return
	}

	if !user.IsActive || user.PasswordHash == nil {
		jsonError(w, http.StatusBadRequest, "Invalid or expired reset code")
		return
	}

	// Hash new password.
	hash, salt, newKDFParams, err := auth.HashUserPassword([]byte(req.NewPassword))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	if err := s.store.UpdateUserPassword(ctx, user.ID, hash, salt, newKDFParams.Time, newKDFParams.Memory, newKDFParams.Threads); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to update password")
		return
	}

	// Mark reset code as used only after password is successfully updated.
	if err := s.store.MarkPasswordResetUsed(ctx, pr.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to process reset")
		return
	}

	// Invalidate all existing sessions.
	_ = s.store.DeleteUserSessions(ctx, user.ID)

	// Reset rate limit on successful reset.
	s.rateLimit.FailureReset(ratelimit.TierVerifyFailure, resetKey)

	// Create new session and auto-login.
	resetParams := newUserSessionParams(r, user.ID)
	resetParams.DeviceLabel = truncateDeviceLabel(req.DeviceLabel)
	session, err := s.store.CreateUserSession(ctx, resetParams)
	if err != nil {
		// Password was reset but session creation failed — user can re-login.
		jsonOK(w, map[string]interface{}{
			"message":       "Password reset successfully. Please log in.",
			"authenticated": false,
		})
		return
	}

	http.SetCookie(w, sessionCookie(r, s.baseURL, session.ID, int(userSessionAbsoluteTTL.Seconds())))

	jsonOK(w, map[string]interface{}{
		"message":       "Password reset successfully.",
		"authenticated": true,
		"expires_at":    formatExpiresAt(session.ExpiresAt),
	})
}

// handleAuthMe returns the current authenticated actor's info.
func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		jsonError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}
	actor, err := s.actorFromSession(r.Context(), sess)
	if err != nil || actor == nil {
		jsonError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	if actor.Type == "agent" {
		jsonOK(w, map[string]interface{}{
			"type":       "agent",
			"agent_name": actor.Agent.Name,
			"role":       actor.Role,
			"is_owner":   actor.IsOwner(),
		})
		return
	}

	// User actor.
	user := actor.User
	var oauthProviders []string
	oauthAccounts, err := s.store.ListUserOAuthAccounts(r.Context(), user.ID)
	if err == nil {
		for _, oa := range oauthAccounts {
			oauthProviders = append(oauthProviders, oa.Provider)
		}
	}
	if oauthProviders == nil {
		oauthProviders = []string{}
	}

	jsonOK(w, map[string]interface{}{
		"type":            "user",
		"email":           user.Email,
		"role":            user.Role,
		"is_owner":        user.Role == "owner",
		"has_password":    user.PasswordHash != nil,
		"oauth_providers": oauthProviders,
	})
}

// userKDFParams reconstructs KDFParams from a User's stored fields.
// KeyLen and SaltLen use the standard values (32 and 16).
func userKDFParams(u *store.User) crypto.KDFParams {
	return crypto.KDFParams{
		Time:    u.KDFTime,
		Memory:  u.KDFMemory,
		Threads: u.KDFThreads,
		KeyLen:  32,
		SaltLen: 16,
	}
}

// clientIP extracts the client's IP address. X-Forwarded-For is only trusted
// when AGENT_VAULT_TRUSTED_PROXIES is configured and the direct connection
// comes from a listed proxy. Falls back to RemoteAddr for direct connections.
func clientIP(r *http.Request) string {
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if remoteIP == "" {
		remoteIP = r.RemoteAddr
	}

	// Only trust XFF when the request comes from a configured trusted proxy.
	if len(trustedProxyCIDRs) > 0 {
		ip := net.ParseIP(remoteIP)
		trusted := false
		if ip != nil {
			for _, cidr := range trustedProxyCIDRs {
				if cidr.Contains(ip) {
					trusted = true
					break
				}
			}
		}
		if trusted {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				parts := strings.Split(xff, ",")
				for i := len(parts) - 1; i >= 0; i-- {
					entry := strings.TrimSpace(parts[i])
					if entry != "" {
						return entry
					}
				}
			}
		}
	}
	return remoteIP
}

func init() {
	dummyPasswordHash, dummyPasswordSalt, dummyKDFParams, _ = auth.HashUserPassword([]byte("sb-dummy-timing-equalization"))
}

// newUserSessionParams builds a CreateUserSessionParams populated with the
// caller's IP and User-Agent. Centralized so every login path (password,
// OAuth, verification, password reset) records the same shape and applies
// the same TTLs. DeviceLabel is left empty here because only the password
// login path receives one in the request body — other paths set it
// post-construction if needed.
func newUserSessionParams(r *http.Request, userID string) store.CreateUserSessionParams {
	return store.CreateUserSessionParams{
		UserID:        userID,
		ExpiresAt:     time.Now().Add(userSessionAbsoluteTTL),
		IdleTTL:       userSessionIdleTTL,
		LastIP:        clientIP(r),
		LastUserAgent: r.UserAgent(),
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		jsonError(w, http.StatusBadRequest, "Email and password are required")
		return
	}

	// Rate limit by IP and by email (reject if either bucket is full).
	// Normalize the email key so case/whitespace variations don't
	// let an attacker bypass the email bucket for a legitimate user.
	ip := clientIP(r)
	ipDecision := s.rateLimit.Allow(ratelimit.TierAuth, "ip:"+ip)
	emailDecision := s.rateLimit.Allow(ratelimit.TierAuth, "email:"+strings.ToLower(strings.TrimSpace(req.Email)))
	if !ipDecision.Allow || !emailDecision.Allow {
		d := ipDecision
		if !emailDecision.Allow {
			d = emailDecision
		}
		ratelimit.WriteDenial(w, d, "Too many login attempts, try again later")
		return
	}

	ctx := r.Context()

	user, err := s.store.GetUserByEmail(ctx, req.Email)
	if err != nil {
		// Run KDF against dummy hash to equalize response time (prevent user enumeration).
		auth.VerifyUserPassword([]byte(req.Password), dummyPasswordHash, dummyPasswordSalt, dummyKDFParams)
		jsonError(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	// OAuth-only user trying to use password login — run dummy KDF to prevent timing attacks.
	if user.PasswordHash == nil {
		auth.VerifyUserPassword([]byte(req.Password), dummyPasswordHash, dummyPasswordSalt, dummyKDFParams)
		jsonError(w, http.StatusUnauthorized, "This account uses social login. Use the 'Continue with Google' button on the login page.")
		return
	}

	if !auth.VerifyUserPassword([]byte(req.Password), user.PasswordHash, user.PasswordSalt, userKDFParams(user)) {
		jsonError(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	if !user.IsActive {
		jsonError(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	params := newUserSessionParams(r, user.ID)
	params.DeviceLabel = truncateDeviceLabel(req.DeviceLabel)
	session, err := s.store.CreateUserSession(ctx, params)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create session")
		return
	}

	http.SetCookie(w, sessionCookie(r, s.baseURL, session.ID, int(userSessionAbsoluteTTL.Seconds())))

	jsonOK(w, loginResponse{
		Token:     session.ID,
		ExpiresAt: formatExpiresAt(session.ExpiresAt),
	})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.NewPassword == "" {
		jsonError(w, http.StatusBadRequest, "New_password is required")
		return
	}
	if len(req.NewPassword) < 8 {
		jsonError(w, http.StatusBadRequest, "New password must be at least 8 characters")
		return
	}

	ctx := r.Context()
	sess := sessionFromContext(ctx)
	if sess == nil || sess.UserID == "" {
		jsonError(w, http.StatusForbidden, "User session required")
		return
	}

	user, err := s.store.GetUserByID(ctx, sess.UserID)
	if err != nil || user == nil {
		jsonError(w, http.StatusInternalServerError, "Failed to load user")
		return
	}

	// OAuth-only users (no password) can set a password without providing current_password.
	// Users with an existing password must verify it first.
	if user.PasswordHash != nil {
		if req.CurrentPassword == "" {
			jsonError(w, http.StatusBadRequest, "Current_password is required")
			return
		}
		if !auth.VerifyUserPassword([]byte(req.CurrentPassword), user.PasswordHash, user.PasswordSalt, userKDFParams(user)) {
			jsonError(w, http.StatusUnauthorized, "Current password is incorrect")
			return
		}
	}

	hash, salt, newKDFParams, err := auth.HashUserPassword([]byte(req.NewPassword))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	if err := s.store.UpdateUserPassword(ctx, user.ID, hash, salt, newKDFParams.Time, newKDFParams.Memory, newKDFParams.Threads); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to update password")
		return
	}

	// Carry the caller's device_label onto the post-change session so
	// `auth sessions list` keeps showing the same DEVICE label across
	// password changes. Captured before DeleteUserSessions wipes the row.
	var carryDeviceLabel string
	if caller := sessionFromContext(ctx); caller != nil {
		carryDeviceLabel = caller.DeviceLabel
	}

	// Invalidate all existing sessions, then create a fresh one for this request.
	_ = s.store.DeleteUserSessions(ctx, user.ID)

	params := newUserSessionParams(r, user.ID)
	params.DeviceLabel = carryDeviceLabel
	newSess, err := s.store.CreateUserSession(ctx, params)
	if err != nil {
		// Password was changed but session creation failed — user can re-login.
		jsonError(w, http.StatusInternalServerError, "Password changed but failed to create new session")
		return
	}

	http.SetCookie(w, sessionCookie(r, s.baseURL, newSess.ID, int(userSessionAbsoluteTTL.Seconds())))

	jsonOK(w, loginResponse{
		Token:     newSess.ID,
		ExpiresAt: formatExpiresAt(newSess.ExpiresAt),
	})
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := sessionFromContext(ctx)
	if sess == nil || sess.UserID == "" {
		jsonError(w, http.StatusForbidden, "User session required")
		return
	}

	user, err := s.store.GetUserByID(ctx, sess.UserID)
	if err != nil || user == nil {
		jsonError(w, http.StatusInternalServerError, "Failed to load user")
		return
	}

	if user.Role == "owner" {
		jsonError(w, http.StatusConflict, "Owners cannot delete their own account; transfer ownership first")
		return
	}

	_ = s.store.DeleteUserSessions(ctx, user.ID)
	if err := s.store.DeleteUser(ctx, user.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to delete account")
		return
	}

	// Clear session cookie.
	http.SetCookie(w, sessionCookie(r, s.baseURL, "", -1))

	jsonOK(w, map[string]string{"status": "deleted", "email": user.Email})
}

// handleLogout clears the session cookie and deletes the session.
// Handles both cookie-based and Bearer token sessions.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var token string
	if header := r.Header.Get("Authorization"); strings.HasPrefix(header, "Bearer ") {
		token = strings.TrimPrefix(header, "Bearer ")
	}
	if c, err := r.Cookie("av_session"); err == nil && c.Value != "" {
		if token == "" {
			token = c.Value
		}
	}
	if token != "" {
		_ = s.store.DeleteSession(r.Context(), token)
		s.touchCache.Delete(token)
	}
	http.SetCookie(w, sessionCookie(r, s.baseURL, "", -1))
	jsonOK(w, map[string]string{"status": "ok"})
}
