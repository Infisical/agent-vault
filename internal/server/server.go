package server

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"math/big"
	"net"
	"sync"

	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/catalog"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/pidfile"
	"github.com/Infisical/agent-vault/internal/proposal"
	"github.com/Infisical/agent-vault/internal/store"
)

//go:embed instructions_proxy.txt
var instructionsProxy string

//go:embed instructions_member.txt
var instructionsMember string

//go:embed instructions_admin.txt
var instructionsAdmin string

//go:embed all:webdist
var webDistFS embed.FS

//go:embed invite_email.html
var userInviteEmailHTML string

//go:embed proposal_notification_email.html
var proposalNotificationEmailHTML string

//go:embed verification_code_email.html
var verificationCodeEmailHTML string

//go:embed password_reset_email.html
var passwordResetEmailHTML string

//go:embed test_email.html
var testEmailHTML string

// Server is the Agent Vault HTTP server.
type Server struct {
	httpServer  *http.Server
	store       Store
	encKey      []byte // 32-byte encryption key, held in memory while running
	notifier    *notify.Notifier
	initialized bool   // true when at least one owner account exists
	baseURL        string // externally-reachable base URL (e.g. "https://sb.example.com")
	oauthProviders map[string]oauth.Provider
	skillCLI    []byte // embedded CLI skill content (served at GET /v1/skills/cli)
	skillHTTP   []byte // embedded HTTP skill content (served at GET /v1/skills/http)
}

// Store is the persistence interface used by the server.
type Store interface {
	GetMasterKeyRecord(ctx context.Context) (*store.MasterKeyRecord, error)
	CreateUser(ctx context.Context, email string, passwordHash, passwordSalt []byte, role string, kdfTime uint32, kdfMemory uint32, kdfThreads uint8) (*store.User, error)
	GetUserByEmail(ctx context.Context, email string) (*store.User, error)
	GetUserByID(ctx context.Context, id string) (*store.User, error)
	ListUsers(ctx context.Context) ([]store.User, error)
	UpdateUserRole(ctx context.Context, userID, role string) error
	UpdateUserPassword(ctx context.Context, userID string, passwordHash, passwordSalt []byte, kdfTime uint32, kdfMemory uint32, kdfThreads uint8) error
	DeleteUser(ctx context.Context, userID string) error
	CountUsers(ctx context.Context) (int, error)
	CountOwners(ctx context.Context) (int, error)
	RegisterFirstUser(ctx context.Context, email string, passwordHash, passwordSalt []byte, defaultVaultID string, kdfTime uint32, kdfMemory uint32, kdfThreads uint8) (*store.User, error)
	CreateSession(ctx context.Context, userID string, expiresAt time.Time) (*store.Session, error)
	CreateScopedSession(ctx context.Context, vaultID, vaultRole string, expiresAt *time.Time) (*store.Session, error)
	GetSession(ctx context.Context, id string) (*store.Session, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteUserSessions(ctx context.Context, userID string) error

	// Vaults
	CreateVault(ctx context.Context, name string) (*store.Vault, error)
	GetVault(ctx context.Context, name string) (*store.Vault, error)
	GetVaultByID(ctx context.Context, id string) (*store.Vault, error)
	ListVaults(ctx context.Context) ([]store.Vault, error)
	DeleteVault(ctx context.Context, name string) error
	RenameVault(ctx context.Context, oldName string, newName string) error

	// Vault grants
	GrantVaultRole(ctx context.Context, userID, vaultID, role string) error
	RevokeVaultAccess(ctx context.Context, userID, vaultID string) error
	ListUserGrants(ctx context.Context, userID string) ([]store.VaultGrant, error)
	HasVaultAccess(ctx context.Context, userID, vaultID string) (bool, error)
	GetVaultRole(ctx context.Context, userID, vaultID string) (string, error)
	CountVaultAdmins(ctx context.Context, vaultID string) (int, error)
	ListVaultUsers(ctx context.Context, vaultID string) ([]store.VaultGrant, error)

	// User activation
	ActivateUser(ctx context.Context, userID string) error

	// Credentials
	SetCredential(ctx context.Context, vaultID, key string, ciphertext, nonce []byte) (*store.Credential, error)
	GetCredential(ctx context.Context, vaultID, key string) (*store.Credential, error)
	ListCredentials(ctx context.Context, vaultID string) ([]store.Credential, error)
	DeleteCredential(ctx context.Context, vaultID, key string) error

	// Broker configs
	GetBrokerConfig(ctx context.Context, vaultID string) (*store.BrokerConfig, error)
	SetBrokerConfig(ctx context.Context, vaultID, servicesJSON string) (*store.BrokerConfig, error)

	// Proposals
	CreateProposal(ctx context.Context, vaultID, sessionID, servicesJSON, credentialsJSON, message, userMessage string, credentials map[string]store.EncryptedCredential) (*store.Proposal, error)
	GetProposal(ctx context.Context, vaultID string, id int) (*store.Proposal, error)
	GetProposalByApprovalToken(ctx context.Context, token string) (*store.Proposal, error)
	ListProposals(ctx context.Context, vaultID, status string) ([]store.Proposal, error)
	CountPendingProposals(ctx context.Context, vaultID string) (int, error)
	UpdateProposalStatus(ctx context.Context, vaultID string, id int, status, reviewNote string) error
	GetProposalCredentials(ctx context.Context, vaultID string, proposalID int) (map[string]store.EncryptedCredential, error)
	ApplyProposal(ctx context.Context, vaultID string, proposalID int, mergedServicesJSON string, credentials map[string]store.EncryptedCredential, deleteCredentialKeys []string) error
	ExpirePendingProposals(ctx context.Context, before time.Time) (int, error)

	// Invites
	CreateInvite(ctx context.Context, vaultID, vaultRole, createdBy string, expiresAt time.Time, sessionTTLSeconds int) (*store.Invite, error)
	GetInviteByToken(ctx context.Context, token string) (*store.Invite, error)
	ListInvites(ctx context.Context, vaultID, status string) ([]store.Invite, error)
	RedeemInvite(ctx context.Context, token, sessionID string) error
	RevokeInvite(ctx context.Context, token string) error
	GetInviteByID(ctx context.Context, id int) (*store.Invite, error)
	RevokeInviteByID(ctx context.Context, id int) error
	CountPendingInvites(ctx context.Context, vaultID string) (int, error)
	ExpirePendingInvites(ctx context.Context, before time.Time) (int, error)

	// User invites (instance-level)
	CreateUserInvite(ctx context.Context, email, createdBy string, expiresAt time.Time, vaults []store.UserInviteVault) (*store.UserInvite, error)
	GetUserInviteByToken(ctx context.Context, token string) (*store.UserInvite, error)
	GetPendingUserInviteByEmail(ctx context.Context, email string) (*store.UserInvite, error)
	ListUserInvites(ctx context.Context, status string) ([]store.UserInvite, error)
	ListUserInvitesByVault(ctx context.Context, vaultID, status string) ([]store.UserInvite, error)
	AcceptUserInvite(ctx context.Context, token string) error
	RevokeUserInvite(ctx context.Context, token string) error
	UpdateUserInviteVaults(ctx context.Context, token string, vaults []store.UserInviteVault) error
	CountPendingUserInvites(ctx context.Context) (int, error)

	// Email verification
	CreateEmailVerification(ctx context.Context, email, code string, expiresAt time.Time) (*store.EmailVerification, error)
	GetPendingEmailVerification(ctx context.Context, email, code string) (*store.EmailVerification, error)
	MarkEmailVerificationUsed(ctx context.Context, id int) error
	CountPendingEmailVerifications(ctx context.Context, email string) (int, error)

	// Password resets
	CreatePasswordReset(ctx context.Context, email, code string, expiresAt time.Time) (*store.PasswordReset, error)
	GetPendingPasswordReset(ctx context.Context, email, code string) (*store.PasswordReset, error)
	MarkPasswordResetUsed(ctx context.Context, id int) error
	CountPendingPasswordResets(ctx context.Context, email string) (int, error)
	ExpirePendingPasswordResets(ctx context.Context, before time.Time) (int, error)

	// OAuth accounts
	CreateOAuthAccount(ctx context.Context, userID, provider, providerUserID, email, name, avatarURL string) (*store.OAuthAccount, error)
	GetOAuthAccount(ctx context.Context, provider, providerUserID string) (*store.OAuthAccount, error)
	GetOAuthAccountByUser(ctx context.Context, userID, provider string) (*store.OAuthAccount, error)
	ListUserOAuthAccounts(ctx context.Context, userID string) ([]store.OAuthAccount, error)
	DeleteOAuthAccount(ctx context.Context, userID, provider string) error

	// OAuth state
	CreateOAuthState(ctx context.Context, stateHash, codeVerifier, nonce, redirectURL, mode, userID string, expiresAt time.Time) (*store.OAuthState, error)
	GetOAuthStateByHash(ctx context.Context, stateHash string) (*store.OAuthState, error)
	DeleteOAuthState(ctx context.Context, id string) error
	ExpireOAuthStates(ctx context.Context, before time.Time) (int, error)

	// OAuth user creation
	CreateOAuthUser(ctx context.Context, email, role string) (*store.User, error)
	CreateOAuthUserAndAccount(ctx context.Context, email, role, provider, providerUserID, oauthEmail, name, avatarURL string) (*store.User, *store.OAuthAccount, error)

	// Instance settings
	GetSetting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
	GetAllSettings(ctx context.Context) (map[string]string, error)

	// Agents
	CreateAgent(ctx context.Context, name, vaultID string, tokenHash, tokenSalt []byte, tokenPrefix, vaultRole, createdBy string) (*store.Agent, error)
	GetAgentByID(ctx context.Context, id string) (*store.Agent, error)
	GetAgentByName(ctx context.Context, name string) (*store.Agent, error)
	GetAgentByTokenPrefix(ctx context.Context, prefix string) (*store.Agent, error)
	ListAgents(ctx context.Context, vaultID string) ([]store.Agent, error)
	ListAllAgents(ctx context.Context) ([]store.Agent, error)
	RevokeAgent(ctx context.Context, id string) error
	UpdateAgentServiceToken(ctx context.Context, id string, tokenHash, tokenSalt []byte, tokenPrefix string) error
	UpdateAgentVaultRole(ctx context.Context, id, role string) error
	RenameAgent(ctx context.Context, id string, newName string) error
	CountAgentSessions(ctx context.Context, agentID string) (int, error)
	GetLatestAgentSessionExpiry(ctx context.Context, agentID string) (*time.Time, error)
	DeleteAgentSessions(ctx context.Context, agentID string) error
	CreateAgentSession(ctx context.Context, agentID, vaultID, vaultRole string, expiresAt *time.Time) (*store.Session, error)
	CreatePersistentInvite(ctx context.Context, vaultID, vaultRole, createdBy string, agentName string, expiresAt time.Time) (*store.Invite, error)
	CreateRotationInvite(ctx context.Context, agentID, vaultID, createdBy string, expiresAt time.Time) (*store.Invite, error)

	Close() error
}

// contextKey is an unexported type for context keys in this package.
type contextKey int

const sessionContextKey contextKey = 0

// sessionFromContext retrieves the session from the request context.
func sessionFromContext(ctx context.Context) *store.Session {
	sess, _ := ctx.Value(sessionContextKey).(*store.Session)
	return sess
}

// userFromSession loads the user for a login session (UserID != "").
// Returns nil for agent sessions (no UserID).
func (s *Server) userFromSession(ctx context.Context, sess *store.Session) (*store.User, error) {
	if sess == nil || sess.UserID == "" {
		return nil, nil
	}
	return s.store.GetUserByID(ctx, sess.UserID)
}

// requireOwner checks that the request is from a logged-in owner.
// Writes a 403 and returns a non-nil error if the check fails.
func (s *Server) requireOwner(w http.ResponseWriter, r *http.Request) (*store.User, error) {
	sess := sessionFromContext(r.Context())
	if sess == nil || sess.UserID == "" {
		jsonError(w, http.StatusForbidden, "Owner session required")
		return nil, fmt.Errorf("no user session")
	}
	user, err := s.userFromSession(r.Context(), sess)
	if err != nil || user == nil {
		jsonError(w, http.StatusForbidden, "Owner session required")
		return nil, fmt.Errorf("user not found")
	}
	if user.Role != "owner" {
		jsonError(w, http.StatusForbidden, "Owner role required")
		return nil, fmt.Errorf("not owner")
	}
	return user, nil
}

// requireUser checks that the request is from a logged-in user (any role).
// Writes a 403 and returns a non-nil error if the check fails.
func (s *Server) requireUser(w http.ResponseWriter, r *http.Request) (*store.User, error) {
	sess := sessionFromContext(r.Context())
	if sess == nil || sess.UserID == "" {
		jsonError(w, http.StatusForbidden, "User session required")
		return nil, fmt.Errorf("no user session")
	}
	user, err := s.userFromSession(r.Context(), sess)
	if err != nil || user == nil {
		jsonError(w, http.StatusForbidden, "User session required")
		return nil, fmt.Errorf("user not found")
	}
	return user, nil
}

// requireVaultAccess checks that the session has access to the given vault.
// For agent sessions (VaultID set), checks that the session's vault matches.
// For user sessions: owners have implicit access; members need an explicit grant.
// Returns the user (nil for agent sessions) or writes an error response.
func (s *Server) requireVaultAccess(w http.ResponseWriter, r *http.Request, vaultID string) (*store.User, error) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return nil, fmt.Errorf("no session")
	}

	// Agent session: relies on vault_id scoping.
	if sess.VaultID != "" {
		if sess.VaultID != vaultID {
			jsonError(w, http.StatusForbidden, "Session not authorized for this vault")
			return nil, fmt.Errorf("vault mismatch")
		}
		return nil, nil // agent session, no user
	}

	// User session: check grants (no implicit owner bypass).
	user, err := s.userFromSession(r.Context(), sess)
	if err != nil || user == nil {
		jsonError(w, http.StatusForbidden, "Invalid session")
		return nil, fmt.Errorf("user not found")
	}

	// All users need an explicit grant.
	has, err := s.store.HasVaultAccess(r.Context(), user.ID, vaultID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to check vault access")
		return nil, err
	}
	if !has {
		jsonError(w, http.StatusForbidden, "No access to this vault")
		return nil, fmt.Errorf("no grant")
	}

	return user, nil
}

// requireVaultAdmin checks that the user has admin role in the given vault.
func (s *Server) requireVaultAdmin(w http.ResponseWriter, r *http.Request, vaultID string) (*store.User, error) {
	user, err := s.requireVaultAccess(w, r, vaultID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		// Agent session — agents cannot be vault admins.
		jsonError(w, http.StatusForbidden, "Vault admin role required")
		return nil, fmt.Errorf("agent session")
	}

	role, err := s.store.GetVaultRole(r.Context(), user.ID, vaultID)
	if err != nil || role != "admin" {
		jsonError(w, http.StatusForbidden, "Vault admin role required")
		return nil, fmt.Errorf("not vault admin")
	}
	return user, nil
}

// agentRoleSatisfies returns true if agentRole is at least as privileged as requiredRole.
// Hierarchy: proxy(0) < member(1) < admin(2).
var roleRank = map[string]int{"proxy": 0, "member": 1, "admin": 2}

func agentRoleSatisfies(agentRole, requiredRole string) bool {
	return roleRank[agentRole] >= roleRank[requiredRole]
}

// requireVaultMember checks that the session has member+ access to the vault.
// For agent/scoped sessions: requires sess.VaultRole is "member" or "admin".
// For user sessions: requires vault access (user vault role is not checked — any user
// with vault access is considered at least a member).
func (s *Server) requireVaultMember(w http.ResponseWriter, r *http.Request, vaultID string) (*store.User, error) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return nil, fmt.Errorf("no session")
	}

	// Scoped session (agent or temp invite): check vault_role.
	if sess.VaultID != "" {
		if sess.VaultID != vaultID {
			jsonError(w, http.StatusForbidden, "Session not authorized for this vault")
			return nil, fmt.Errorf("vault mismatch")
		}
		if !agentRoleSatisfies(sess.VaultRole, "member") {
			jsonError(w, http.StatusForbidden, "Member role required")
			return nil, fmt.Errorf("insufficient role: %s", sess.VaultRole)
		}
		return nil, nil
	}

	// User session: any user with vault access is a member+.
	return s.requireVaultAccess(w, r, vaultID)
}

// requireProposalReview checks proposal approve/reject access.
// Agent/scoped sessions require admin role (proxy-role agents cannot self-approve).
// User sessions require any vault access (member or admin — by design).
func (s *Server) requireProposalReview(w http.ResponseWriter, r *http.Request, vaultID string) (*store.User, error) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return nil, fmt.Errorf("no session")
	}

	// Scoped session (agent or temp invite): require admin role.
	if sess.VaultID != "" {
		if sess.VaultID != vaultID {
			jsonError(w, http.StatusForbidden, "Session not authorized for this vault")
			return nil, fmt.Errorf("vault mismatch")
		}
		if sess.VaultRole != "admin" {
			jsonError(w, http.StatusForbidden, "Admin role required")
			return nil, fmt.Errorf("insufficient role: %s", sess.VaultRole)
		}
		return nil, nil
	}

	// User session: any vault member can review proposals.
	return s.requireVaultAccess(w, r, vaultID)
}

// requireVaultAdminSession checks that the session has admin access to the vault.
// For agent/scoped sessions: requires sess.VaultRole == "admin".
// For user sessions: requires vault admin role.
func (s *Server) requireVaultAdminSession(w http.ResponseWriter, r *http.Request, vaultID string) (*store.User, error) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return nil, fmt.Errorf("no session")
	}

	// Scoped session (agent or temp invite): check vault_role.
	if sess.VaultID != "" {
		if sess.VaultID != vaultID {
			jsonError(w, http.StatusForbidden, "Session not authorized for this vault")
			return nil, fmt.Errorf("vault mismatch")
		}
		if sess.VaultRole != "admin" {
			jsonError(w, http.StatusForbidden, "Admin role required")
			return nil, fmt.Errorf("insufficient role: %s", sess.VaultRole)
		}
		return nil, nil
	}

	// User session: requires vault admin.
	return s.requireVaultAdmin(w, r, vaultID)
}

// securityHeaders wraps a handler to set security headers on every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// maxRequestBodySize is the maximum allowed request body size (1 MB).
const maxRequestBodySize = 1 << 20

// limitBody wraps a handler to enforce a maximum request body size.
func limitBody(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
		next(w, r)
	}
}

// New creates a new Server listening on the given address.
// The initialized parameter indicates whether at least one owner account exists.
// When false, all endpoints except /health and POST /v1/init return 503.
func New(addr string, store Store, encKey []byte, notifier *notify.Notifier, initialized bool, baseURL string, oauthProviders map[string]oauth.Provider) *Server {
	mux := http.NewServeMux()

	// Initialize proxy client once (reads AGENT_VAULT_NETWORK_MODE after env is configured).
	if proxyClient == nil {
		proxyClient = newProxyClient()
	}

	s := &Server{
		httpServer: &http.Server{
			Addr:              addr,
			Handler:           securityHeaders(mux),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
		},
		store:          store,
		encKey:         encKey,
		notifier:       notifier,
		initialized:    initialized,
		baseURL:        strings.TrimRight(baseURL, "/"),
		oauthProviders: oauthProviders,
	}

	// Always available (no initialization required)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /v1/status", s.handleStatus)
	mux.HandleFunc("POST /v1/auth/register", limitBody(s.handleRegister))
	mux.HandleFunc("POST /v1/auth/verify", limitBody(s.handleVerify))
	mux.HandleFunc("POST /v1/auth/resend-verification", limitBody(s.handleResendVerification))
	mux.HandleFunc("POST /v1/auth/forgot-password", limitBody(s.handleForgotPassword))
	mux.HandleFunc("POST /v1/auth/reset-password", limitBody(s.handleResetPassword))

	// Require initialization
	mux.HandleFunc("GET /v1/auth/me", s.requireInitialized(s.requireAuth(s.handleAuthMe)))
	mux.HandleFunc("POST /v1/auth/login", s.requireInitialized(limitBody(s.handleLogin)))
	mux.HandleFunc("POST /v1/auth/change-password", s.requireInitialized(s.requireAuth(limitBody(s.handleChangePassword))))
	mux.HandleFunc("DELETE /v1/auth/account", s.requireInitialized(s.requireAuth(s.handleDeleteAccount)))
	mux.HandleFunc("POST /v1/sessions/scoped", s.requireInitialized(s.requireAuth(limitBody(s.handleScopedSession))))
	mux.HandleFunc("POST /v1/sessions/direct", s.requireInitialized(s.requireAuth(limitBody(s.handleDirectSession))))
	mux.HandleFunc("GET /v1/credentials", s.requireInitialized(s.requireAuth(s.handleCredentialsList)))
	mux.HandleFunc("POST /v1/credentials", s.requireInitialized(s.requireAuth(limitBody(s.handleCredentialsSet))))
	mux.HandleFunc("DELETE /v1/credentials", s.requireInitialized(s.requireAuth(limitBody(s.handleCredentialsDelete))))
	mux.HandleFunc("GET /discover", s.requireInitialized(s.requireAuth(s.handleDiscover)))
	mux.HandleFunc("POST /v1/proposals", s.requireInitialized(s.requireAuth(limitBody(s.handleProposalCreate))))
	mux.HandleFunc("GET /v1/proposals/{id}", s.requireInitialized(s.requireAuth(s.handleProposalGet)))
	mux.HandleFunc("GET /v1/proposals", s.requireInitialized(s.requireAuth(s.handleProposalList)))
	mux.HandleFunc("POST /v1/admin/proposals/{id}/approve", s.requireInitialized(s.requireAuth(limitBody(s.handleAdminProposalApprove))))
	mux.HandleFunc("POST /v1/admin/proposals/{id}/reject", s.requireInitialized(s.requireAuth(limitBody(s.handleAdminProposalReject))))
	mux.HandleFunc("/proxy/", s.requireInitialized(s.requireAuth(s.handleProxy)))

	// Agent invites
	mux.HandleFunc("GET /invite/{token}", s.requireInitialized(s.handleInviteRedeem))
	mux.HandleFunc("POST /invite/{token}", s.requireInitialized(limitBody(s.handlePersistentInviteRedeem)))
	mux.HandleFunc("POST /v1/invites", s.requireInitialized(s.requireAuth(limitBody(s.handleInviteCreate))))
	mux.HandleFunc("GET /v1/invites", s.requireInitialized(s.requireAuth(s.handleInviteList)))
	mux.HandleFunc("DELETE /v1/invites/{token}", s.requireInitialized(s.requireAuth(s.handleInviteRevoke)))
	mux.HandleFunc("DELETE /v1/invites/by-id/{id}", s.requireInitialized(s.requireAuth(s.handleInviteRevokeByID)))

	// Agent management (owner-only)
	mux.HandleFunc("GET /v1/admin/agents", s.requireInitialized(s.requireAuth(s.handleAgentList)))
	mux.HandleFunc("GET /v1/admin/agents/{name}", s.requireInitialized(s.requireAuth(s.handleAgentGet)))
	mux.HandleFunc("DELETE /v1/admin/agents/{name}", s.requireInitialized(s.requireAuth(s.handleAgentRevoke)))
	mux.HandleFunc("POST /v1/admin/agents/{name}/rotate", s.requireInitialized(s.requireAuth(limitBody(s.handleAgentRotate))))
	mux.HandleFunc("POST /v1/admin/agents/{name}/rename", s.requireInitialized(s.requireAuth(limitBody(s.handleAgentRename))))

	// Instance settings (owner-only)
	mux.HandleFunc("GET /v1/admin/settings", s.requireInitialized(s.requireAuth(s.handleGetSettings)))
	mux.HandleFunc("PUT /v1/admin/settings", s.requireInitialized(s.requireAuth(limitBody(s.handleUpdateSettings))))
	mux.HandleFunc("POST /v1/admin/agents/{name}/vault-role", s.requireInitialized(s.requireAuth(limitBody(s.handleAgentSetRole))))

	// Public user list (any authenticated user)
	mux.HandleFunc("GET /v1/users", s.requireInitialized(s.requireAuth(s.handlePublicUserList)))

	// User management (owner-only, except GET self)
	mux.HandleFunc("POST /v1/admin/users", s.requireInitialized(s.requireAuth(limitBody(s.handleUserCreate))))
	mux.HandleFunc("GET /v1/admin/users", s.requireInitialized(s.requireAuth(s.handleUserList)))
	mux.HandleFunc("GET /v1/admin/users/{email}", s.requireInitialized(s.requireAuth(s.handleUserGet)))
	mux.HandleFunc("DELETE /v1/admin/users/{email}", s.requireInitialized(s.requireAuth(s.handleUserDelete)))
	mux.HandleFunc("POST /v1/admin/users/{email}/role", s.requireInitialized(s.requireAuth(limitBody(s.handleUserSetRole))))

	// Vault management (any auth'd user)
	mux.HandleFunc("GET /v1/vaults/{name}/context", s.requireInitialized(s.requireAuth(s.handleVaultContext)))
	mux.HandleFunc("POST /v1/vaults", s.requireInitialized(s.requireAuth(limitBody(s.handleVaultCreate))))
	mux.HandleFunc("GET /v1/vaults", s.requireInitialized(s.requireAuth(s.handleVaultList)))
	mux.HandleFunc("DELETE /v1/vaults/{name}", s.requireInitialized(s.requireAuth(s.handleVaultDelete)))
	mux.HandleFunc("POST /v1/vaults/{name}/rename", s.requireInitialized(s.requireAuth(limitBody(s.handleVaultRename))))
	mux.HandleFunc("POST /v1/vaults/{name}/join", s.requireInitialized(s.requireAuth(limitBody(s.handleVaultJoin))))

	// Vault admin (owner-only)
	mux.HandleFunc("GET /v1/admin/vaults", s.requireInitialized(s.requireAuth(s.handleAdminVaultList)))
	mux.HandleFunc("GET /v1/vaults/{name}/services", s.requireInitialized(s.requireAuth(s.handleServicesGet)))
	mux.HandleFunc("PUT /v1/vaults/{name}/services", s.requireInitialized(s.requireAuth(limitBody(s.handleServicesSet))))
	mux.HandleFunc("DELETE /v1/vaults/{name}/services", s.requireInitialized(s.requireAuth(s.handleServicesClear)))
	mux.HandleFunc("GET /v1/vaults/{name}/services/credential-usage", s.requireInitialized(s.requireAuth(s.handleServicesCredentialUsage)))
	mux.HandleFunc("GET /v1/service-catalog", s.requireInitialized(s.handleServiceCatalog))
	mux.HandleFunc("GET /v1/skills/cli", s.requireInitialized(s.handleSkillCLI))
	mux.HandleFunc("GET /v1/skills/http", s.requireInitialized(s.handleSkillHTTP))

	// Instance-level user invites
	mux.HandleFunc("POST /v1/users/invites", s.requireInitialized(s.requireAuth(limitBody(s.handleUserInviteCreate))))
	mux.HandleFunc("GET /v1/users/invites", s.requireInitialized(s.requireAuth(s.handleUserInviteList)))
	mux.HandleFunc("DELETE /v1/users/invites/{token}", s.requireInitialized(s.requireAuth(s.handleUserInviteRevoke)))
	mux.HandleFunc("POST /v1/users/invites/{token}/reinvite", s.requireInitialized(s.requireAuth(limitBody(s.handleUserInviteReinvite))))
	mux.HandleFunc("GET /v1/users/invites/{token}/details", s.requireInitialized(s.handleUserInviteDetails))
	mux.HandleFunc("POST /v1/users/invites/{token}/accept", s.requireInitialized(limitBody(s.handleUserInviteAccept)))

	// Vault user management (vault admin)
	mux.HandleFunc("GET /v1/vaults/{name}/users", s.requireInitialized(s.requireAuth(s.handleVaultUserList)))
	mux.HandleFunc("POST /v1/vaults/{name}/users", s.requireInitialized(s.requireAuth(limitBody(s.handleVaultUserAdd))))
	mux.HandleFunc("DELETE /v1/vaults/{name}/users/{email}", s.requireInitialized(s.requireAuth(s.handleVaultUserRemove)))
	mux.HandleFunc("POST /v1/vaults/{name}/users/{email}/role", s.requireInitialized(s.requireAuth(limitBody(s.handleVaultUserSetRole))))

	// Proposal approval details (token-based, no auth required)
	mux.HandleFunc("GET /v1/proposals/approve-details", s.requireInitialized(s.handleProposalApproveDetails))

	// Admin proposal management
	mux.HandleFunc("GET /v1/admin/proposals", s.requireInitialized(s.requireAuth(s.handleAdminProposalList)))
	mux.HandleFunc("GET /v1/admin/proposals/{id}", s.requireInitialized(s.requireAuth(s.handleAdminProposalGet)))

	// Email
	mux.HandleFunc("POST /v1/admin/email/test", s.requireInitialized(s.requireAuth(limitBody(s.handleEmailTest))))

	mux.HandleFunc("POST /v1/auth/logout", s.requireInitialized(s.handleLogout))

	// OAuth
	mux.HandleFunc("GET /v1/auth/oauth/providers", s.handleOAuthProviders)
	mux.HandleFunc("GET /v1/auth/oauth/{provider}/login", s.requireInitialized(s.optionalAuth(s.handleOAuthLogin)))
	mux.HandleFunc("GET /v1/auth/oauth/{provider}/callback", s.requireInitialized(s.handleOAuthCallback))
	mux.HandleFunc("POST /v1/auth/oauth/{provider}/connect", s.requireInitialized(s.requireAuth(s.handleOAuthConnect)))
	mux.HandleFunc("DELETE /v1/auth/oauth/{provider}", s.requireInitialized(s.requireAuth(s.handleOAuthDisconnect)))

	// React app static assets (Vite outputs to /assets/ with base "/")
	webFS, _ := fs.Sub(webDistFS, "webdist")
	mux.Handle("GET /assets/", http.FileServer(http.FS(webFS)))
	mux.Handle("GET /vite.svg", http.FileServer(http.FS(webFS)))

	// SPA catch-all: serve index.html for all frontend routes
	mux.HandleFunc("GET /login", s.handleSPA)
	mux.HandleFunc("GET /register", s.handleSPA)
	mux.HandleFunc("GET /vaults/{$}", s.handleSPA)
	mux.HandleFunc("GET /vaults/{name...}", s.handleSPA)
	mux.HandleFunc("GET /invite/{token...}", s.handleSPA)
	mux.HandleFunc("GET /approve/{id...}", s.handleSPA)
	mux.HandleFunc("GET /manage/{path...}", s.handleSPA)
	mux.HandleFunc("GET /change-password", s.handleSPA)
	mux.HandleFunc("GET /oauth/callback", s.handleSPA)
	mux.HandleFunc("GET /account/{path...}", s.handleSPA)
	mux.HandleFunc("GET /{$}", s.handleSPA)

	return s
}

// requireInitialized returns 503 when no owner account exists yet.
func (s *Server) requireInitialized(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.initialized {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":   "not_initialized",
				"message": "No owner account exists. Run 'agent-vault auth register' to create the first account.",
			})
			return
		}
		next(w, r)
	}
}

// Start starts the server and blocks until shutdown.
// It listens for SIGINT/SIGTERM to shut down gracefully.
func (s *Server) Start() error {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		fmt.Printf("Agent Vault server listening on %s\n", s.baseURL)
		if !s.initialized {
			fmt.Printf("Run `agent-vault auth register` or visit %s to create the owner account\n", s.baseURL)
		}
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	if err := pidfile.Write(os.Getpid()); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write PID file: %v\n", err)
	}
	defer func() { _ = pidfile.Remove() }()

	select {
	case err := <-errCh:
		return err
	case <-stop:
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fmt.Println("shutting down server...")
	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}
	fmt.Println("server shut down gracefully")
	crypto.WipeBytes(s.encKey)
	return nil
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

const emailVerificationTTL = 15 * time.Minute
const maxPendingVerifications = 3

// verifyRateLimiter tracks failed verification attempts per email.
type verifyRateLimiter struct {
	mu       sync.Mutex
	attempts map[string]int
	maxKeys  int
}

const maxVerifyAttempts = 10 // max failed attempts per email before code is invalidated
const maxVerifyKeys = 10000 // max tracked emails to prevent unbounded map growth

var verifyLimiter = &verifyRateLimiter{attempts: make(map[string]int), maxKeys: maxVerifyKeys}

func (l *verifyRateLimiter) check(email string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.attempts[email] < maxVerifyAttempts
}

func (l *verifyRateLimiter) recordFailure(email string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.attempts[email]++
	// Evict entries if map grows too large (DoS protection).
	if len(l.attempts) > l.maxKeys {
		for k := range l.attempts {
			if k != email {
				delete(l.attempts, k)
				break
			}
		}
	}
}

func (l *verifyRateLimiter) reset(email string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, email)
}

var errTooManyPendingCodes = errors.New("too many pending verification codes")

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
		Email    string `json:"email"`
		Password string `json:"password"`
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

	// Rate limit registrations by IP to prevent account creation floods.
	ip := clientIP(r)
	if !registerLimiter.allow(ip) {
		jsonError(w, http.StatusTooManyRequests, "Too many registration attempts, try again later")
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
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

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
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

		// Auto-login: create session and set cookie.
		session, err := s.store.CreateSession(ctx, user.ID, time.Now().Add(sessionTTL))
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to create session")
			return
		}
		http.SetCookie(w, sessionCookie(r, s.baseURL, session.ID, int(sessionTTL.Seconds())))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"email":                 user.Email,
			"role":                  "owner",
			"requires_verification": false,
			"authenticated":         true,
			"message":               "Owner account created.",
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"email":                 req.Email,
		"requires_verification": true,
		"email_sent":            emailSent,
		"message":               msg,
	})
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
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
	if !verifyLimiter.check(req.Email) {
		jsonError(w, http.StatusTooManyRequests, "Too many failed verification attempts; request a new code")
		return
	}

	ev, err := s.store.GetPendingEmailVerification(ctx, req.Email, req.Code)
	if err != nil || ev == nil {
		verifyLimiter.recordFailure(req.Email)
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
	verifyLimiter.reset(req.Email)

	// Auto-login: create session and set cookie.
	session, err := s.store.CreateSession(ctx, user.ID, time.Now().Add(sessionTTL))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create session")
		return
	}
	http.SetCookie(w, sessionCookie(r, s.baseURL, session.ID, int(sessionTTL.Seconds())))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"email":         user.Email,
		"authenticated": true,
		"message":       "Account verified.",
	})
}

func (s *Server) handleResendVerification(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		jsonError(w, http.StatusBadRequest, "Email is required")
		return
	}

	// Rate limit by IP.
	ip := clientIP(r)
	if !resendVerifyLimiter.allow(ip) {
		jsonError(w, http.StatusTooManyRequests, "Too many requests, try again later")
		return
	}

	ctx := r.Context()

	// Uniform response to prevent email enumeration.
	uniformResponse := func(emailSent bool) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
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

const passwordResetTTL = 15 * time.Minute
const maxPendingPasswordResets = 3

func (s *Server) handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		jsonError(w, http.StatusBadRequest, "Email is required")
		return
	}

	// Rate limit by IP.
	ip := clientIP(r)
	if !forgotPasswordLimiter.allow(ip) {
		jsonError(w, http.StatusTooManyRequests, "Too many requests, try again later")
		return
	}

	ctx := r.Context()

	// Lazy expiration of old password resets.
	_, _ = s.store.ExpirePendingPasswordResets(ctx, time.Now())

	// Uniform response to prevent email enumeration.
	uniformResponse := func(emailSent bool) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
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
	if !resetVerifyLimiter.check(req.Email) {
		jsonError(w, http.StatusTooManyRequests, "Too many failed reset attempts; request a new code")
		return
	}

	pr, err := s.store.GetPendingPasswordReset(ctx, req.Email, req.Code)
	if err != nil || pr == nil {
		resetVerifyLimiter.recordFailure(req.Email)
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
	resetVerifyLimiter.reset(req.Email)

	// Create new session and auto-login.
	session, err := s.store.CreateSession(ctx, user.ID, time.Now().Add(sessionTTL))
	if err != nil {
		// Password was reset but session creation failed — user can re-login.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"message":       "Password reset successfully. Please log in.",
			"authenticated": false,
		})
		return
	}

	http.SetCookie(w, sessionCookie(r, s.baseURL, session.ID, int(sessionTTL.Seconds())))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"message":       "Password reset successfully.",
		"authenticated": true,
		"expires_at":    formatExpiresAt(session.ExpiresAt),
	})
}

// handleStatus returns the instance initialization status (public, no auth).
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"initialized":      s.initialized,
		"needs_first_user": !s.initialized,
	}

	// Read all settings in one query instead of two separate reads.
	if settings, err := s.store.GetAllSettings(r.Context()); err == nil {
		if raw, ok := settings[settingAllowedDomains]; ok {
			var domains []string
			if json.Unmarshal([]byte(raw), &domains) == nil && len(domains) > 0 {
				resp["allowed_email_domains"] = domains
			}
		}
		if raw, ok := settings[settingInviteOnly]; ok && raw == "true" {
			resp["invite_only"] = true
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleAuthMe returns the current authenticated user's info.
func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil || sess.UserID == "" {
		jsonError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}
	user, err := s.userFromSession(r.Context(), sess)
	if err != nil || user == nil {
		jsonError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}
	// Collect OAuth providers linked to this user.
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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"email":           user.Email,
		"role":            user.Role,
		"is_owner":        user.Role == "owner",
		"has_password":    user.PasswordHash != nil,
		"oauth_providers": oauthProviders,
	})
}

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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"vault_name": vault.Name,
		"vault_role": vaultRole,
	})
}

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
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": true, "error_title": "Already Accepted",
			"error_message": "This invitation has already been accepted. You can log in.",
		})
		return
	case "revoked":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": true, "error_title": "Invite Revoked",
			"error_message": "This invitation was revoked. Please ask for a new one.",
		})
		return
	case "expired":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": true, "error_title": "Invite Expired",
			"error_message": "This invitation has expired. Please ask for a new one.",
		})
		return
	}

	if time.Now().After(inv.ExpiresAt) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": true, "error_title": "Invite Expired",
			"error_message": "This invitation has expired. Please ask for a new one.",
		})
		return
	}

	existing, _ := s.store.GetUserByEmail(ctx, inv.Email)
	needsAccount := existing == nil

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"email":         inv.Email,
		"vaults":        vaultsToJSON(inv.Vaults),
		"needs_account": needsAccount,
	})
}

// handleProposalApproveDetails returns proposal approval page data as JSON.
// The approval token grants read access; user session determines approval capability.
func (s *Server) handleProposalApproveDetails(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.URL.Query().Get("token")
	idStr := r.URL.Query().Get("id")

	if token == "" {
		jsonError(w, http.StatusBadRequest, "Missing token")
		return
	}

	cs, err := s.store.GetProposalByApprovalToken(ctx, token)
	if err != nil || cs == nil {
		jsonError(w, http.StatusNotFound, "Invalid or expired approval link")
		return
	}

	if id, err := strconv.Atoi(idStr); err != nil || id != cs.ID {
		jsonError(w, http.StatusBadRequest, "Proposal ID mismatch")
		return
	}

	if cs.ApprovalTokenExpiresAt != nil && time.Now().After(*cs.ApprovalTokenExpiresAt) {
		jsonError(w, http.StatusGone, "Approval link has expired")
		return
	}

	if cs.Status != "pending" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":       true,
			"error_title": strings.ToUpper(cs.Status[:1]) + cs.Status[1:],
			"error_message": "This request has already been " + cs.Status + ".",
		})
		return
	}

	ns, err := s.store.GetVaultByID(ctx, cs.VaultID)
	if err != nil || ns == nil {
		jsonError(w, http.StatusInternalServerError, "Could not load vault details")
		return
	}

	// Resolve agent name via session -> agent chain.
	agentName := ""
	if sess, err := s.store.GetSession(ctx, cs.SessionID); err == nil && sess != nil && sess.AgentID != "" {
		if agent, err := s.store.GetAgentByID(ctx, sess.AgentID); err == nil && agent != nil {
			agentName = agent.Name
		}
	}

	authenticated := false
	canApprove := false
	userEmail := ""
	if c, err := r.Cookie("av_session"); err == nil && c.Value != "" {
		sess, err := s.store.GetSession(ctx, c.Value)
		if err == nil && sess != nil && !sessionExpired(sess) && sess.UserID != "" {
			user, err := s.userFromSession(ctx, sess)
			if err == nil && user != nil {
				authenticated = true
				userEmail = user.Email
				has, err := s.store.HasVaultAccess(ctx, user.ID, cs.VaultID)
				if err == nil && has {
					canApprove = true
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"proposal_id":  cs.ID,
		"vault":         ns.Name,
		"status":        cs.Status,
		"user_message":  cs.UserMessage,
		"message":       cs.Message,
		"services":      json.RawMessage(cs.ServicesJSON),
		"credentials":       json.RawMessage(cs.CredentialsJSON),
		"created_at":    cs.CreatedAt.Format(time.RFC3339),
		"agent_name":    agentName,
		"authenticated": authenticated,
		"can_approve":   canApprove,
		"user_email":    userEmail,
	})
}

// handleSPA serves the SPA index.html for client-side routing.
func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	indexHTML, err := fs.ReadFile(webDistFS, "webdist/index.html")
	if err != nil {
		http.Error(w, "Frontend not built", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(indexHTML)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

const sessionTTL = 24 * time.Hour

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

// --- Rate limiting ---

// trustedProxyCIDRs holds parsed CIDR ranges from AGENT_VAULT_TRUSTED_PROXIES.
// When non-empty, X-Forwarded-For is only trusted if RemoteAddr matches one of these.
var trustedProxyCIDRs []*net.IPNet

func init() {
	if raw := os.Getenv("AGENT_VAULT_TRUSTED_PROXIES"); raw != "" {
		for _, cidr := range strings.Split(raw, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			// Allow bare IPs (e.g. "10.0.0.1") by appending /32 or /128.
			if !strings.Contains(cidr, "/") {
				if strings.Contains(cidr, ":") {
					cidr += "/128"
				} else {
					cidr += "/32"
				}
			}
			if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
				trustedProxyCIDRs = append(trustedProxyCIDRs, ipNet)
			}
		}
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

// slidingWindowLimiter is a generic sliding-window rate limiter keyed by string.
type slidingWindowLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	window   time.Duration
	max      int
	maxKeys  int // max map keys before eviction (0 = unlimited)
}

func newSlidingWindowLimiter(window time.Duration, max, maxKeys int) *slidingWindowLimiter {
	return &slidingWindowLimiter{
		attempts: make(map[string][]time.Time),
		window:   window,
		max:      max,
		maxKeys:  maxKeys,
	}
}

// allow checks whether an action for the given key should be allowed.
func (l *slidingWindowLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.window)

	// Filter to recent attempts only.
	recent := l.attempts[key][:0]
	for _, t := range l.attempts[key] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	l.attempts[key] = recent

	if len(recent) >= l.max {
		return false
	}

	l.attempts[key] = append(l.attempts[key], now)

	// Evict oldest keys if map grows too large (prevents unbounded growth).
	if l.maxKeys > 0 && len(l.attempts) > l.maxKeys {
		for k, v := range l.attempts {
			if len(v) == 0 || v[len(v)-1].Before(cutoff) {
				delete(l.attempts, k)
			}
		}
	}

	return true
}

const (
	loginRateWindow = 5 * time.Minute
	loginRateMax    = 10 // max attempts per key per window
)

var (
	loginIPLimiter    = newSlidingWindowLimiter(loginRateWindow, loginRateMax, 10000)
	loginEmailLimiter = newSlidingWindowLimiter(loginRateWindow, loginRateMax, 10000)
	registerLimiter          = newSlidingWindowLimiter(loginRateWindow, 5, 10000) // 5 registrations per IP per 5 min
	forgotPasswordLimiter    = newSlidingWindowLimiter(loginRateWindow, 5, 10000) // 5 forgot-password requests per IP per 5 min
	resendVerifyLimiter      = newSlidingWindowLimiter(loginRateWindow, 5, 10000) // 5 resend-verification requests per IP per 5 min
	userInviteAcceptLimiter = newSlidingWindowLimiter(loginRateWindow, 10, 10000) // 10 invite accepts per IP per 5 min
	resetVerifyLimiter    = &verifyRateLimiter{attempts: make(map[string]int), maxKeys: maxVerifyKeys}
)

// dummyPasswordHash and dummyPasswordSalt are pre-computed KDF outputs used to
// equalize response time when a login attempt uses a non-existent email.
// This prevents timing side-channel user enumeration.
var (
	dummyPasswordHash []byte
	dummyPasswordSalt []byte
	dummyKDFParams    crypto.KDFParams
)

func init() {
	dummyPasswordHash, dummyPasswordSalt, dummyKDFParams, _ = auth.HashUserPassword([]byte("sb-dummy-timing-equalization"))
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		jsonError(w, http.StatusBadRequest, "Email and password are required")
		return
	}

	// Rate limit by IP and by email.
	ip := clientIP(r)
	if !loginIPLimiter.allow(ip) || !loginEmailLimiter.allow(req.Email) {
		http.Error(w, `{"error":"Too many login attempts, try again later"}`, http.StatusTooManyRequests)
		return
	}

	ctx := r.Context()

	user, err := s.store.GetUserByEmail(ctx, req.Email)
	if err != nil {
		// Run KDF against dummy hash to equalize response time (prevent user enumeration).
		auth.VerifyUserPassword([]byte(req.Password), dummyPasswordHash, dummyPasswordSalt, dummyKDFParams)
		http.Error(w, `{"error":"Invalid email or password"}`, http.StatusUnauthorized)
		return
	}

	// OAuth-only user trying to use password login — run dummy KDF to prevent timing attacks.
	if user.PasswordHash == nil {
		auth.VerifyUserPassword([]byte(req.Password), dummyPasswordHash, dummyPasswordSalt, dummyKDFParams)
		http.Error(w, `{"error":"This account uses social login. Use the 'Continue with Google' button on the login page."}`, http.StatusUnauthorized)
		return
	}

	if !auth.VerifyUserPassword([]byte(req.Password), user.PasswordHash, user.PasswordSalt, userKDFParams(user)) {
		http.Error(w, `{"error":"Invalid email or password"}`, http.StatusUnauthorized)
		return
	}

	if !user.IsActive {
		http.Error(w, `{"error":"Invalid email or password"}`, http.StatusUnauthorized)
		return
	}

	session, err := s.store.CreateSession(ctx, user.ID, time.Now().Add(sessionTTL))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create session")
		return
	}

	http.SetCookie(w, sessionCookie(r, s.baseURL, session.ID, int(sessionTTL.Seconds())))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(loginResponse{
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

	// Invalidate all existing sessions, then create a fresh one for this request.
	_ = s.store.DeleteUserSessions(ctx, user.ID)

	newSess, err := s.store.CreateSession(ctx, user.ID, time.Now().Add(sessionTTL))
	if err != nil {
		// Password was changed but session creation failed — user can re-login.
		jsonError(w, http.StatusInternalServerError, "Password changed but failed to create new session")
		return
	}

	http.SetCookie(w, sessionCookie(r, s.baseURL, newSess.ID, int(sessionTTL.Seconds())))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(loginResponse{
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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "email": user.Email})
}

// requireAuth wraps a handler and validates the Bearer token or av_session cookie.
// The authenticated session is stored in the request context.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var token string
		header := r.Header.Get("Authorization")
		if strings.HasPrefix(header, "Bearer ") {
			token = strings.TrimPrefix(header, "Bearer ")
		} else if c, err := r.Cookie("av_session"); err == nil && c.Value != "" {
			token = c.Value
		} else {
			http.Error(w, `{"error":"Authorization required"}`, http.StatusUnauthorized)
			return
		}

		sess, err := s.store.GetSession(r.Context(), token)
		if err != nil || sess == nil {
			http.Error(w, `{"error":"Invalid or expired session"}`, http.StatusUnauthorized)
			return
		}
		if sessionExpired(sess) {
			http.Error(w, `{"error":"Session expired"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), sessionContextKey, sess)
		next(w, r.WithContext(ctx))
	}
}

// optionalAuth is like requireAuth but does not reject unauthenticated
// requests. If a valid session token is present it is placed in context;
// otherwise the handler runs without a session.
func (s *Server) optionalAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var token string
		header := r.Header.Get("Authorization")
		if strings.HasPrefix(header, "Bearer ") {
			token = strings.TrimPrefix(header, "Bearer ")
		} else if c, err := r.Cookie("av_session"); err == nil && c.Value != "" {
			token = c.Value
		}

		if token != "" {
			if sess, err := s.store.GetSession(r.Context(), token); err == nil && sess != nil && !sessionExpired(sess) {
				ctx := context.WithValue(r.Context(), sessionContextKey, sess)
				next(w, r.WithContext(ctx))
				return
			}
		}

		next(w, r)
	}
}

type scopedSessionRequest struct {
	Vault     string `json:"vault"`
	VaultRole string `json:"vault_role"`
}

type scopedSessionResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

func (s *Server) handleScopedSession(w http.ResponseWriter, r *http.Request) {
	var req scopedSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Vault == "" {
		jsonError(w, http.StatusBadRequest, "Vault is required")
		return
	}

	ctx := r.Context()

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}

	// Check that the user has access to this vault.
	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	// Default to "proxy" if no role specified; cap to caller's own role.
	requestedRole := req.VaultRole
	if requestedRole == "" {
		requestedRole = "proxy"
	}
	parentSess := sessionFromContext(ctx)
	cappedRole, errMsg := s.capRequestedRole(ctx, parentSess, ns.ID, requestedRole)
	if errMsg != "" {
		jsonError(w, http.StatusForbidden, errMsg)
		return
	}

	sess, err := s.store.CreateScopedSession(ctx, ns.ID, cappedRole, timePtr(time.Now().Add(sessionTTL)))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create scoped session")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(scopedSessionResponse{
		Token:     sess.ID,
		ExpiresAt: formatExpiresAt(sess.ExpiresAt),
	})
}

// capRequestedRole enforces role-capping rules: the requested role cannot
// exceed the caller's own vault role. Proxy-role agents cannot mint sessions at all.
// Returns the validated role, or an error string if the caller lacks permission.
func (s *Server) capRequestedRole(ctx context.Context, sess *store.Session, vaultID, requestedRole string) (string, string) {
	if requestedRole == "" {
		requestedRole = "proxy"
	}

	var callerRole string

	if sess.VaultID != "" {
		// Scoped session (agent or temp invite).
		if sess.VaultID != vaultID {
			return "", "Session not authorized for this vault"
		}
		if !agentRoleSatisfies(sess.VaultRole, "member") {
			return "", "Member role required"
		}
		callerRole = sess.VaultRole
	} else {
		// User session: require vault access.
		user, err := s.userFromSession(ctx, sess)
		if err != nil || user == nil {
			return "", "Invalid session"
		}
		has, err := s.store.HasVaultAccess(ctx, user.ID, vaultID)
		if err != nil || !has {
			return "", "No access to this vault"
		}
		role, err2 := s.store.GetVaultRole(ctx, user.ID, vaultID)
		if err2 != nil {
			return "", "Failed to check vault role"
		}
		callerRole = role
	}

	if !agentRoleSatisfies(callerRole, requestedRole) {
		return "", fmt.Sprintf("Your vault role (%s) cannot mint sessions with role %s", callerRole, requestedRole)
	}
	return requestedRole, ""
}

type directSessionRequest struct {
	Vault      string `json:"vault"`
	VaultRole  string `json:"vault_role"`
	TTLSeconds *int   `json:"ttl_seconds,omitempty"`
}

type directSessionResponse struct {
	AVAddr         string            `json:"av_addr"`
	AVSessionToken string            `json:"av_session_token"`
	AVVault        string            `json:"av_vault"`
	VaultRole      string            `json:"vault_role"`
	ProxyURL       string            `json:"proxy_url"`
	Services       []discoverService `json:"services"`
	Instructions   string            `json:"instructions"`
	ExpiresAt      string            `json:"expires_at"`
}

const (
	directSessionMinTTL = 5 * 60        // 5 minutes
	directSessionMaxTTL = 7 * 24 * 3600 // 7 days
	directSessionDefTTL = 24 * 3600     // 24 hours
)

func (s *Server) handleDirectSession(w http.ResponseWriter, r *http.Request) {
	var req directSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Vault == "" {
		req.Vault = "default"
	}
	if req.VaultRole == "" {
		req.VaultRole = "proxy"
	}
	if req.VaultRole != "proxy" && req.VaultRole != "member" && req.VaultRole != "admin" {
		jsonError(w, http.StatusBadRequest, "vault_role must be one of: proxy, member, admin")
		return
	}
	if req.TTLSeconds != nil {
		ttl := *req.TTLSeconds
		if ttl < directSessionMinTTL || ttl > directSessionMaxTTL {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("ttl_seconds must be between %d and %d", directSessionMinTTL, directSessionMaxTTL))
			return
		}
	}
	ctx := r.Context()

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}

	sess := sessionFromContext(ctx)
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return
	}

	cappedRole, errMsg := s.capRequestedRole(ctx, sess, ns.ID, req.VaultRole)
	if errMsg != "" {
		jsonError(w, http.StatusForbidden, errMsg)
		return
	}

	// ttl_seconds omitted = no expiry; ttl_seconds present = finite session.
	var expiresAt *time.Time
	if req.TTLSeconds != nil {
		t := time.Now().Add(time.Duration(*req.TTLSeconds) * time.Second)
		expiresAt = &t
	}
	newSess, err := s.store.CreateScopedSession(ctx, ns.ID, cappedRole, expiresAt)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create session")
		return
	}

	services := s.buildServiceList(ctx, ns.ID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(directSessionResponse{
		AVAddr:         s.baseURL,
		AVSessionToken: newSess.ID,
		AVVault:        ns.Name,
		VaultRole:      cappedRole,
		ProxyURL:       s.baseURL + "/proxy",
		Services:       services,
		Instructions:   instructionsForRole(cappedRole),
		ExpiresAt:      formatExpiresAt(newSess.ExpiresAt),
	})
}

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
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}
	if len(req.Credentials) == 0 {
		http.Error(w, `{"error":"Credentials map is required"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		http.Error(w, fmt.Sprintf(`{"error":"Vault %q not found"}`, req.Vault), http.StatusNotFound)
		return
	}

	// Setting credentials requires member+ role.
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	for key := range req.Credentials {
		if !broker.CredentialKeyPattern.MatchString(key) {
			http.Error(w, fmt.Sprintf(`{"error":"Invalid credential key %q: must be SCREAMING_SNAKE_CASE (e.g. STRIPE_KEY)"}`, key), http.StatusBadRequest)
			return
		}
	}

	var setKeys []string
	for key, value := range req.Credentials {
		ciphertext, nonce, err := crypto.Encrypt([]byte(value), s.encKey)
		if err != nil {
			http.Error(w, `{"error":"Encryption failed"}`, http.StatusInternalServerError)
			return
		}
		if _, err := s.store.SetCredential(ctx, ns.ID, key, ciphertext, nonce); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"Failed to set credential %q"}`, key), http.StatusInternalServerError)
			return
		}
		setKeys = append(setKeys, key)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(credentialsSetResponse{Set: setKeys})
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
		http.Error(w, fmt.Sprintf(`{"error":"Vault %q not found"}`, vault), http.StatusNotFound)
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
			http.Error(w, `{"error":"Failed to decrypt credential"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(credentialsListResponse{
			Keys:        []string{cred.Key},
			Credentials: []credentialEntry{{Key: cred.Key, Value: string(plaintext)}},
		})
		return
	}

	creds, err := s.store.ListCredentials(ctx, ns.ID)
	if err != nil {
		http.Error(w, `{"error":"Failed to list credentials"}`, http.StatusInternalServerError)
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
				http.Error(w, `{"error":"Failed to decrypt credential"}`, http.StatusInternalServerError)
				return
			}
			entries[i] = credentialEntry{Key: cred.Key, Value: string(plaintext)}
		}
		resp.Credentials = entries
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}
	if len(req.Keys) == 0 {
		http.Error(w, `{"error":"Keys list is required"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		http.Error(w, fmt.Sprintf(`{"error":"Vault %q not found"}`, req.Vault), http.StatusNotFound)
		return
	}

	// Deleting credentials requires member+ role.
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	for _, key := range req.Keys {
		if !broker.CredentialKeyPattern.MatchString(key) {
			http.Error(w, fmt.Sprintf(`{"error":"Invalid credential key %q: must be SCREAMING_SNAKE_CASE (e.g. STRIPE_KEY)"}`, key), http.StatusBadRequest)
			return
		}
	}

	var deleted []string
	for _, key := range req.Keys {
		if err := s.store.DeleteCredential(ctx, ns.ID, key); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"Failed to delete credential %q"}`, key), http.StatusInternalServerError)
			return
		}
		deleted = append(deleted, key)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(credentialsDeleteResponse{Deleted: deleted})
}

type discoverService struct {
	Host        string  `json:"host"`
	Description *string `json:"description"`
}

type discoverResponse struct {
	Vault        string            `json:"vault"`
	ProxyURL         string            `json:"proxy_url"`
	Services         []discoverService `json:"services"`
	AvailableCredentials []string          `json:"available_credentials"`
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

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Require scoped session — global admin sessions may not use discovery.
	sess := sessionFromContext(ctx)
	if sess == nil || sess.VaultID == "" {
		proxyError(w, http.StatusForbidden, "forbidden", "Discovery requires a vault-scoped session")
		return
	}

	ns, err := s.store.GetVaultByID(ctx, sess.VaultID)
	if err != nil || ns == nil {
		proxyError(w, http.StatusInternalServerError, "internal", "Failed to resolve vault")
		return
	}

	credentialKeys := s.listCredentialKeys(ctx, sess.VaultID)

	// Load broker config for this vault.
	brokerCfg, err := s.store.GetBrokerConfig(ctx, sess.VaultID)
	if err != nil || brokerCfg == nil {
		// No config means no services — return empty list.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discoverResponse{
			Vault:        ns.Name,
			ProxyURL:         s.baseURL + "/proxy",
			Services:         []discoverService{},
			AvailableCredentials: credentialKeys,
		})
		return
	}

	var svcList []broker.Service
	if err := json.Unmarshal([]byte(brokerCfg.ServicesJSON), &svcList); err != nil {
		proxyError(w, http.StatusInternalServerError, "internal", "Failed to parse broker services")
		return
	}

	services := make([]discoverService, len(svcList))
	for i, svc := range svcList {
		services[i] = discoverService{
			Host:        svc.Host,
			Description: svc.Description,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(discoverResponse{
		Vault:        ns.Name,
		ProxyURL:         s.baseURL + "/proxy",
		Services:         services,
		AvailableCredentials: credentialKeys,
	})
}

// --- Proposals ---

const maxPendingProposals = 20

type proposalCreateRequest struct {
	Services    []proposal.Service    `json:"services"`
	Credentials []proposal.CredentialSlot `json:"credentials"`
	Message     string                 `json:"message"`
	UserMessage string                 `json:"user_message"`
}

func (s *Server) handleProposalCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Enforce scoped session.
	sess := sessionFromContext(ctx)
	if sess == nil || sess.VaultID == "" {
		jsonError(w, http.StatusForbidden, "Proposals require a vault-scoped session")
		return
	}

	var req proposalCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate the proposal.
	if err := proposal.Validate(req.Services, req.Credentials); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Validate that all credential references resolve to existing or proposed credentials.
	existingKeys := s.listCredentialKeys(ctx, sess.VaultID)
	if err := proposal.ValidateCredentialRefs(req.Services, req.Credentials, existingKeys); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Check pending limit.
	count, err := s.store.CountPendingProposals(ctx, sess.VaultID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to count pending proposals")
		return
	}
	if count >= maxPendingProposals {
		jsonError(w, http.StatusTooManyRequests, fmt.Sprintf("Too many pending proposals (max %d)", maxPendingProposals))
		return
	}

	// Encrypt agent-provided credential values (skip delete-action slots).
	encCredentials := make(map[string]store.EncryptedCredential)
	for i := range req.Credentials {
		if req.Credentials[i].Action == proposal.ActionDelete {
			continue
		}
		if req.Credentials[i].Value != nil && *req.Credentials[i].Value != "" {
			ct, nonce, err := crypto.Encrypt([]byte(*req.Credentials[i].Value), s.encKey)
			if err != nil {
				jsonError(w, http.StatusInternalServerError, "Encryption failed")
				return
			}
			encCredentials[req.Credentials[i].Key] = store.EncryptedCredential{Ciphertext: ct, Nonce: nonce}
			// Replace value with nil in the metadata and mark has_value.
			req.Credentials[i].Value = nil
			req.Credentials[i].HasValue = true
		}
	}

	servicesJSON, _ := json.Marshal(req.Services)
	credentialsJSON, _ := json.Marshal(req.Credentials)

	cs, err := s.store.CreateProposal(ctx, sess.VaultID, sess.ID, string(servicesJSON), string(credentialsJSON), req.Message, req.UserMessage, encCredentials)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create proposal")
		return
	}

	// Look up vault name for the response message.
	nsName := sess.VaultID
	if ns, err := s.store.GetVaultByID(ctx, sess.VaultID); err == nil && ns != nil {
		nsName = ns.Name
	}

	approvalURL := fmt.Sprintf("%s/approve/%d?token=%s", s.baseURL, cs.ID, cs.ApprovalToken)

	// Resolve agent name for the notification email.
	proposalAgentName := ""
	if sess.AgentID != "" {
		if agent, err := s.store.GetAgentByID(ctx, sess.AgentID); err == nil && agent != nil {
			proposalAgentName = agent.Name
		}
	}

	// Notify vault members about the new proposal (fire-and-forget).
	// The goroutine intentionally outlives the request, so we use a detached context.
	if s.notifier.Enabled() {
		go s.notifyProposalCreated(sess.VaultID, nsName, cs.ID, req.Message, approvalURL, proposalAgentName) //nolint:gosec // G118: intentional fire-and-forget goroutine
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":           cs.ID,
		"status":       cs.Status,
		"vault":    nsName,
		"approval_url": approvalURL,
		"message":      fmt.Sprintf("Proposal created. Approve here: %s", approvalURL),
	})
}

// notifyProposalCreated sends an email notification to all vault members
// when a new proposal is created. Intended to be called in a goroutine.
func (s *Server) notifyProposalCreated(vaultID, vaultName string, proposalID int, message, approvalURL, agentName string) {
	ctx := context.Background()

	grants, err := s.store.ListVaultUsers(ctx, vaultID)
	if err != nil || len(grants) == 0 {
		return
	}

	var emails []string
	for _, g := range grants {
		if u, err := s.store.GetUserByID(ctx, g.UserID); err == nil && u != nil {
			emails = append(emails, u.Email)
		}
	}
	if len(emails) == 0 {
		return
	}

	// Truncate message for the email body.
	msg := message
	if len(msg) > 200 {
		msg = msg[:200] + "..."
	}

	subject := fmt.Sprintf("New proposal (#%d) in vault %q", proposalID, vaultName)
	body := proposalNotificationEmailHTML
	body = strings.ReplaceAll(body, "{{VAULT_NAME}}", html.EscapeString(vaultName))
	body = strings.ReplaceAll(body, "{{PROPOSAL_ID}}", strconv.Itoa(proposalID))
	body = strings.ReplaceAll(body, "{{MESSAGE}}", html.EscapeString(msg))
	body = strings.ReplaceAll(body, "{{AGENT_NAME}}", html.EscapeString(agentName))
	body = strings.ReplaceAll(body, "{{APPROVAL_URL}}", html.EscapeString(approvalURL))

	if err := s.notifier.SendHTMLMail(emails, subject, body); err != nil {
		fmt.Fprintf(os.Stderr, "[agent-vault] Failed to send proposal notification: %v\n", err)
	}
}

func (s *Server) handleProposalGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sess := sessionFromContext(ctx)
	if sess == nil || sess.VaultID == "" {
		jsonError(w, http.StatusForbidden, "Proposals require a vault-scoped session")
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid proposal id")
		return
	}

	cs, err := s.store.GetProposal(ctx, sess.VaultID, id)
	if err != nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Proposal %d not found", id))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":          cs.ID,
		"status":      cs.Status,
		"services":    json.RawMessage(cs.ServicesJSON),
		"credentials":     json.RawMessage(cs.CredentialsJSON),
		"message":     cs.Message,
		"review_note": cs.ReviewNote,
		"reviewed_at": cs.ReviewedAt,
		"created_at":  cs.CreatedAt.Format(time.RFC3339),
	})
}

func (s *Server) handleProposalList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sess := sessionFromContext(ctx)
	if sess == nil || sess.VaultID == "" {
		jsonError(w, http.StatusForbidden, "Proposals require a vault-scoped session")
		return
	}

	status := r.URL.Query().Get("status")
	list, err := s.store.ListProposals(ctx, sess.VaultID, status)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list proposals")
		return
	}

	type item struct {
		ID        int    `json:"id"`
		Status    string `json:"status"`
		Message   string `json:"message"`
		CreatedAt string `json:"created_at"`
	}
	items := make([]item, len(list))
	for i, cs := range list {
		items[i] = item{
			ID:        cs.ID,
			Status:    cs.Status,
			Message:   cs.Message,
			CreatedAt: cs.CreatedAt.Format(time.RFC3339),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"proposals": items,
	})
}

// --- Admin Proposal Endpoints ---

type adminApproveRequest struct {
	Vault string            `json:"vault"`
	Credentials map[string]string `json:"credentials"` // human-provided credential values (plaintext)
}

func (s *Server) handleAdminProposalApprove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid proposal id")
		return
	}

	var req adminApproveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}

	// Approving proposals: agents need admin role; users need vault access.
	if _, err := s.requireProposalReview(w, r, ns.ID); err != nil {
		return
	}

	cs, err := s.store.GetProposal(ctx, ns.ID, id)
	if err != nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Proposal %d not found", id))
		return
	}
	if cs.Status != "pending" {
		jsonError(w, http.StatusConflict, fmt.Sprintf("Proposal %d is already %s", id, cs.Status))
		return
	}

	// Parse proposed services and credential slots.
	var proposedServices []proposal.Service
	if err := json.Unmarshal([]byte(cs.ServicesJSON), &proposedServices); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to parse proposal services")
		return
	}
	var credentialSlots []proposal.CredentialSlot
	if err := json.Unmarshal([]byte(cs.CredentialsJSON), &credentialSlots); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to parse proposal credentials")
		return
	}

	// Load agent-provided encrypted credentials.
	agentCredentials, err := s.store.GetProposalCredentials(ctx, ns.ID, cs.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to load proposal credentials")
		return
	}

	// Resolve final credential values for set slots; collect keys for delete slots.
	finalCredentials := make(map[string]store.EncryptedCredential)
	var deleteCredentialKeys []string
	for _, slot := range credentialSlots {
		if slot.Action == proposal.ActionDelete {
			deleteCredentialKeys = append(deleteCredentialKeys, slot.Key)
			continue
		}

		var plaintext string

		if override, ok := req.Credentials[slot.Key]; ok {
			// Human-provided override.
			plaintext = override
		} else if slot.HasValue {
			// Agent-provided value: decrypt to re-encrypt with current key.
			enc, ok := agentCredentials[slot.Key]
			if !ok {
				jsonError(w, http.StatusBadRequest, fmt.Sprintf("Agent-provided credential %q not found in proposal", slot.Key))
				return
			}
			decrypted, err := crypto.Decrypt(enc.Ciphertext, enc.Nonce, s.encKey)
			if err != nil {
				jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to decrypt agent-provided credential %q", slot.Key))
				return
			}
			plaintext = string(decrypted)
			crypto.WipeBytes(decrypted)
		} else {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("Missing value for credential %q", slot.Key))
			return
		}

		if plaintext == "" {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("Credential %q cannot be empty", slot.Key))
			return
		}

		ct, nonce, err := crypto.Encrypt([]byte(plaintext), s.encKey)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to encrypt credential %q", slot.Key))
			return
		}
		finalCredentials[slot.Key] = store.EncryptedCredential{Ciphertext: ct, Nonce: nonce}
	}

	// Merge services.
	bc, err := s.store.GetBrokerConfig(ctx, ns.ID)
	if err != nil {
		// No existing config — start fresh.
		bc = &store.BrokerConfig{ServicesJSON: "[]"}
	}

	var existingServices []broker.Service
	if err := json.Unmarshal([]byte(bc.ServicesJSON), &existingServices); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to parse existing services")
		return
	}

	merged, _ := proposal.MergeServices(existingServices, proposedServices)
	mergedJSON, err := json.Marshal(merged)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to marshal merged services")
		return
	}

	// Apply atomically.
	if err := s.store.ApplyProposal(ctx, ns.ID, cs.ID, string(mergedJSON), finalCredentials, deleteCredentialKeys); err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to apply proposal: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":     id,
		"status": "applied",
	})
}

type adminRejectRequest struct {
	Vault string `json:"vault"`
	Reason    string `json:"reason"`
}

func (s *Server) handleAdminProposalReject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid proposal id")
		return
	}

	var req adminRejectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}

	// Rejecting proposals: agents need admin role; users need vault access.
	if _, err := s.requireProposalReview(w, r, ns.ID); err != nil {
		return
	}

	cs, err := s.store.GetProposal(ctx, ns.ID, id)
	if err != nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Proposal %d not found", id))
		return
	}
	if cs.Status != "pending" {
		jsonError(w, http.StatusConflict, fmt.Sprintf("Proposal %d is already %s", id, cs.Status))
		return
	}

	if err := s.store.UpdateProposalStatus(ctx, ns.ID, id, "rejected", req.Reason); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to reject proposal")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":     id,
		"status": "rejected",
	})
}

// isSecureRequest returns true if the request arrived over TLS (direct) or if
// the configured baseURL uses HTTPS (proxy deployments). We derive the flag
// from the trusted server-side baseURL rather than the client-supplied
// X-Forwarded-Proto header to avoid spoofing.
func isSecureRequest(r *http.Request, baseURL string) bool {
	if r.TLS != nil {
		return true
	}
	return strings.HasPrefix(baseURL, "https://")
}

// sessionCookie builds an av_session cookie with all hardening flags set.
// Secure is set based on TLS state or the server's configured baseURL.
func sessionCookie(r *http.Request, baseURL, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     "av_session",
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecureRequest(r, baseURL),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	}
}

// timePtr returns a pointer to the given time value.
func timePtr(t time.Time) *time.Time { return &t }

// formatExpiresAt returns a formatted RFC3339 string for an optional expiry time,
// or an empty string if the session never expires.
func formatExpiresAt(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

// sessionExpired returns true if the session has a finite expiry and that time has passed.
func sessionExpired(s *store.Session) bool {
	return s.ExpiresAt != nil && time.Now().After(*s.ExpiresAt)
}

func jsonError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// proxyError writes a JSON error response with the given status code.
func proxyError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "message": message})
}

// proxyForbiddenWithHint writes a 403 with a proposal_hint so agents can
// programmatically construct a proposal from a denied proxy request.
func proxyForbiddenWithHint(w http.ResponseWriter, targetHost, nsName string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   "forbidden",
		"message": fmt.Sprintf("No broker service matching host %q in vault %q", targetHost, nsName),
		"proposal_hint": map[string]interface{}{
			"host":                 targetHost,
			"endpoint":             "POST /v1/proposals",
			"supported_auth_types": broker.SupportedAuthTypes,
		},
	})
}

// hopByHopHeaders are HTTP/1.1 hop-by-hop headers that must not be forwarded by proxies.
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// isHopByHopHeader returns true if the header is a hop-by-hop header.
func isHopByHopHeader(name string) bool {
	return hopByHopHeaders[http.CanonicalHeaderKey(name)]
}

// isValidProxyHost validates that a target host is a safe hostname or host:port.
// Rejects characters that could cause URL parsing issues (userinfo injection, etc.).
func isValidProxyHost(host string) bool {
	if host == "" {
		return false
	}
	// Strip optional port suffix for hostname validation.
	h := host
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		h = host[:idx]
		port := host[idx+1:]
		// Port must be numeric.
		for _, c := range port {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	if h == "" {
		return false
	}
	// Reject any character that could cause URL parsing issues.
	for _, c := range h {
		if c == '@' || c == '?' || c == '#' || c == '/' || c == '\\' || c == ' ' || c == '%' || c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// proxyPassthroughHeaders is the allowlist of headers forwarded from agent
// requests to upstream services. All other agent headers are dropped.
var proxyPassthroughHeaders = []string{
	"Content-Type",
	"Content-Encoding",
	"Accept",
	"Accept-Encoding",
	"Accept-Language",
	"User-Agent",
	"Idempotency-Key",
	"X-Request-Id",
}

// newProxyClient creates an HTTP client for outbound proxy requests.
// It uses a safe DialContext that blocks connections to forbidden IP ranges
// based on the AGENT_VAULT_NETWORK_MODE setting.
func newProxyClient() *http.Client {
	mode := netguard.ModeFromEnv()
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: netguard.SafeDialContext(mode),
		},
	}
}

// proxyClient is initialized in New() to ensure environment is fully configured.
var proxyClient *http.Client

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	// 1. Parse target host and path from /proxy/{target_host}/{path...}
	trimmed := strings.TrimPrefix(r.URL.Path, "/proxy/")
	if trimmed == "" {
		proxyError(w, http.StatusBadRequest, "bad_request", "Missing target host in proxy URL")
		return
	}
	// Split into host and remaining path.
	targetHost, remainingPath, _ := strings.Cut(trimmed, "/")
	if targetHost == "" {
		proxyError(w, http.StatusBadRequest, "bad_request", "Missing target host in proxy URL")
		return
	}

	// Validate targetHost is a safe hostname (no @, ?, #, spaces, control chars).
	// This prevents userinfo injection (e.g. host@evil.com) in the outbound URL.
	if !isValidProxyHost(targetHost) {
		proxyError(w, http.StatusBadRequest, "bad_request", "Invalid target host")
		return
	}

	ctx := r.Context()

	// 2. Enforce scoped session — global admin sessions may not use the proxy.
	sess := sessionFromContext(ctx)
	if sess == nil || sess.VaultID == "" {
		proxyError(w, http.StatusForbidden, "forbidden", "Proxy requires a vault-scoped session")
		return
	}

	// 3. Look up vault name for error messages.
	ns, err := s.store.GetVaultByID(ctx, sess.VaultID)
	if err != nil || ns == nil {
		proxyError(w, http.StatusInternalServerError, "internal", "Failed to resolve vault")
		return
	}

	// 4. Load broker config for this vault.
	brokerCfg, err := s.store.GetBrokerConfig(ctx, sess.VaultID)
	if err != nil || brokerCfg == nil {
		proxyForbiddenWithHint(w, targetHost, ns.Name)
		return
	}

	var services []broker.Service
	if err := json.Unmarshal([]byte(brokerCfg.ServicesJSON), &services); err != nil {
		proxyError(w, http.StatusInternalServerError, "internal", "Failed to parse broker services")
		return
	}

	// 5. Match host against broker services.
	// Strip port for matching (services use bare hostnames).
	matchHost := targetHost
	if h, _, err := net.SplitHostPort(targetHost); err == nil {
		matchHost = h
	}
	matched := broker.MatchHost(matchHost, services)
	if matched == nil {
		proxyForbiddenWithHint(w, targetHost, ns.Name)
		return
	}

	// 6. Resolve credentials from matched service's auth config.
	resolved, err := matched.Auth.Resolve(func(key string) (string, error) {
		cred, err := s.store.GetCredential(ctx, sess.VaultID, key)
		if err != nil {
			return "", fmt.Errorf("credential %q not found", key)
		}
		plaintext, err := crypto.Decrypt(cred.Ciphertext, cred.Nonce, s.encKey)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt credential %q", key)
		}
		return string(plaintext), nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[agent-vault] credential resolution failed for vault %s: %v\n", sess.VaultID, err)
		proxyError(w, http.StatusBadGateway, "credential_not_found", "A required credential could not be resolved; check vault configuration")
		return
	}

	// 7. Build outbound URL.
	targetURL := "https://" + targetHost
	if remainingPath != "" {
		targetURL += "/" + remainingPath
	}
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	// 8. Build outbound request.
	outReq, err := http.NewRequestWithContext(ctx, r.Method, targetURL, r.Body)
	if err != nil {
		proxyError(w, http.StatusInternalServerError, "internal", "Failed to create outbound request")
		return
	}

	// Copy only safe headers from the agent request (allowlist approach).
	for _, k := range proxyPassthroughHeaders {
		if vv := r.Header.Values(k); len(vv) > 0 {
			for _, v := range vv {
				outReq.Header.Add(k, v)
			}
		}
	}
	outReq.Host = targetHost

	// Merge injected headers (injected wins on conflict).
	for k, v := range resolved {
		outReq.Header.Set(k, v)
	}

	// 9. Forward request to target.
	resp, err := proxyClient.Do(outReq)
	if err != nil {
		// Sanitize error — do not leak internal IPs or hostnames to the agent.
		proxyError(w, http.StatusBadGateway, "upstream_error",
			fmt.Sprintf("Failed to reach %s", targetHost))
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// 10. Stream response back to agent (filter unsafe headers).
	for k, vv := range resp.Header {
		// Skip hop-by-hop and security-sensitive headers from upstream.
		if isHopByHopHeader(k) || strings.EqualFold(k, "Set-Cookie") {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	// Limit response body to 100 MB to prevent resource exhaustion.
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 100<<20))
}

// --- Invites ---

type inviteRedeemResponse struct {
	AVAddr         string            `json:"av_addr"`
	AVSessionToken string            `json:"av_session_token"`
	AVVault        string            `json:"av_vault"`
	VaultRole      string            `json:"vault_role"`
	ProxyURL       string            `json:"proxy_url"`
	Services       []discoverService `json:"services"`
	Instructions   string            `json:"instructions"`
}

func (s *Server) handleInviteRedeem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.PathValue("token")

	inv, err := s.store.GetInviteByToken(ctx, token)
	if err != nil || inv == nil {
		proxyError(w, http.StatusNotFound, "invite_not_found", "Invite not found")
		return
	}

	// Check status — return distinct codes for each terminal state.
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

	// Lazy expiry check for pending invites whose TTL has passed.
	if time.Now().After(inv.ExpiresAt) {
		proxyError(w, http.StatusGone, "invite_expired", "This invite has expired — ask for a new one")
		return
	}

	// Persistent invites must be redeemed via POST.
	if inv.Persistent {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "persistent_invite",
			"message": "This is a persistent agent invite. Use POST /invite/{token} with a JSON body to redeem it.",
		})
		return
	}

	// Burn the invite first to prevent double-redeem race conditions.
	if err := s.store.RedeemInvite(ctx, token, ""); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to redeem invite")
		return
	}

	// Create a vault-scoped session for the agent with the invite's role.
	// SessionTTLSeconds > 0 = finite session; 0 = no expiry.
	var sessExpiry *time.Time
	if inv.SessionTTLSeconds > 0 {
		sessExpiry = timePtr(time.Now().Add(time.Duration(inv.SessionTTLSeconds) * time.Second))
	}
	sess, err := s.store.CreateScopedSession(ctx, inv.VaultID, inv.VaultRole, sessExpiry)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create session")
		return
	}

	// Build the onboarding payload — same data as /discover plus instructions.
	ns, err := s.store.GetVaultByID(ctx, inv.VaultID)
	if err != nil || ns == nil {
		jsonError(w, http.StatusInternalServerError, "Failed to resolve vault")
		return
	}

	baseURL := s.baseURL
	services := s.buildServiceList(ctx, inv.VaultID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(inviteRedeemResponse{
		AVAddr:         baseURL,
		AVSessionToken: sess.ID,
		AVVault:        ns.Name,
		VaultRole:      inv.VaultRole,
		ProxyURL:       baseURL + "/proxy",
		Services:       services,
		Instructions:   instructionsForRole(inv.VaultRole),
	})
}

func (s *Server) handleInviteList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	nsName := r.URL.Query().Get("vault")
	if nsName == "" {
		nsName = store.DefaultVault
	}
	ns, err := s.store.GetVault(ctx, nsName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, "Vault not found")
		return
	}

	// Check vault access.
	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	status := r.URL.Query().Get("status")
	invites, err := s.store.ListInvites(ctx, ns.ID, status)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list invites")
		return
	}

	type inviteItem struct {
		ID               int     `json:"id"`
		Token            string  `json:"token"`
		Status           string  `json:"status"`
		Vault            string  `json:"vault"`
		VaultRole        string  `json:"vault_role"`
		Persistent       bool    `json:"persistent"`
		AgentName        string  `json:"agent_name,omitempty"`
		CreatedAt        string  `json:"created_at"`
		ExpiresAt        string  `json:"expires_at"`
		RedeemedAt       *string `json:"redeemed_at,omitempty"`
		SessionExpiresAt *string `json:"session_expires_at,omitempty"`
	}

	// Return full tokens for admin (user) sessions so CLI can do suffix-based revoke.
	sess := sessionFromContext(ctx)
	isAdmin := sess != nil && sess.UserID != ""

	items := make([]inviteItem, len(invites))
	for i, inv := range invites {
		token := inv.Token
		if !isAdmin && len(token) > 8 {
			token = token[len(token)-8:]
		}
		items[i] = inviteItem{
			ID:         inv.ID,
			Token:      token,
			Status:     inv.Status,
			Vault:      nsName,
			VaultRole:  inv.VaultRole,
			Persistent: inv.Persistent,
			AgentName:  inv.AgentName,
			CreatedAt:  inv.CreatedAt.Format(time.RFC3339),
			ExpiresAt:  inv.ExpiresAt.Format(time.RFC3339),
		}
		if inv.RedeemedAt != nil {
			r := inv.RedeemedAt.Format(time.RFC3339)
			items[i].RedeemedAt = &r
		}
		// For redeemed invites, look up session expiry.
		if inv.Status == "redeemed" && inv.SessionID != "" {
			if session, err := s.store.GetSession(ctx, inv.SessionID); err == nil && session != nil {
				e := formatExpiresAt(session.ExpiresAt)
				items[i].SessionExpiresAt = &e
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

func (s *Server) handleInviteRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token := r.PathValue("token")

	inv, err := s.store.GetInviteByToken(ctx, token)
	if err != nil || inv == nil {
		proxyError(w, http.StatusNotFound, "invite_not_found", "Invite not found")
		return
	}

	// Check vault access for the invite's vault.
	if _, err := s.requireVaultAccess(w, r, inv.VaultID); err != nil {
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
}

func (s *Server) handleInviteRevokeByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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

	// Check vault access for the invite's vault.
	if _, err := s.requireVaultAccess(w, r, inv.VaultID); err != nil {
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
}

// --- User Management Endpoints ---

type userCreateRequest struct {
	Email      string   `json:"email"`
	Password   string   `json:"password"`
	Vaults []string `json:"vaults"`
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwner(w, r); err != nil {
		return
	}

	var req userCreateRequest
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

	// Check email uniqueness.
	if existing, _ := s.store.GetUserByEmail(ctx, req.Email); existing != nil {
		jsonError(w, http.StatusConflict, fmt.Sprintf("User %q already exists", req.Email))
		return
	}

	hash, salt, kdfP, err := auth.HashUserPassword([]byte(req.Password))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	user, err := s.store.CreateUser(ctx, req.Email, hash, salt, "member", kdfP.Time, kdfP.Memory, kdfP.Threads)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	// Admin-created users are active immediately (no email verification needed).
	if err := s.store.ActivateUser(ctx, user.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to activate user")
		return
	}
	user.IsActive = true

	// Grant vault access.
	for _, nsName := range req.Vaults {
		ns, err := s.store.GetVault(ctx, nsName)
		if err != nil || ns == nil {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("Vault %q not found", nsName))
			return
		}
		if err := s.store.GrantVaultRole(ctx, user.ID, ns.ID, "member"); err != nil {
			jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to grant vault %q", nsName))
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"email":      user.Email,
		"role":       user.Role,
		"vaults": req.Vaults,
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

	items := make([]map[string]interface{}, len(users))
	for i, u := range users {
		grants, _ := s.store.ListUserGrants(ctx, u.ID)
		vaultNames := make([]string, 0, len(grants))
		for _, g := range grants {
			if name, ok := vaultNameByID[g.VaultID]; ok {
				vaultNames = append(vaultNames, name)
			}
		}
		items[i] = map[string]interface{}{
			"email":      u.Email,
			"role":       u.Role,
			"vaults":     vaultNames,
			"created_at": u.CreatedAt.Format(time.RFC3339),
		}
	}
	return items
}

func (s *Server) handleUserList(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwner(w, r); err != nil {
		return
	}

	ctx := r.Context()
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list users")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"users": s.buildOwnerUserList(ctx, users)})
}

// handlePublicUserList returns all users to any authenticated user.
// Owners get full data (including vault memberships); members get a reduced view.
func (s *Server) handlePublicUserList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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

	users, err := s.store.ListUsers(ctx)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list users")
		return
	}

	if user.Role == "owner" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"users": s.buildOwnerUserList(ctx, users)})
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"users": items})
}

func (s *Server) handleUserGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	email := r.PathValue("email")

	sess := sessionFromContext(ctx)
	if sess == nil || sess.UserID == "" {
		jsonError(w, http.StatusForbidden, "User session required")
		return
	}

	caller, err := s.userFromSession(ctx, sess)
	if err != nil || caller == nil {
		jsonError(w, http.StatusForbidden, "Invalid session")
		return
	}

	// Allow "me" as a shorthand for the caller's own email.
	if email == "me" {
		email = caller.Email
	}

	// Members can only view themselves.
	if caller.Role != "owner" && caller.Email != email {
		jsonError(w, http.StatusForbidden, "Owner role required to view other users")
		return
	}

	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("User %q not found", email))
		return
	}

	grants, _ := s.store.ListUserGrants(ctx, user.ID)
	nsNames := make([]string, 0, len(grants))
	for _, g := range grants {
		if ns, err := s.store.GetVaultByID(ctx, g.VaultID); err == nil && ns != nil {
			nsNames = append(nsNames, ns.Name)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"email":      user.Email,
		"role":       user.Role,
		"vaults": nsNames,
		"created_at": user.CreatedAt.Format(time.RFC3339),
	})
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwner(w, r); err != nil {
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
	if user.Role == "owner" {
		count, err := s.store.CountOwners(ctx)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to count owners")
			return
		}
		if count <= 1 {
			jsonError(w, http.StatusConflict, "Cannot remove the last owner")
			return
		}
	}

	// Delete sessions, then user (grants cascade via FK).
	_ = s.store.DeleteUserSessions(ctx, user.ID)
	if err := s.store.DeleteUser(ctx, user.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to delete user")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "removed", "email": email})
}

type setRoleRequest struct {
	Role string `json:"role"`
}

func (s *Server) handleUserSetRole(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwner(w, r); err != nil {
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
	if user.Role == "owner" && req.Role == "member" {
		count, err := s.store.CountOwners(ctx)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to count owners")
			return
		}
		if count <= 1 {
			jsonError(w, http.StatusConflict, "Cannot demote the last owner")
			return
		}
	}

	if err := s.store.UpdateUserRole(ctx, user.ID, req.Role); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to update role")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"email": email, "role": req.Role})
}

// buildServiceList returns the services array for a vault (reused by discover and invite redeem).
func (s *Server) buildServiceList(ctx context.Context, vaultID string) []discoverService {
	brokerCfg, err := s.store.GetBrokerConfig(ctx, vaultID)
	if err != nil || brokerCfg == nil {
		return []discoverService{}
	}

	var svcList []broker.Service
	if err := json.Unmarshal([]byte(brokerCfg.ServicesJSON), &svcList); err != nil {
		return []discoverService{}
	}

	services := make([]discoverService, len(svcList))
	for i, svc := range svcList {
		services[i] = discoverService{
			Host:        svc.Host,
			Description: svc.Description,
		}
	}
	return services
}

// handleEmailTest sends a test email to verify SMTP configuration.
// Owner-only. Accepts optional JSON body {"to": "recipient@example.com"}.
// If "to" is omitted, sends to the owner's own email address.
func (s *Server) handleEmailTest(w http.ResponseWriter, r *http.Request) {
	user, err := s.requireOwner(w, r)
	if err != nil {
		return
	}

	if !s.notifier.Enabled() {
		jsonError(w, http.StatusBadRequest, "SMTP is not configured")
		return
	}

	// Parse optional recipient override.
	to := user.Email
	if r.Body != nil && r.ContentLength > 0 {
		var body struct {
			To string `json:"to"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil && body.To != "" {
			to = body.To
		}
	}

	if err := s.notifier.SendHTMLMail(
		[]string{to},
		"Agent Vault \u2014 Test Email",
		testEmailHTML,
	); err != nil {
		jsonError(w, http.StatusBadGateway, fmt.Sprintf("Failed to send test email: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Test email sent",
		"to":      to,
	})
}

// --- Vault Invite Endpoints ---

const userInviteTTL = 48 * time.Hour
const maxPendingUserInvites = 100

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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
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

	user, err := s.requireUser(w, r)
	if err != nil {
		return
	}

	var req struct {
		Email  string `json:"email"`
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
		if user.Role != "owner" {
			role, _ := s.store.GetVaultRole(ctx, user.ID, vault.ID)
			if role != "admin" {
				jsonError(w, http.StatusForbidden, fmt.Sprintf("You must be an admin of vault %q to pre-assign it", v.VaultName))
				return
			}
		}
		vaults = append(vaults, store.UserInviteVault{VaultID: vault.ID, VaultName: vault.Name, VaultRole: v.VaultRole})
	}

	inv, err := s.store.CreateUserInvite(ctx, req.Email, user.ID, time.Now().Add(userInviteTTL), vaults)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create invite")
		return
	}

	inviteLink := s.baseURL + "/invite/" + inv.Token

	emailSent := s.sendUserInviteEmail(w, req.Email, user.Email, inviteLink, "You've been invited to Agent Vault", vaults, inv.ExpiresAt)
	if !emailSent && s.notifier.Enabled() {
		return // error response already written by sendUserInviteEmail
	}

	resp := map[string]interface{}{
		"email":      req.Email,
		"vaults":     vaultsToJSON(vaults),
		"email_sent": emailSent,
		"expires_at": inv.ExpiresAt.Format(time.RFC3339),
	}
	if !emailSent {
		resp["invite_link"] = inviteLink
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
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
	}
	http.SetCookie(w, sessionCookie(r, s.baseURL, "", -1))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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

		newUser, err := s.store.CreateUser(ctx, inv.Email, hash, salt, "member", kdfP.Time, kdfP.Memory, kdfP.Threads)
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
		if err := s.store.GrantVaultRole(ctx, user.ID, v.VaultID, v.VaultRole); err != nil {
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"email":   user.Email,
		"message": msg,
	})
}

func (s *Server) handleUserInviteList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	user, err := s.requireUser(w, r)
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
	if user.Role != "owner" {
		userGrants, _ := s.store.ListUserGrants(ctx, user.ID)
		adminVaultIDs := map[string]bool{}
		for _, g := range userGrants {
			if g.Role == "admin" {
				adminVaultIDs[g.VaultID] = true
			}
		}

		var filtered []store.UserInvite
		for _, inv := range invites {
			if inv.CreatedBy == user.ID {
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
			Token:     inv.Token,
			Status:    inv.Status,
			CreatedBy: inv.CreatedBy,
			Vaults:    vaultsToJSON(inv.Vaults),
			ExpiresAt: inv.ExpiresAt.Format(time.RFC3339),
			CreatedAt: inv.CreatedAt.Format(time.RFC3339),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"invites": items})
}

func (s *Server) handleUserInviteRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	user, err := s.requireUser(w, r)
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
	allowed := inv.CreatedBy == user.Email || user.Role == "owner"
	if !allowed {
		for _, v := range inv.Vaults {
			role, _ := s.store.GetVaultRole(ctx, user.ID, v.VaultID)
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Invite revoked"})
}

// handleUserInviteReinvite revokes an existing pending invite and creates a
// new one for the same email/vault assignments, generating a fresh token and link.
func (s *Server) handleUserInviteReinvite(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	user, err := s.requireUser(w, r)
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

	// Revoke the old invite.
	if err := s.store.RevokeUserInvite(ctx, token); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to revoke old invite")
		return
	}

	// Create a new invite with the same email and vault assignments.
	inv, err := s.store.CreateUserInvite(ctx, existing.Email, user.ID, time.Now().Add(userInviteTTL), existing.Vaults)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create new invite")
		return
	}

	inviteLink := s.baseURL + "/invite/" + inv.Token

	emailSent := s.sendUserInviteEmail(w, existing.Email, user.Email, inviteLink, "You've been re-invited to Agent Vault", existing.Vaults, inv.ExpiresAt)
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// --- Vault User Endpoints ---

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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"users": users})
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": fmt.Sprintf("removed %s from vault %s", email, vaultName)})
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"email":   email,
		"role":    req.Role,
		"message": fmt.Sprintf("updated %s's role to %s in vault %s", email, req.Role, vaultName),
	})
}

// --- Persistent Agent Identity ---

//go:embed persistent_instructions_proxy.txt
var persistentInstructionsProxy string

//go:embed persistent_instructions_member.txt
var persistentInstructionsMember string

//go:embed persistent_instructions_admin.txt
var persistentInstructionsAdmin string

// instructionsForRole returns role-specific instructions for temporary agent invites.
func instructionsForRole(role string) string {
	switch role {
	case "member":
		return instructionsMember
	case "admin":
		return instructionsAdmin
	default:
		return instructionsProxy
	}
}

// persistentInstructionsForRole returns role-specific instructions for persistent agents.
func persistentInstructionsForRole(role string) string {
	switch role {
	case "member":
		return persistentInstructionsMember
	case "admin":
		return persistentInstructionsAdmin
	default:
		return persistentInstructionsProxy
	}
}

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

// handleAgentSessionMint was removed as part of the unified token model.
// Persistent agents now receive session tokens directly (no service token minting).
// The POST /v1/agent/session route is no longer registered.

// handlePersistentInviteRedeem handles POST /invite/{token} for persistent agent invites.
func (s *Server) handlePersistentInviteRedeem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.PathValue("token")

	inv, err := s.store.GetInviteByToken(ctx, token)
	if err != nil || inv == nil {
		proxyError(w, http.StatusNotFound, "invite_not_found", "Invite not found")
		return
	}

	// Check status.
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

	if !inv.Persistent {
		proxyError(w, http.StatusBadRequest, "not_persistent", "This is a temporary invite — use GET /invite/{token} instead")
		return
	}

	// Parse optional body for agent name.
	var body struct {
		Name string `json:"name"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}

	// Rotation invite: agent_id is set, no new agent creation needed.
	if inv.AgentID != "" {
		s.handleRotationRedeem(w, r, inv, token)
		return
	}

	// New persistent agent invite: determine name.
	agentName := inv.AgentName
	if agentName == "" {
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

	// Burn the invite first (atomic CAS via status='pending' guard) to prevent
	// double-redeem race conditions. Only one concurrent request can succeed.
	if err := s.store.RedeemInvite(ctx, token, ""); err != nil {
		proxyError(w, http.StatusGone, "invite_redeemed", "This invite has already been used — ask for a new one")
		return
	}

	// Create agent record with placeholder service token fields (service tokens are
	// no longer used — agents get session tokens directly).
	placeholderHash := []byte("unused")
	placeholderSalt := []byte("unused")
	agent, err := s.store.CreateAgent(ctx, agentName, inv.VaultID, placeholderHash, placeholderSalt, "unused", inv.VaultRole, inv.CreatedBy)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create agent")
		return
	}

	// Create a non-expiring session for the persistent agent.
	sess, err := s.store.CreateAgentSession(ctx, agent.ID, inv.VaultID, agent.VaultRole, nil)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create session")
		return
	}

	ns, _ := s.store.GetVaultByID(ctx, inv.VaultID)
	nsName := store.DefaultVault
	if ns != nil {
		nsName = ns.Name
	}

	baseURL := s.baseURL
	services := s.buildServiceList(ctx, inv.VaultID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"av_addr":          baseURL,
		"av_session_token": sess.ID,
		"av_vault":         nsName,
		"vault_role":       inv.VaultRole,
		"agent_name":       agentName,
		"proxy_url":        baseURL + "/proxy",
		"services":         services,
		"instructions":     persistentInstructionsForRole(inv.VaultRole),
	})
}

// handleRotationRedeem handles redemption of a rotation invite (persistent invite with agent_id set).
func (s *Server) handleRotationRedeem(w http.ResponseWriter, r *http.Request, inv *store.Invite, token string) {
	ctx := r.Context()

	// Look up existing agent by the invite's agent_id.
	// We need to query by ID; since GetAgentByName won't work, query the store directly.
	// Use ListAgents and filter, or add a helper. For now, use the agent_id from the invite
	// by looking up all agents and matching. But that's inefficient.
	// Actually, we can use GetAgentByTokenPrefix — but we don't have the prefix.
	// Let's query directly. We need to find the agent. Let me use a simpler approach:
	// we query the agents table by iterating. But a better approach: look up agent by name
	// from the invite. However, the rotation invite doesn't store the agent name.
	// The invite stores agent_id. We need a GetAgentByID method.
	// For now, let's add a lightweight lookup. Actually, let me check — we can list all agents
	// and filter by ID. But that's wasteful. Let me just query by the agent_id.

	agent, err := s.store.GetAgentByID(ctx, inv.AgentID)
	if err != nil || agent == nil || agent.Status != "active" {
		proxyError(w, http.StatusGone, "agent_not_found", "The agent for this rotation invite no longer exists or has been revoked")
		return
	}

	// Burn the invite first (atomic CAS via status='pending' guard) to prevent
	// double-redeem race conditions. Only one concurrent request can succeed.
	if err := s.store.RedeemInvite(ctx, token, ""); err != nil {
		proxyError(w, http.StatusGone, "invite_redeemed", "This invite has already been used — ask for a new one")
		return
	}

	// Invalidate existing sessions for this agent (rotation replaces access).
	if err := s.store.DeleteAgentSessions(ctx, agent.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to invalidate old sessions")
		return
	}

	// Create a new non-expiring session.
	sess, err := s.store.CreateAgentSession(ctx, agent.ID, agent.VaultID, agent.VaultRole, nil)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create session")
		return
	}

	ns, _ := s.store.GetVaultByID(ctx, agent.VaultID)
	nsName := store.DefaultVault
	if ns != nil {
		nsName = ns.Name
	}

	baseURL := s.baseURL
	services := s.buildServiceList(ctx, agent.VaultID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"av_addr":          baseURL,
		"av_session_token": sess.ID,
		"av_vault":         nsName,
		"vault_role":       agent.VaultRole,
		"agent_name":       agent.Name,
		"proxy_url":        baseURL + "/proxy",
		"services":         services,
		"instructions":     persistentInstructionsForRole(agent.VaultRole),
	})
}

// --- Agent Admin Endpoints ---

func (s *Server) handleAgentList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	nsName := r.URL.Query().Get("vault")
	if nsName == "" {
		// Without a vault filter, only owners can list all agents.
		if _, err := s.requireOwner(w, r); err != nil {
			return
		}
	}

	var vaultID string
	if nsName != "" {
		ns, err := s.store.GetVault(ctx, nsName)
		if err != nil || ns == nil {
			jsonError(w, http.StatusNotFound, "Vault not found")
			return
		}
		vaultID = ns.ID
		// Any vault member can list agents in their vault.
		if _, err := s.requireVaultAccess(w, r, vaultID); err != nil {
			return
		}
	}

	var agents []store.Agent
	var agentErr error
	if vaultID != "" {
		agents, agentErr = s.store.ListAgents(ctx, vaultID)
	} else {
		agents, agentErr = s.store.ListAllAgents(ctx)
	}
	if agentErr != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list agents")
		return
	}

	type agentItem struct {
		Name              string  `json:"name"`
		VaultID           string  `json:"vault_id"`
		VaultRole         string  `json:"vault_role"`
		Status            string  `json:"status"`
		CreatedAt         string  `json:"created_at"`
		RevokedAt         *string `json:"revoked_at,omitempty"`
		SessionExpiresAt  *string `json:"session_expires_at,omitempty"`
	}

	items := make([]agentItem, 0, len(agents))
	for _, ag := range agents {
		item := agentItem{
			Name:        ag.Name,
			VaultID:     ag.VaultID,
			VaultRole:   ag.VaultRole,
			Status:      ag.Status,
			CreatedAt:   ag.CreatedAt.Format(time.RFC3339),
		}
		if ag.RevokedAt != nil {
			s := ag.RevokedAt.Format(time.RFC3339)
			item.RevokedAt = &s
		}
		if ag.Status == "active" {
			if expiry, err := s.store.GetLatestAgentSessionExpiry(ctx, ag.ID); err == nil && expiry != nil {
				e := expiry.Format(time.RFC3339)
				item.SessionExpiresAt = &e
			}
		}
		items = append(items, item)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"agents": items})
}

func (s *Server) handleAgentGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	agent, err := s.store.GetAgentByName(ctx, name)
	if err != nil {
		jsonError(w, http.StatusNotFound, "Agent not found")
		return
	}

	// Any vault member can view agents in their vault.
	if _, err := s.requireVaultAccess(w, r, agent.VaultID); err != nil {
		return
	}

	// Resolve vault name.
	ns, _ := s.store.GetVaultByID(ctx, agent.VaultID)
	nsName := agent.VaultID
	if ns != nil {
		nsName = ns.Name
	}

	resp := map[string]interface{}{
		"name":         agent.Name,
		"vault":        nsName,
		"vault_id":     agent.VaultID,
		"vault_role":   agent.VaultRole,
		"status":       agent.Status,
		"created_by":   agent.CreatedBy,
		"created_at":   agent.CreatedAt.Format(time.RFC3339),
		"updated_at":   agent.UpdatedAt.Format(time.RFC3339),
	}
	if agent.RevokedAt != nil {
		resp["revoked_at"] = agent.RevokedAt.Format(time.RFC3339)
	}

	// Count active sessions.
	sessionCount, _ := s.store.CountAgentSessions(ctx, agent.ID)
	resp["active_sessions"] = sessionCount
	if expiry, err := s.store.GetLatestAgentSessionExpiry(ctx, agent.ID); err == nil && expiry != nil {
		resp["session_expires_at"] = expiry.Format(time.RFC3339)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleAgentRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	agent, err := s.store.GetAgentByName(ctx, name)
	if err != nil {
		jsonError(w, http.StatusNotFound, "Agent not found")
		return
	}

	// Vault admins can revoke agents in their vault.
	if _, err := s.requireVaultAdminSession(w, r, agent.VaultID); err != nil {
		return
	}
	if agent.Status != "active" {
		jsonError(w, http.StatusConflict, "Agent is already revoked")
		return
	}

	if err := s.store.RevokeAgent(ctx, agent.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to revoke agent")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": fmt.Sprintf("agent %q revoked", name)})
}

func (s *Server) handleAgentRotate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	agent, err := s.store.GetAgentByName(ctx, name)
	if err != nil {
		jsonError(w, http.StatusNotFound, "Agent not found")
		return
	}

	// Vault admins can rotate agents in their vault.
	user, err := s.requireVaultAdmin(w, r, agent.VaultID)
	if err != nil {
		return
	}
	if agent.Status != "active" {
		jsonError(w, http.StatusConflict, "Agent is revoked — cannot rotate")
		return
	}

	// Create a rotation invite.
	inv, err := s.store.CreateRotationInvite(ctx, agent.ID, agent.VaultID, user.ID, time.Now().Add(15*time.Minute))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create rotation invite")
		return
	}

	inviteURL := s.baseURL + "/invite/" + inv.Token
	prompt := fmt.Sprintf(`Your Agent Vault session is being rotated. To accept the new session, make the following HTTP request:

  POST %s
  Content-Type: application/json

  {}

The response contains your new session token and usage instructions.

This link expires in 15 minutes and can only be used once.
`, inviteURL)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"invite_url": inviteURL,
		"prompt":     prompt,
		"expires_in": "15m",
	})
}

func (s *Server) handleAgentRename(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	agent, err := s.store.GetAgentByName(ctx, name)
	if err != nil {
		jsonError(w, http.StatusNotFound, "Agent not found")
		return
	}

	// Vault admins can rename agents in their vault.
	if _, err := s.requireVaultAdminSession(w, r, agent.VaultID); err != nil {
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message":  fmt.Sprintf("agent renamed from %q to %q", name, body.Name),
		"old_name": name,
		"new_name": body.Name,
	})
}

func (s *Server) handleAgentSetRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	agent, err := s.store.GetAgentByName(ctx, name)
	if err != nil {
		jsonError(w, http.StatusNotFound, "Agent not found")
		return
	}

	// Only vault admins can change agent roles.
	if _, err := s.requireVaultAdminSession(w, r, agent.VaultID); err != nil {
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

	if err := s.store.UpdateAgentVaultRole(ctx, agent.ID, body.Role); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to update agent role")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message":  fmt.Sprintf("agent %q role updated to %q", name, body.Role),
		"agent":    name,
		"old_role": agent.VaultRole,
		"new_role": body.Role,
	})
}

// ---------------------------------------------------------------------------
// Vault CRUD endpoints
// ---------------------------------------------------------------------------

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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"vaults": items})
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"vaults": items})
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"name": name, "deleted": true})
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"vault":  name,
		"role":   "admin",
		"joined": true,
	})
}

// ---------------------------------------------------------------------------
// Services endpoints
// ---------------------------------------------------------------------------

func (s *Server) handleServicesGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return
	}

	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	bc, err := s.store.GetBrokerConfig(ctx, ns.ID)
	if err != nil || bc == nil {
		// No services set — return empty services.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"vault": name, "services": []interface{}{}})
		return
	}

	var services json.RawMessage
	if err := json.Unmarshal([]byte(bc.ServicesJSON), &services); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to parse services")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"vault": name, "services": services})
}

func (s *Server) handleServicesCredentialUsage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return
	}

	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	key := r.URL.Query().Get("key")
	if key == "" {
		jsonError(w, http.StatusBadRequest, "Missing required query parameter: key")
		return
	}

	bc, err := s.store.GetBrokerConfig(ctx, ns.ID)
	if err != nil || bc == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"services": []interface{}{}})
		return
	}

	var services []broker.Service
	if err := json.Unmarshal([]byte(bc.ServicesJSON), &services); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to parse services")
		return
	}

	type serviceRef struct {
		Host        string `json:"host"`
		Description string `json:"description,omitempty"`
	}
	var refs []serviceRef
	for _, svc := range services {
		for _, sk := range svc.Auth.CredentialKeys() {
			if sk == key {
				ref := serviceRef{Host: svc.Host}
				if svc.Description != nil {
					ref.Description = *svc.Description
				}
				refs = append(refs, ref)
				break
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if refs == nil {
		refs = []serviceRef{}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"services": refs})
}

func (s *Server) handleServicesSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return
	}

	// Setting services requires admin role.
	if _, err := s.requireVaultAdmin(w, r, ns.ID); err != nil {
		return
	}

	var req struct {
		Services json.RawMessage `json:"services"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate services by unmarshalling into broker.Service slice and running broker.Validate.
	var services []broker.Service
	if err := json.Unmarshal(req.Services, &services); err != nil {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid services: %v", err))
		return
	}
	cfg := broker.Config{Vault: name, Services: services}
	if err := broker.Validate(&cfg); err != nil {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid services: %v", err))
		return
	}

	servicesJSON, err := json.Marshal(services)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to marshal services")
		return
	}

	if _, err := s.store.SetBrokerConfig(ctx, ns.ID, string(servicesJSON)); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to set services")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"vault": name, "services_count": len(services)})
}

func (s *Server) handleServicesClear(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", name))
		return
	}

	// Clearing services requires admin role.
	if _, err := s.requireVaultAdmin(w, r, ns.ID); err != nil {
		return
	}

	if _, err := s.store.SetBrokerConfig(ctx, ns.ID, "[]"); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to clear services")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"vault": name, "cleared": true})
}

// ---------------------------------------------------------------------------
// Service catalog endpoint
// ---------------------------------------------------------------------------

func (s *Server) handleServiceCatalog(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"services": catalog.GetAll()})
}

// ---------------------------------------------------------------------------
// Skill serving endpoint
// ---------------------------------------------------------------------------

// SetSkills sets the embedded skill content for the CLI and HTTP skills.
func (s *Server) SetSkills(cli, httpSkill string) {
	s.skillCLI = []byte(cli)
	s.skillHTTP = []byte(httpSkill)
}

func (s *Server) handleSkillCLI(w http.ResponseWriter, r *http.Request) {
	s.serveSkill(w, r, s.skillCLI)
}

func (s *Server) handleSkillHTTP(w http.ResponseWriter, r *http.Request) {
	s.serveSkill(w, r, s.skillHTTP)
}

func (s *Server) serveSkill(w http.ResponseWriter, r *http.Request, content []byte) {
	if len(content) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	_, _ = w.Write(content)
}

// ---------------------------------------------------------------------------
// Invite create endpoint
// ---------------------------------------------------------------------------

func (s *Server) handleInviteCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		Vault             string `json:"vault"`
		Persistent        bool   `json:"persistent"`
		TTLSeconds        int    `json:"ttl_seconds"`
		AgentName         string `json:"agent_name"`
		VaultRole         string `json:"vault_role"`
		SessionTTLSeconds *int   `json:"session_ttl_seconds,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}
	if req.TTLSeconds <= 0 {
		req.TTLSeconds = 900 // 15 minutes default
	}
	// Determine if this is a persistent (named agent) invite.
	// persistent=true or agent_name set → persistent invite.
	isPersistent := req.Persistent || req.AgentName != ""
	// Cap invite TTL: 24 hours for temporary, 7 days for persistent.
	maxTTL := 24 * 60 * 60 // 24 hours
	if isPersistent {
		maxTTL = 7 * 24 * 60 * 60 // 7 days
	}
	if req.TTLSeconds > maxTTL {
		req.TTLSeconds = maxTTL
	}
	// session_ttl_seconds: nil = no expiry, >0 = finite session.
	// Cap finite session TTL using the same bounds as direct connect sessions.
	if req.SessionTTLSeconds != nil && *req.SessionTTLSeconds > 0 {
		ttl := *req.SessionTTLSeconds
		if ttl < directSessionMinTTL {
			ttl = directSessionMinTTL
			req.SessionTTLSeconds = &ttl
		} else if ttl > directSessionMaxTTL {
			ttl = directSessionMaxTTL
			req.SessionTTLSeconds = &ttl
		}
	}
	if req.VaultRole == "" {
		req.VaultRole = "proxy"
	}
	if req.VaultRole != "proxy" && req.VaultRole != "member" && req.VaultRole != "admin" {
		jsonError(w, http.StatusBadRequest, "Vault_role must be one of: proxy, member, admin")
		return
	}

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}

	// Role-based invite enforcement:
	// - Proxy-role agents cannot invite anyone.
	// - Members can invite agents but only as proxy.
	// - Admins (user vault admin or admin agent) can invite with any role.
	sess := sessionFromContext(ctx)
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return
	}

	cappedRole, errMsg := s.capRequestedRole(ctx, sess, ns.ID, req.VaultRole)
	if errMsg != "" {
		jsonError(w, http.StatusForbidden, errMsg)
		return
	}
	req.VaultRole = cappedRole

	// Check pending invite limit.
	count, err := s.store.CountPendingInvites(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to check pending invites")
		return
	}
	if count >= 10 {
		jsonError(w, http.StatusTooManyRequests, fmt.Sprintf("Too many pending invites (%d) — revoke some before creating new ones", count))
		return
	}

	createdBy := "api"
	if sess.UserID != "" {
		createdBy = sess.UserID
	}

	expiresAt := time.Now().Add(time.Duration(req.TTLSeconds) * time.Second)

	// Resolve session TTL: nil = no expiry (0 stored), pointer = finite.
	sessionTTL := 0
	if req.SessionTTLSeconds != nil {
		sessionTTL = *req.SessionTTLSeconds
	}

	if isPersistent {
		// Check for duplicate agent name.
		if req.AgentName != "" {
			existing, _ := s.store.GetAgentByName(ctx, req.AgentName)
			if existing != nil {
				jsonError(w, http.StatusConflict, fmt.Sprintf("An agent named %q already exists", req.AgentName))
				return
			}
		}

		inv, err := s.store.CreatePersistentInvite(ctx, ns.ID, req.VaultRole, createdBy, req.AgentName, expiresAt)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to create persistent invite")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":      inv.Token,
			"persistent": true,
			"agent_name": req.AgentName,
			"vault_role": inv.VaultRole,
			"expires_at": inv.ExpiresAt.Format(time.RFC3339),
		})
		return
	}

	inv, err := s.store.CreateInvite(ctx, ns.ID, req.VaultRole, createdBy, expiresAt, sessionTTL)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create invite")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":      inv.Token,
		"persistent": false,
		"vault_role": inv.VaultRole,
		"expires_at": inv.ExpiresAt.Format(time.RFC3339),
	})
}

// ---------------------------------------------------------------------------
// Admin proposal endpoints
// ---------------------------------------------------------------------------

func (s *Server) handleAdminProposalList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	nsName := r.URL.Query().Get("vault")
	if nsName == "" {
		nsName = store.DefaultVault
	}

	ns, err := s.store.GetVault(ctx, nsName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", nsName))
		return
	}

	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	// Proxy-role agents can only view pending proposals (to avoid duplicates).
	sess := sessionFromContext(r.Context())
	isProxy := sess != nil && sess.VaultID != "" && sess.VaultRole == "proxy"

	// Lazy expiration.
	_, _ = s.store.ExpirePendingProposals(ctx, time.Now().Add(-7*24*time.Hour))

	status := r.URL.Query().Get("status")
	if isProxy {
		status = "pending"
	}
	list, err := s.store.ListProposals(ctx, ns.ID, status)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list proposals")
		return
	}

	type csItem struct {
		ID          int     `json:"id"`
		Status      string  `json:"status"`
		Message     string  `json:"message"`
		ServicesJSON string  `json:"services_json"`
		CredentialsJSON string  `json:"credentials_json"`
		ReviewNote  string  `json:"review_note,omitempty"`
		ReviewedAt  *string `json:"reviewed_at,omitempty"`
		CreatedAt   string  `json:"created_at"`
	}

	items := make([]csItem, len(list))
	for i, cs := range list {
		item := csItem{
			ID:          cs.ID,
			Status:      cs.Status,
			Message:     cs.Message,
			ServicesJSON: cs.ServicesJSON,
			CredentialsJSON: cs.CredentialsJSON,
			ReviewNote:  cs.ReviewNote,
			CreatedAt:   cs.CreatedAt.Format(time.RFC3339),
		}
		if cs.ReviewedAt != nil {
			t := *cs.ReviewedAt
			item.ReviewedAt = &t
		}
		items[i] = item
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"proposals": items})
}

func (s *Server) handleAdminProposalGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	nsName := r.URL.Query().Get("vault")
	if nsName == "" {
		nsName = store.DefaultVault
	}

	ns, err := s.store.GetVault(ctx, nsName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", nsName))
		return
	}

	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid proposal id")
		return
	}

	cs, err := s.store.GetProposal(ctx, ns.ID, id)
	if err != nil || cs == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Proposal #%d not found in vault %q", id, nsName))
		return
	}

	// Proxy-role agents can only view pending proposals.
	sess := sessionFromContext(r.Context())
	if sess != nil && sess.VaultID != "" && sess.VaultRole == "proxy" && cs.Status != "pending" {
		jsonError(w, http.StatusForbidden, "Proxy-role agents can only view pending proposals")
		return
	}

	resp := map[string]interface{}{
		"id":           cs.ID,
		"status":       cs.Status,
		"message":      cs.Message,
		"user_message": cs.UserMessage,
		"services_json": cs.ServicesJSON,
		"credentials_json": cs.CredentialsJSON,
		"review_note":  cs.ReviewNote,
		"created_at":   cs.CreatedAt.Format(time.RFC3339),
	}
	if cs.ReviewedAt != nil {
		resp["reviewed_at"] = *cs.ReviewedAt
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// --- OAuth handlers ---

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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"providers": providers})
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"redirect_url": authURL})
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Provider disconnected"})
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

// --- Instance Settings ---

const settingAllowedDomains = "allowed_email_domains"
const settingInviteOnly = "invite_only"

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwner(w, r); err != nil {
		return
	}
	s.writeSettingsResponse(w, r.Context())
}

// writeSettingsResponse reads all settings and writes the JSON response.
func (s *Server) writeSettingsResponse(w http.ResponseWriter, ctx context.Context) {
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to read settings")
		return
	}

	resp := map[string]interface{}{
		"allowed_email_domains": []string{},
		"invite_only":          false,
		"smtp_configured":      s.notifier.Enabled(),
	}
	if raw, ok := settings[settingAllowedDomains]; ok {
		var domains []string
		if json.Unmarshal([]byte(raw), &domains) == nil {
			resp["allowed_email_domains"] = domains
		}
	}
	if raw, ok := settings[settingInviteOnly]; ok {
		resp["invite_only"] = raw == "true"
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwner(w, r); err != nil {
		return
	}

	var req struct {
		AllowedEmailDomains *[]string `json:"allowed_email_domains"`
		InviteOnly          *bool     `json:"invite_only"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ctx := r.Context()

	if req.InviteOnly != nil {
		val := "false"
		if *req.InviteOnly {
			val = "true"
		}
		if err := s.store.SetSetting(ctx, settingInviteOnly, val); err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to save settings")
			return
		}
	}

	if req.AllowedEmailDomains != nil {
		// Normalize: lowercase, trim whitespace, deduplicate, reject empty.
		seen := make(map[string]bool)
		var cleaned []string
		for _, d := range *req.AllowedEmailDomains {
			d = strings.ToLower(strings.TrimSpace(d))
			if d == "" {
				continue
			}
			// Basic domain validation: must contain at least one dot, no spaces.
			if !strings.Contains(d, ".") || strings.ContainsAny(d, " \t@") {
				jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid domain: %q", d))
				return
			}
			if !seen[d] {
				seen[d] = true
				cleaned = append(cleaned, d)
			}
		}

		if len(cleaned) == 0 {
			// Empty list = unrestricted, delete the setting.
			if err := s.store.SetSetting(ctx, settingAllowedDomains, "[]"); err != nil {
				jsonError(w, http.StatusInternalServerError, "Failed to save settings")
				return
			}
		} else {
			encoded, _ := json.Marshal(cleaned)
			if err := s.store.SetSetting(ctx, settingAllowedDomains, string(encoded)); err != nil {
				jsonError(w, http.StatusInternalServerError, "Failed to save settings")
				return
			}
		}
	}

	// Return the updated settings.
	s.writeSettingsResponse(w, r.Context())
}

// getAllowedDomains reads the allowed_email_domains setting from the store.
// Returns (nil, nil) if the setting is not set or is an empty array (unrestricted).
// Returns a non-nil error on database or parse failures so callers can fail closed.
func (s *Server) getAllowedDomains(ctx context.Context) ([]string, error) {
	raw, err := s.store.GetSetting(ctx, settingAllowedDomains)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // setting not configured — unrestricted
		}
		return nil, fmt.Errorf("failed to read allowed domains setting: %w", err)
	}
	var domains []string
	if err := json.Unmarshal([]byte(raw), &domains); err != nil {
		return nil, fmt.Errorf("failed to parse allowed domains setting: %w", err)
	}
	if len(domains) == 0 {
		return nil, nil
	}
	return domains, nil
}

// checkEmailDomain returns an error message if the email's domain is not in the allowed list.
// Returns "" if the domain is allowed or no restrictions are set.
// Returns a non-empty string on domain mismatch or on internal errors (fail-closed).
func (s *Server) checkEmailDomain(ctx context.Context, email string) string {
	domains, err := s.getAllowedDomains(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[agent-vault] %v\n", err)
		return "unable to verify email domain restrictions, please try again later"
	}
	if domains == nil {
		return ""
	}

	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return "invalid email address"
	}
	emailDomain := strings.ToLower(parts[1])

	for _, d := range domains {
		if emailDomain == d {
			return ""
		}
	}

	if len(domains) == 1 {
		return fmt.Sprintf("signups are restricted to @%s email addresses", domains[0])
	}
	return "signups are restricted to specific email domains"
}

// isInviteOnly returns true if invite-only registration mode is enabled.
// Fails closed: returns true on database/parse errors to prevent accidental open registration.
func (s *Server) isInviteOnly(ctx context.Context) bool {
	raw, err := s.store.GetSetting(ctx, settingInviteOnly)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false // setting not configured — open registration
		}
		fmt.Fprintf(os.Stderr, "[agent-vault] failed to read invite_only setting: %v\n", err)
		return true // fail closed
	}
	return raw == "true"
}
