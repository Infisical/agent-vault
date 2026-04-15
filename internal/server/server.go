package server

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"net"
	"sync"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/pidfile"
	"github.com/Infisical/agent-vault/internal/store"
)

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

// agentVaultJSON is the JSON representation of an agent's vault grant (reused across handlers).
type agentVaultJSON struct {
	VaultName string `json:"vault_name"`
	VaultRole string `json:"vault_role"`
}

// Server is the Agent Vault HTTP server.
type Server struct {
	httpServer     *http.Server
	store          Store
	encKey         []byte // 32-byte encryption key, held in memory while running
	notifier       *notify.Notifier
	initialized    bool   // true when at least one owner account exists
	baseURL        string // externally-reachable base URL (e.g. "https://sb.example.com")
	oauthProviders map[string]oauth.Provider
	skillCLI       []byte // embedded CLI skill content (served at GET /v1/skills/cli)
	skillHTTP      []byte // embedded HTTP skill content (served at GET /v1/skills/http)
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

	// Vault grants (unified: actor_id + actor_type)
	GrantVaultRole(ctx context.Context, actorID, actorType, vaultID, role string) error
	RevokeVaultAccess(ctx context.Context, actorID, vaultID string) error
	ListActorGrants(ctx context.Context, actorID string) ([]store.VaultGrant, error)
	HasVaultAccess(ctx context.Context, actorID, vaultID string) (bool, error)
	GetVaultRole(ctx context.Context, actorID, vaultID string) (string, error)
	CountVaultAdmins(ctx context.Context, vaultID string) (int, error)
	ListVaultMembers(ctx context.Context, vaultID string) ([]store.VaultGrant, error)
	ListVaultMembersByType(ctx context.Context, vaultID, actorType string) ([]store.VaultGrant, error)

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

	// Agent invites (instance-level)
	CreateAgentInvite(ctx context.Context, agentName, createdBy string, expiresAt time.Time, sessionTTLSeconds int, agentRole string, vaults []store.AgentInviteVault) (*store.Invite, error)
	CreateRotationInvite(ctx context.Context, agentID, createdBy string, expiresAt time.Time) (*store.Invite, error)
	GetInviteByToken(ctx context.Context, token string) (*store.Invite, error)
	ListInvites(ctx context.Context, status string) ([]store.Invite, error)
	ListInvitesByVault(ctx context.Context, vaultID, status string) ([]store.Invite, error)
	RedeemInvite(ctx context.Context, token, sessionID string) error
	UpdateInviteSessionID(ctx context.Context, inviteID int, sessionID string) error
	RevokeInvite(ctx context.Context, token string) error
	GetInviteByID(ctx context.Context, id int) (*store.Invite, error)
	RevokeInviteByID(ctx context.Context, id int) error
	CountPendingInvites(ctx context.Context) (int, error)
	HasPendingInviteByAgentName(ctx context.Context, name string) (bool, error)
	GetPendingInviteByAgentName(ctx context.Context, name string) (*store.Invite, error)
	AddAgentInviteVault(ctx context.Context, inviteID int, vaultID, role string) error
	RemoveAgentInviteVault(ctx context.Context, inviteID int, vaultID string) error
	UpdateAgentInviteVaultRole(ctx context.Context, inviteID int, vaultID, role string) error
	ExpirePendingInvites(ctx context.Context, before time.Time) (int, error)

	// User invites (instance-level)
	CreateUserInvite(ctx context.Context, email, createdBy, role string, expiresAt time.Time, vaults []store.UserInviteVault) (*store.UserInvite, error)
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
	CreateAgent(ctx context.Context, name, createdBy, role string) (*store.Agent, error)
	GetAgentByID(ctx context.Context, id string) (*store.Agent, error)
	GetAgentByName(ctx context.Context, name string) (*store.Agent, error)
	ListAgents(ctx context.Context, vaultID string) ([]store.Agent, error)
	ListAllAgents(ctx context.Context) ([]store.Agent, error)
	RevokeAgent(ctx context.Context, id string) error
	RenameAgent(ctx context.Context, id string, newName string) error
	UpdateAgentRole(ctx context.Context, agentID, role string) error
	CountAgentSessions(ctx context.Context, agentID string) (int, error)
	GetLatestAgentSessionExpiry(ctx context.Context, agentID string) (*time.Time, error)
	DeleteAgentSessions(ctx context.Context, agentID string) error
	CreateAgentSession(ctx context.Context, agentID string, expiresAt *time.Time) (*store.Session, error)
	CountAllOwners(ctx context.Context) (int, error)

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

// Actor represents an authenticated entity (user or agent) with an instance-level role.
// All permission checks operate on Actor, making the system role-based rather than type-based.
type Actor struct {
	ID    string       // user.ID or agent.ID
	Type  string       // "user" or "agent"
	Role  string       // "owner" or "member" (instance-level)
	User  *store.User  // non-nil for user actors
	Agent *store.Agent // non-nil for agent actors
}

// IsOwner returns true if the actor has the instance-level owner role.
func (a *Actor) IsOwner() bool { return a.Role == "owner" }

// DisplayLabel returns a human-readable label for the actor (email for users, name for agents).
func (a *Actor) DisplayLabel() string {
	if a.User != nil {
		return a.User.Email
	}
	if a.Agent != nil {
		return a.Agent.Name
	}
	return a.ID
}

// actorFromSession resolves any session to an Actor.
func (s *Server) actorFromSession(ctx context.Context, sess *store.Session) (*Actor, error) {
	if sess == nil {
		return nil, fmt.Errorf("no session")
	}
	if sess.UserID != "" {
		user, err := s.store.GetUserByID(ctx, sess.UserID)
		if err != nil || user == nil {
			return nil, fmt.Errorf("user not found")
		}
		return &Actor{ID: user.ID, Type: "user", Role: user.Role, User: user}, nil
	}
	if sess.AgentID != "" {
		agent, err := s.store.GetAgentByID(ctx, sess.AgentID)
		if err != nil || agent == nil {
			return nil, fmt.Errorf("agent not found")
		}
		return &Actor{ID: agent.ID, Type: "agent", Role: agent.Role, Agent: agent}, nil
	}
	return nil, fmt.Errorf("session has no actor")
}

// requireActor checks that the request is from any authenticated actor (user or agent).
func (s *Server) requireActor(w http.ResponseWriter, r *http.Request) (*Actor, error) {
	sess := sessionFromContext(r.Context())
	actor, err := s.actorFromSession(r.Context(), sess)
	if err != nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return nil, err
	}
	return actor, nil
}

// requireOwnerActor checks that the request is from an owner (user OR agent).
func (s *Server) requireOwnerActor(w http.ResponseWriter, r *http.Request) (*Actor, error) {
	actor, err := s.requireActor(w, r)
	if err != nil {
		return nil, err
	}
	if !actor.IsOwner() {
		jsonError(w, http.StatusForbidden, "Owner role required")
		return nil, fmt.Errorf("not owner")
	}
	return actor, nil
}

// guardLastOwner checks that removing/demoting an owner would not leave zero owners.
// Returns true if the operation is blocked (error already written to w).
func (s *Server) guardLastOwner(ctx context.Context, w http.ResponseWriter, action string) bool {
	count, err := s.store.CountAllOwners(ctx)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to count owners")
		return true
	}
	if count <= 1 {
		jsonError(w, http.StatusConflict, "Cannot "+action+" the last owner")
		return true
	}
	return false
}


// requireVaultAccess checks that the session has access to the given vault.
// For scoped sessions (VaultID set): checks that the session's vault matches.
// For instance-level sessions: resolves actor and checks the unified vault_grants table.
// Returns the actor (nil for scoped sessions) or writes an error response.
func (s *Server) requireVaultAccess(w http.ResponseWriter, r *http.Request, vaultID string) (*Actor, error) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return nil, fmt.Errorf("no session")
	}

	// Scoped session: vault is baked into the session.
	if sess.VaultID != "" {
		if sess.VaultID != vaultID {
			jsonError(w, http.StatusForbidden, "Session not authorized for this vault")
			return nil, fmt.Errorf("vault mismatch")
		}
		return nil, nil // scoped session, no actor resolved
	}

	// Instance-level session: resolve actor, check unified vault_grants.
	actor, err := s.actorFromSession(r.Context(), sess)
	if err != nil {
		jsonError(w, http.StatusForbidden, "Invalid session")
		return nil, err
	}

	has, err := s.store.HasVaultAccess(r.Context(), actor.ID, vaultID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to check vault access")
		return nil, err
	}
	if !has {
		jsonError(w, http.StatusForbidden, "No access to this vault")
		return nil, fmt.Errorf("no grant")
	}

	return actor, nil
}

// requireVaultAdmin checks that the actor has admin role in the given vault.
// For scoped sessions: checks sess.VaultRole. For instance-level sessions: checks vault_grants.
func (s *Server) requireVaultAdmin(w http.ResponseWriter, r *http.Request, vaultID string) (*Actor, error) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return nil, fmt.Errorf("no session")
	}

	// Scoped session: check role from session.
	if sess.VaultID != "" {
		if sess.VaultID != vaultID {
			jsonError(w, http.StatusForbidden, "Session not authorized for this vault")
			return nil, fmt.Errorf("vault mismatch")
		}
		if !roleSatisfies(sess.VaultRole, "admin") {
			jsonError(w, http.StatusForbidden, "Vault admin role required")
			return nil, fmt.Errorf("insufficient role: %s", sess.VaultRole)
		}
		return nil, nil
	}

	// Instance-level session: single GetVaultRole call (covers both existence and role check).
	actor, err := s.actorFromSession(r.Context(), sess)
	if err != nil {
		jsonError(w, http.StatusForbidden, "Invalid session")
		return nil, err
	}
	role, err := s.store.GetVaultRole(r.Context(), actor.ID, vaultID)
	if err != nil {
		jsonError(w, http.StatusForbidden, "No access to this vault")
		return nil, fmt.Errorf("no vault grant")
	}
	if role != "admin" {
		jsonError(w, http.StatusForbidden, "Vault admin role required")
		return nil, fmt.Errorf("not vault admin")
	}
	return actor, nil
}

// roleSatisfies returns true if role is at least as privileged as requiredRole.
// Hierarchy: proxy(0) < member(1) < admin(2).
var roleRank = map[string]int{"proxy": 0, "member": 1, "admin": 2}

func roleSatisfies(role, requiredRole string) bool {
	return roleRank[role] >= roleRank[requiredRole]
}

// requireVaultMember checks that the session has member+ access to the vault.
// For scoped sessions: requires sess.VaultRole is "member" or "admin".
// For instance-level sessions: checks the unified vault_grants table.
func (s *Server) requireVaultMember(w http.ResponseWriter, r *http.Request, vaultID string) (*Actor, error) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return nil, fmt.Errorf("no session")
	}

	// Scoped session: check vault_role from session.
	if sess.VaultID != "" {
		if sess.VaultID != vaultID {
			jsonError(w, http.StatusForbidden, "Session not authorized for this vault")
			return nil, fmt.Errorf("vault mismatch")
		}
		if !roleSatisfies(sess.VaultRole, "member") {
			jsonError(w, http.StatusForbidden, "Member role required")
			return nil, fmt.Errorf("insufficient role: %s", sess.VaultRole)
		}
		return nil, nil
	}

	// Instance-level session: check vault grant and role.
	actor, err := s.actorFromSession(r.Context(), sess)
	if err != nil {
		jsonError(w, http.StatusForbidden, "Invalid session")
		return nil, err
	}

	role, err := s.store.GetVaultRole(r.Context(), actor.ID, vaultID)
	if err != nil {
		jsonError(w, http.StatusForbidden, "No access to this vault")
		return nil, fmt.Errorf("no vault grant")
	}
	if !roleSatisfies(role, "member") {
		jsonError(w, http.StatusForbidden, "Member role required")
		return nil, fmt.Errorf("insufficient role: %s", role)
	}
	return actor, nil
}

// requireProposalReview checks proposal approve/reject access.
// Scoped sessions require admin role (proxy-role actors cannot self-approve).
// Instance-level sessions require any vault access (member or admin — by design).
func (s *Server) requireProposalReview(w http.ResponseWriter, r *http.Request, vaultID string) (*Actor, error) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return nil, fmt.Errorf("no session")
	}

	// Scoped session: require admin role.
	if sess.VaultID != "" {
		if sess.VaultID != vaultID {
			jsonError(w, http.StatusForbidden, "Session not authorized for this vault")
			return nil, fmt.Errorf("vault mismatch")
		}
		if !roleSatisfies(sess.VaultRole, "admin") {
			jsonError(w, http.StatusForbidden, "Admin role required")
			return nil, fmt.Errorf("insufficient role: %s", sess.VaultRole)
		}
		return nil, nil
	}

	// Instance-level session: any vault member can review proposals.
	return s.requireVaultAccess(w, r, vaultID)
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
	mux.HandleFunc("POST /v1/sessions", s.requireInitialized(s.requireAuth(limitBody(s.handleScopedSession))))
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

	// Agent invite redemption (no auth — token is the credential)
	mux.HandleFunc("GET /invite/{token}", s.requireInitialized(s.handleInviteRedeem))
	mux.HandleFunc("POST /invite/{token}", s.requireInitialized(limitBody(s.handlePersistentInviteRedeem)))

	// Agent invites (instance-level, requires auth)
	mux.HandleFunc("POST /v1/agents/invites", s.requireInitialized(s.requireAuth(limitBody(s.handleAgentInviteCreate))))
	mux.HandleFunc("GET /v1/agents/invites", s.requireInitialized(s.requireAuth(s.handleAgentInviteList)))
	mux.HandleFunc("DELETE /v1/agents/invites/{token}", s.requireInitialized(s.requireAuth(s.handleAgentInviteRevoke)))
	mux.HandleFunc("DELETE /v1/agents/invites/by-id/{id}", s.requireInitialized(s.requireAuth(s.handleAgentInviteRevokeByID)))

	// Agent management (instance-level)
	mux.HandleFunc("GET /v1/agents", s.requireInitialized(s.requireAuth(s.handleAgentList)))
	mux.HandleFunc("GET /v1/agents/{name}", s.requireInitialized(s.requireAuth(s.handleAgentGet)))
	mux.HandleFunc("DELETE /v1/agents/{name}", s.requireInitialized(s.requireAuth(s.handleAgentRevoke)))
	mux.HandleFunc("POST /v1/agents/{name}/rotate", s.requireInitialized(s.requireAuth(limitBody(s.handleAgentRotate))))
	mux.HandleFunc("POST /v1/agents/{name}/rename", s.requireInitialized(s.requireAuth(limitBody(s.handleAgentRename))))
	mux.HandleFunc("POST /v1/agents/{name}/role", s.requireInitialized(s.requireAuth(limitBody(s.handleAgentSetRole))))

	// Vault-level agent management
	mux.HandleFunc("GET /v1/vaults/{name}/agents", s.requireInitialized(s.requireAuth(s.handleVaultAgentList)))
	mux.HandleFunc("POST /v1/vaults/{name}/agents", s.requireInitialized(s.requireAuth(limitBody(s.handleVaultAgentAdd))))
	mux.HandleFunc("DELETE /v1/vaults/{name}/agents/{agentName}", s.requireInitialized(s.requireAuth(s.handleVaultAgentRemove)))
	mux.HandleFunc("POST /v1/vaults/{name}/agents/{agentName}/role", s.requireInitialized(s.requireAuth(limitBody(s.handleVaultAgentSetRole))))

	// Instance settings (owner-only)
	mux.HandleFunc("GET /v1/admin/settings", s.requireInitialized(s.requireAuth(s.handleGetSettings)))
	mux.HandleFunc("PUT /v1/admin/settings", s.requireInitialized(s.requireAuth(limitBody(s.handleUpdateSettings))))

	// Public user list (any authenticated user)
	mux.HandleFunc("GET /v1/users", s.requireInitialized(s.requireAuth(s.handlePublicUserList)))

	// User management (owner-only, except GET self)
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
			jsonStatus(w, http.StatusServiceUnavailable, map[string]string{
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

var errTooManyPendingCodes = errors.New("too many pending verification codes")

const passwordResetTTL = 15 * time.Minute

const maxPendingPasswordResets = 3

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

const sessionTTL = 24 * time.Hour

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

// slidingWindowLimiter is a generic sliding-window rate limiter keyed by string.
type slidingWindowLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	window   time.Duration
	max      int
	maxKeys  int // max map keys before eviction (0 = unlimited)
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
	loginIPLimiter          = newSlidingWindowLimiter(loginRateWindow, loginRateMax, 10000)
	loginEmailLimiter       = newSlidingWindowLimiter(loginRateWindow, loginRateMax, 10000)
	registerLimiter         = newSlidingWindowLimiter(loginRateWindow, 5, 10000)  // 5 registrations per IP per 5 min
	forgotPasswordLimiter   = newSlidingWindowLimiter(loginRateWindow, 5, 10000)  // 5 forgot-password requests per IP per 5 min
	resendVerifyLimiter     = newSlidingWindowLimiter(loginRateWindow, 5, 10000)  // 5 resend-verification requests per IP per 5 min
	userInviteAcceptLimiter = newSlidingWindowLimiter(loginRateWindow, 10, 10000) // 10 invite accepts per IP per 5 min
	resetVerifyLimiter      = &verifyRateLimiter{attempts: make(map[string]int), maxKeys: maxVerifyKeys}
)

var (
	dummyPasswordHash []byte
	dummyPasswordSalt []byte
	dummyKDFParams    crypto.KDFParams
)

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
			jsonError(w, http.StatusUnauthorized, "Authorization required")
			return
		}

		sess, err := s.store.GetSession(r.Context(), token)
		if err != nil || sess == nil {
			jsonError(w, http.StatusUnauthorized, "Invalid or expired session")
			return
		}
		if sessionExpired(sess) {
			jsonError(w, http.StatusUnauthorized, "Session expired")
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

const (
	scopedSessionMinTTL = 5 * 60        // 5 minutes
	scopedSessionMaxTTL = 7 * 24 * 3600 // 7 days
)

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

const settingAllowedDomains = "allowed_email_domains"

const settingInviteOnly = "invite_only"
