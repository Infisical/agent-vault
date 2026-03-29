package server

import (
	"context"
	crand "crypto/rand"
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net/http"
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
	"github.com/Infisical/agent-vault/internal/proposal"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/pidfile"
	"github.com/Infisical/agent-vault/internal/store"
)

//go:embed instructions_consumer.txt
var instructionsConsumer string

//go:embed instructions_member.txt
var instructionsMember string

//go:embed instructions_admin.txt
var instructionsAdmin string

//go:embed all:webdist
var webDistFS embed.FS

//go:embed invite_email.html
var userInviteEmailHTML string

// Server is the Agent Vault HTTP server.
type Server struct {
	httpServer  *http.Server
	store       Store
	encKey      []byte // 32-byte encryption key, held in memory while running
	notifier    *notify.Notifier
	initialized bool   // true when at least one owner account exists
	baseURL     string // externally-reachable base URL (e.g. "https://sb.example.com")
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
	CreateScopedSession(ctx context.Context, vaultID, vaultRole string, expiresAt time.Time) (*store.Session, error)
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
	SetBrokerConfig(ctx context.Context, vaultID, rulesJSON string) (*store.BrokerConfig, error)

	// Proposals
	CreateProposal(ctx context.Context, vaultID, sessionID, rulesJSON, credentialsJSON, message, userMessage string, credentials map[string]store.EncryptedCredential) (*store.Proposal, error)
	GetProposal(ctx context.Context, vaultID string, id int) (*store.Proposal, error)
	GetProposalByApprovalToken(ctx context.Context, token string) (*store.Proposal, error)
	ListProposals(ctx context.Context, vaultID, status string) ([]store.Proposal, error)
	CountPendingProposals(ctx context.Context, vaultID string) (int, error)
	UpdateProposalStatus(ctx context.Context, vaultID string, id int, status, reviewNote string) error
	GetProposalCredentials(ctx context.Context, vaultID string, proposalID int) (map[string]store.EncryptedCredential, error)
	ApplyProposal(ctx context.Context, vaultID string, proposalID int, mergedRulesJSON string, credentials map[string]store.EncryptedCredential, deleteCredentialKeys []string) error
	ExpirePendingProposals(ctx context.Context, before time.Time) (int, error)

	// Invites
	CreateInvite(ctx context.Context, vaultID, vaultRole, createdBy string, expiresAt time.Time) (*store.Invite, error)
	GetInviteByToken(ctx context.Context, token string) (*store.Invite, error)
	ListInvites(ctx context.Context, vaultID, status string) ([]store.Invite, error)
	RedeemInvite(ctx context.Context, token, sessionID string) error
	RevokeInvite(ctx context.Context, token string) error
	CountPendingInvites(ctx context.Context, vaultID string) (int, error)
	ExpirePendingInvites(ctx context.Context, before time.Time) (int, error)

	// Vault invites
	CreateVaultInvite(ctx context.Context, email, vaultID, vaultRole, createdBy string, expiresAt time.Time) (*store.VaultInvite, error)
	GetVaultInviteByToken(ctx context.Context, token string) (*store.VaultInvite, error)
	GetPendingVaultInviteByEmailAndVault(ctx context.Context, email, vaultID string) (*store.VaultInvite, error)
	ListVaultInvites(ctx context.Context, vaultID, status string) ([]store.VaultInvite, error)
	AcceptVaultInvite(ctx context.Context, token string) error
	RevokeVaultInvite(ctx context.Context, token, vaultID string) error
	UpdateVaultInviteRole(ctx context.Context, token, vaultID, newRole string) error
	CountPendingVaultInvites(ctx context.Context, vaultID string) (int, error)

	// Email verification
	CreateEmailVerification(ctx context.Context, email, code string, expiresAt time.Time) (*store.EmailVerification, error)
	GetPendingEmailVerification(ctx context.Context, email, code string) (*store.EmailVerification, error)
	MarkEmailVerificationUsed(ctx context.Context, id int) error
	CountPendingEmailVerifications(ctx context.Context, email string) (int, error)

	// Agents
	CreateAgent(ctx context.Context, name, vaultID string, tokenHash, tokenSalt []byte, tokenPrefix, vaultRole, createdBy string) (*store.Agent, error)
	GetAgentByID(ctx context.Context, id string) (*store.Agent, error)
	GetAgentByName(ctx context.Context, name string) (*store.Agent, error)
	GetAgentByTokenPrefix(ctx context.Context, prefix string) (*store.Agent, error)
	ListAgents(ctx context.Context, vaultID string) ([]store.Agent, error)
	RevokeAgent(ctx context.Context, id string) error
	UpdateAgentServiceToken(ctx context.Context, id string, tokenHash, tokenSalt []byte, tokenPrefix string) error
	UpdateAgentVaultRole(ctx context.Context, id, role string) error
	RenameAgent(ctx context.Context, id string, newName string) error
	CountAgentSessions(ctx context.Context, agentID string) (int, error)
	GetLatestAgentSessionExpiry(ctx context.Context, agentID string) (*time.Time, error)
	DeleteAgentSessions(ctx context.Context, agentID string) error
	CreateAgentSession(ctx context.Context, agentID, vaultID, vaultRole string, expiresAt time.Time) (*store.Session, error)
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
		jsonError(w, http.StatusForbidden, "owner session required")
		return nil, fmt.Errorf("no user session")
	}
	user, err := s.userFromSession(r.Context(), sess)
	if err != nil || user == nil {
		jsonError(w, http.StatusForbidden, "owner session required")
		return nil, fmt.Errorf("user not found")
	}
	if user.Role != "owner" {
		jsonError(w, http.StatusForbidden, "owner role required")
		return nil, fmt.Errorf("not owner")
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
		jsonError(w, http.StatusForbidden, "authentication required")
		return nil, fmt.Errorf("no session")
	}

	// Agent session: relies on vault_id scoping.
	if sess.VaultID != "" {
		if sess.VaultID != vaultID {
			jsonError(w, http.StatusForbidden, "session not authorized for this vault")
			return nil, fmt.Errorf("vault mismatch")
		}
		return nil, nil // agent session, no user
	}

	// User session: check grants (no implicit owner bypass).
	user, err := s.userFromSession(r.Context(), sess)
	if err != nil || user == nil {
		jsonError(w, http.StatusForbidden, "invalid session")
		return nil, fmt.Errorf("user not found")
	}

	// All users need an explicit grant.
	has, err := s.store.HasVaultAccess(r.Context(), user.ID, vaultID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to check vault access")
		return nil, err
	}
	if !has {
		jsonError(w, http.StatusForbidden, "no access to this vault")
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
		jsonError(w, http.StatusForbidden, "vault admin role required")
		return nil, fmt.Errorf("agent session")
	}

	role, err := s.store.GetVaultRole(r.Context(), user.ID, vaultID)
	if err != nil || role != "admin" {
		jsonError(w, http.StatusForbidden, "vault admin role required")
		return nil, fmt.Errorf("not vault admin")
	}
	return user, nil
}

// agentRoleSatisfies returns true if agentRole is at least as privileged as requiredRole.
// Hierarchy: consumer(0) < member(1) < admin(2).
func agentRoleSatisfies(agentRole, requiredRole string) bool {
	rank := map[string]int{"consumer": 0, "member": 1, "admin": 2}
	return rank[agentRole] >= rank[requiredRole]
}

// requireVaultMember checks that the session has member+ access to the vault.
// For agent/scoped sessions: requires sess.VaultRole is "member" or "admin".
// For user sessions: requires vault access (user vault role is not checked — any user
// with vault access is considered at least a member).
func (s *Server) requireVaultMember(w http.ResponseWriter, r *http.Request, vaultID string) (*store.User, error) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		jsonError(w, http.StatusForbidden, "authentication required")
		return nil, fmt.Errorf("no session")
	}

	// Scoped session (agent or temp invite): check vault_role.
	if sess.VaultID != "" {
		if sess.VaultID != vaultID {
			jsonError(w, http.StatusForbidden, "session not authorized for this vault")
			return nil, fmt.Errorf("vault mismatch")
		}
		if !agentRoleSatisfies(sess.VaultRole, "member") {
			jsonError(w, http.StatusForbidden, "member role required")
			return nil, fmt.Errorf("insufficient role: %s", sess.VaultRole)
		}
		return nil, nil
	}

	// User session: any user with vault access is a member+.
	return s.requireVaultAccess(w, r, vaultID)
}

// requireVaultAdminSession checks that the session has admin access to the vault.
// For agent/scoped sessions: requires sess.VaultRole == "admin".
// For user sessions: requires vault admin role.
func (s *Server) requireVaultAdminSession(w http.ResponseWriter, r *http.Request, vaultID string) (*store.User, error) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		jsonError(w, http.StatusForbidden, "authentication required")
		return nil, fmt.Errorf("no session")
	}

	// Scoped session (agent or temp invite): check vault_role.
	if sess.VaultID != "" {
		if sess.VaultID != vaultID {
			jsonError(w, http.StatusForbidden, "session not authorized for this vault")
			return nil, fmt.Errorf("vault mismatch")
		}
		if sess.VaultRole != "admin" {
			jsonError(w, http.StatusForbidden, "admin role required")
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
func New(addr string, store Store, encKey []byte, notifier *notify.Notifier, initialized bool, baseURL string) *Server {
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
		store:       store,
		encKey:      encKey,
		notifier:    notifier,
		initialized: initialized,
		baseURL:     strings.TrimRight(baseURL, "/"),
	}

	// Always available (no initialization required)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /v1/status", s.handleStatus)
	mux.HandleFunc("POST /v1/auth/register", limitBody(s.handleRegister))
	mux.HandleFunc("POST /v1/auth/verify", limitBody(s.handleVerify))

	// Require initialization
	mux.HandleFunc("GET /v1/auth/me", s.requireInitialized(s.requireAuth(s.handleAuthMe)))
	mux.HandleFunc("POST /v1/auth/login", s.requireInitialized(limitBody(s.handleLogin)))
	mux.HandleFunc("POST /v1/auth/change-password", s.requireInitialized(s.requireAuth(limitBody(s.handleChangePassword))))
	mux.HandleFunc("DELETE /v1/auth/account", s.requireInitialized(s.requireAuth(s.handleDeleteAccount)))
	mux.HandleFunc("POST /v1/sessions/scoped", s.requireInitialized(s.requireAuth(limitBody(s.handleScopedSession))))
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

	// Agent session minting (service token is the credential, no requireAuth)
	mux.HandleFunc("POST /v1/agent/session", s.requireInitialized(limitBody(s.handleAgentSessionMint)))

	// Agent management (owner-only)
	mux.HandleFunc("GET /v1/admin/agents", s.requireInitialized(s.requireAuth(s.handleAgentList)))
	mux.HandleFunc("GET /v1/admin/agents/{name}", s.requireInitialized(s.requireAuth(s.handleAgentGet)))
	mux.HandleFunc("DELETE /v1/admin/agents/{name}", s.requireInitialized(s.requireAuth(s.handleAgentRevoke)))
	mux.HandleFunc("POST /v1/admin/agents/{name}/rotate", s.requireInitialized(s.requireAuth(limitBody(s.handleAgentRotate))))
	mux.HandleFunc("POST /v1/admin/agents/{name}/rename", s.requireInitialized(s.requireAuth(limitBody(s.handleAgentRename))))
	mux.HandleFunc("POST /v1/admin/agents/{name}/vault-role", s.requireInitialized(s.requireAuth(limitBody(s.handleAgentSetRole))))

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

	// Vault admin (owner-only)
	mux.HandleFunc("GET /v1/admin/vaults", s.requireInitialized(s.requireAuth(s.handleAdminVaultList)))
	mux.HandleFunc("GET /v1/vaults/{name}/policy", s.requireInitialized(s.requireAuth(s.handlePolicyGet)))
	mux.HandleFunc("PUT /v1/vaults/{name}/policy", s.requireInitialized(s.requireAuth(limitBody(s.handlePolicySet))))
	mux.HandleFunc("DELETE /v1/vaults/{name}/policy", s.requireInitialized(s.requireAuth(s.handlePolicyClear)))
	mux.HandleFunc("GET /v1/vaults/{name}/policy/credential-usage", s.requireInitialized(s.requireAuth(s.handlePolicyCredentialUsage)))

	// Vault invites
	mux.HandleFunc("GET /v1/vault-invites/{token}/details", s.requireInitialized(s.handleVaultInviteDetails))
	mux.HandleFunc("POST /v1/vault-invites/{token}/accept", s.requireInitialized(limitBody(s.handleVaultInviteAccept)))

	// Vault invite management (vault admin)
	mux.HandleFunc("POST /v1/vaults/{name}/invites", s.requireInitialized(s.requireAuth(limitBody(s.handleVaultInviteCreate))))
	mux.HandleFunc("GET /v1/vaults/{name}/invites", s.requireInitialized(s.requireAuth(s.handleVaultInviteList)))
	mux.HandleFunc("DELETE /v1/vaults/{name}/invites/{token}", s.requireInitialized(s.requireAuth(s.handleVaultInviteRevoke)))
	mux.HandleFunc("POST /v1/vaults/{name}/invites/{token}/reinvite", s.requireInitialized(s.requireAuth(limitBody(s.handleVaultInviteReinvite))))
	mux.HandleFunc("PATCH /v1/vaults/{name}/invites/{token}", s.requireInitialized(s.requireAuth(limitBody(s.handleVaultInviteUpdate))))

	// Vault user management (vault admin)
	mux.HandleFunc("GET /v1/vaults/{name}/users", s.requireInitialized(s.requireAuth(s.handleVaultUserList)))
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

	// React app static assets (Vite outputs to /assets/ with base "/")
	webFS, _ := fs.Sub(webDistFS, "webdist")
	mux.Handle("GET /assets/", http.FileServer(http.FS(webFS)))
	mux.Handle("GET /vite.svg", http.FileServer(http.FS(webFS)))

	// SPA catch-all: serve index.html for all frontend routes
	mux.HandleFunc("GET /login", s.handleSPA)
	mux.HandleFunc("GET /register", s.handleSPA)
	mux.HandleFunc("GET /vaults/{$}", s.handleSPA)
	mux.HandleFunc("GET /vaults/{name...}", s.handleSPA)
	mux.HandleFunc("GET /vault-invite/{token...}", s.handleSPA)
	mux.HandleFunc("GET /approve/{id...}", s.handleSPA)
	mux.HandleFunc("GET /manage/{path...}", s.handleSPA)
	mux.HandleFunc("GET /change-password", s.handleSPA)
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
				"message": "No owner account exists. Run 'agent-vault register' to create the first account.",
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
		fmt.Printf("Agent Vault server listening on %s\n", s.httpServer.Addr)
		if !s.initialized {
			fmt.Printf("  → Visit %s/register to create the owner account\n", s.baseURL)
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

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := auth.ValidateEmail(req.Email); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Password) < 8 {
		jsonError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	// Rate limit registrations by IP to prevent account creation floods.
	ip := clientIP(r)
	if !registerLimiter.allow(ip) {
		jsonError(w, http.StatusTooManyRequests, "too many registration attempts, try again later")
		return
	}

	ctx := r.Context()

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
		jsonError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	// If an inactive user exists, update their password and resend verification.
	if existing != nil && !existing.IsActive {
		if err := s.store.UpdateUserPassword(ctx, existing.ID, hash, salt, kdfParams.Time, kdfParams.Memory, kdfParams.Threads); err != nil {
			jsonError(w, http.StatusInternalServerError, "failed to update account")
			return
		}

		// Rate limit verification codes.
		pendingCount, _ := s.store.CountPendingEmailVerifications(ctx, req.Email)
		if pendingCount >= maxPendingVerifications {
			jsonError(w, http.StatusTooManyRequests, "too many pending verification codes")
			return
		}

		// Generate 6-digit verification code.
		codeInt, _ := crand.Int(crand.Reader, big.NewInt(1_000_000))
		code := fmt.Sprintf("%06d", codeInt.Int64())

		_, err = s.store.CreateEmailVerification(ctx, req.Email, code, time.Now().Add(emailVerificationTTL))
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "failed to create verification")
			return
		}

		emailSent := false
		if s.notifier.Enabled() {
			body := fmt.Sprintf("Your Agent Vault verification code is: %s\n\nThis code expires in 15 minutes.", code)
			if err := s.notifier.SendMail([]string{req.Email}, "Agent Vault verification code", body); err != nil {
				fmt.Fprintf(os.Stderr, "[agent-vault] Failed to send verification email to %s: %v\n", req.Email, err)
				fmt.Fprintf(os.Stderr, "[agent-vault] Email verification code for %s: %s\n", req.Email, code)
			} else {
				emailSent = true
			}
		} else {
			fmt.Fprintf(os.Stderr, "[agent-vault] Email verification code for %s: %s\n", req.Email, code)
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
			jsonError(w, http.StatusInternalServerError, "failed to create session")
			return
		}
		http.SetCookie(w, sessionCookie(r, session.ID, int(sessionTTL.Seconds())))

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
		jsonError(w, http.StatusInternalServerError, "failed to create owner account")
		return
	}

	// Not the first user: create as inactive member, require email verification.
	_, err = s.store.CreateUser(ctx, req.Email, hash, salt, "member", kdfParams.Time, kdfParams.Memory, kdfParams.Threads)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	// Rate limit verification codes.
	pendingCount, _ := s.store.CountPendingEmailVerifications(ctx, req.Email)
	if pendingCount >= maxPendingVerifications {
		jsonError(w, http.StatusTooManyRequests, "too many pending verification codes")
		return
	}

	// Generate 6-digit verification code (uniform distribution via rejection sampling).
	codeInt, _ := crand.Int(crand.Reader, big.NewInt(1_000_000))
	code := fmt.Sprintf("%06d", codeInt.Int64())

	_, err = s.store.CreateEmailVerification(ctx, req.Email, code, time.Now().Add(emailVerificationTTL))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create verification")
		return
	}

	// Send verification code via email or log to stderr.
	emailSent := false
	if s.notifier.Enabled() {
		body := fmt.Sprintf("Your Agent Vault verification code is: %s\n\nThis code expires in 15 minutes.", code)
		if err := s.notifier.SendMail([]string{req.Email}, "Agent Vault verification code", body); err != nil {
			fmt.Fprintf(os.Stderr, "[agent-vault] Failed to send verification email to %s: %v\n", req.Email, err)
			fmt.Fprintf(os.Stderr, "[agent-vault] Email verification code for %s: %s\n", req.Email, code)
		} else {
			emailSent = true
		}
	} else {
		fmt.Fprintf(os.Stderr, "[agent-vault] Email verification code for %s: %s\n", req.Email, code)
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
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Email == "" || req.Code == "" {
		jsonError(w, http.StatusBadRequest, "email and code are required")
		return
	}

	ctx := r.Context()

	// Rate limit verification attempts per email.
	if !verifyLimiter.check(req.Email) {
		jsonError(w, http.StatusTooManyRequests, "too many failed verification attempts; request a new code")
		return
	}

	ev, err := s.store.GetPendingEmailVerification(ctx, req.Email, req.Code)
	if err != nil || ev == nil {
		verifyLimiter.recordFailure(req.Email)
		jsonError(w, http.StatusBadRequest, "invalid or expired verification code")
		return
	}

	user, err := s.store.GetUserByEmail(ctx, req.Email)
	if err != nil || user == nil {
		jsonError(w, http.StatusNotFound, "user not found")
		return
	}

	if user.IsActive {
		jsonError(w, http.StatusConflict, "account is already verified")
		return
	}

	if err := s.store.MarkEmailVerificationUsed(ctx, ev.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to mark verification used")
		return
	}

	if err := s.store.ActivateUser(ctx, user.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to activate account")
		return
	}

	// Reset rate limit on successful verification.
	verifyLimiter.reset(req.Email)

	// Auto-login: create session and set cookie.
	session, err := s.store.CreateSession(ctx, user.ID, time.Now().Add(sessionTTL))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create session")
		return
	}
	http.SetCookie(w, sessionCookie(r, session.ID, int(sessionTTL.Seconds())))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"email":         user.Email,
		"authenticated": true,
		"message":       "Account verified.",
	})
}

// handleStatus returns the instance initialization status (public, no auth).
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"initialized":    s.initialized,
		"needs_first_user": !s.initialized,
	})
}

// handleAuthMe returns the current authenticated user's info.
func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil || sess.UserID == "" {
		jsonError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	user, err := s.userFromSession(r.Context(), sess)
	if err != nil || user == nil {
		jsonError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"email":    user.Email,
		"role":     user.Role,
		"is_owner": user.Role == "owner",
	})
}

// handleVaultContext returns the current user's membership context for a vault.
func (s *Server) handleVaultContext(w http.ResponseWriter, r *http.Request) {
	vaultName := r.PathValue("name")
	ctx := r.Context()

	sess := sessionFromContext(ctx)
	if sess == nil || sess.UserID == "" {
		jsonError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	user, err := s.userFromSession(ctx, sess)
	if err != nil || user == nil {
		jsonError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	vault, err := s.store.GetVault(ctx, vaultName)
	if err != nil || vault == nil {
		jsonError(w, http.StatusNotFound, "vault not found")
		return
	}

	has, err := s.store.HasVaultAccess(ctx, user.ID, vault.ID)
	if err != nil || !has {
		jsonError(w, http.StatusForbidden, "no vault access")
		return
	}

	vaultRole, _ := s.store.GetVaultRole(ctx, user.ID, vault.ID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"vault_name": vault.Name,
		"vault_role": vaultRole,
	})
}

// handleVaultInviteDetails returns vault invite details as JSON (token-based, no auth).
func (s *Server) handleVaultInviteDetails(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.PathValue("token")

	inv, err := s.store.GetVaultInviteByToken(ctx, token)
	if err != nil || inv == nil {
		jsonError(w, http.StatusNotFound, "invite not found")
		return
	}

	switch inv.Status {
	case "accepted":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": true, "error_title": "Already Accepted",
			"error_message": "This invitation has already been accepted. You can log in using 'agent-vault login'.",
		})
		return
	case "revoked":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": true, "error_title": "Invite Revoked",
			"error_message": "This invitation was revoked. Please ask the vault admin for a new one.",
		})
		return
	case "expired":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": true, "error_title": "Invite Expired",
			"error_message": "This invitation has expired. Please ask the vault admin for a new one.",
		})
		return
	}

	if time.Now().After(inv.ExpiresAt) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": true, "error_title": "Invite Expired",
			"error_message": "This invitation has expired. Please ask the vault admin for a new one.",
		})
		return
	}

	vault, _ := s.store.GetVaultByID(ctx, inv.VaultID)
	vaultName := ""
	if vault != nil {
		vaultName = vault.Name
	}

	existing, _ := s.store.GetUserByEmail(ctx, inv.Email)
	needsAccount := existing == nil

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"token":         inv.Token,
		"email":         inv.Email,
		"vault_name":    vaultName,
		"vault_role":    inv.VaultRole,
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
		jsonError(w, http.StatusBadRequest, "missing token")
		return
	}

	cs, err := s.store.GetProposalByApprovalToken(ctx, token)
	if err != nil || cs == nil {
		jsonError(w, http.StatusNotFound, "invalid or expired approval link")
		return
	}

	if id, err := strconv.Atoi(idStr); err != nil || id != cs.ID {
		jsonError(w, http.StatusBadRequest, "proposal ID mismatch")
		return
	}

	if cs.ApprovalTokenExpiresAt != nil && time.Now().After(*cs.ApprovalTokenExpiresAt) {
		jsonError(w, http.StatusGone, "approval link has expired")
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
		jsonError(w, http.StatusInternalServerError, "could not load vault details")
		return
	}

	authenticated := false
	canApprove := false
	userEmail := ""
	if c, err := r.Cookie("av_session"); err == nil && c.Value != "" {
		sess, err := s.store.GetSession(ctx, c.Value)
		if err == nil && sess != nil && !time.Now().After(sess.ExpiresAt) && sess.UserID != "" {
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
		"rules":         json.RawMessage(cs.RulesJSON),
		"credentials":       json.RawMessage(cs.CredentialsJSON),
		"created_at":    cs.CreatedAt.Format(time.RFC3339),
		"authenticated": authenticated,
		"can_approve":   canApprove,
		"user_email":    userEmail,
	})
}

// handleSPA serves the SPA index.html for client-side routing.
func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	indexHTML, err := fs.ReadFile(webDistFS, "webdist/index.html")
	if err != nil {
		http.Error(w, "frontend not built", http.StatusInternalServerError)
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

// clientIP extracts the client's IP address. When behind a reverse proxy
// (detected via X-Forwarded-For header), uses the rightmost non-empty entry.
// Falls back to RemoteAddr for direct connections.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		// Use the last entry (closest to the proxy / most trustworthy).
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if ip != "" {
				return ip
			}
		}
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}
	return ip
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
	registerLimiter   = newSlidingWindowLimiter(loginRateWindow, 5, 10000) // 5 registrations per IP per 5 min
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
		jsonError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	// Rate limit by IP and by email.
	ip := clientIP(r)
	if !loginIPLimiter.allow(ip) || !loginEmailLimiter.allow(req.Email) {
		http.Error(w, `{"error":"too many login attempts, try again later"}`, http.StatusTooManyRequests)
		return
	}

	ctx := r.Context()

	user, err := s.store.GetUserByEmail(ctx, req.Email)
	if err != nil {
		// Run KDF against dummy hash to equalize response time (prevent user enumeration).
		auth.VerifyUserPassword([]byte(req.Password), dummyPasswordHash, dummyPasswordSalt, dummyKDFParams)
		http.Error(w, `{"error":"invalid email or password"}`, http.StatusUnauthorized)
		return
	}

	if !auth.VerifyUserPassword([]byte(req.Password), user.PasswordHash, user.PasswordSalt, userKDFParams(user)) {
		http.Error(w, `{"error":"invalid email or password"}`, http.StatusUnauthorized)
		return
	}

	if !user.IsActive {
		http.Error(w, `{"error":"invalid email or password"}`, http.StatusUnauthorized)
		return
	}

	session, err := s.store.CreateSession(ctx, user.ID, time.Now().Add(sessionTTL))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	http.SetCookie(w, sessionCookie(r, session.ID, int(sessionTTL.Seconds())))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(loginResponse{
		Token:     session.ID,
		ExpiresAt: session.ExpiresAt.Format(time.RFC3339),
	})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		jsonError(w, http.StatusBadRequest, "current_password and new_password are required")
		return
	}
	if len(req.NewPassword) < 8 {
		jsonError(w, http.StatusBadRequest, "new password must be at least 8 characters")
		return
	}

	ctx := r.Context()
	sess := sessionFromContext(ctx)
	if sess == nil || sess.UserID == "" {
		jsonError(w, http.StatusForbidden, "user session required")
		return
	}

	user, err := s.store.GetUserByID(ctx, sess.UserID)
	if err != nil || user == nil {
		jsonError(w, http.StatusInternalServerError, "failed to load user")
		return
	}

	if !auth.VerifyUserPassword([]byte(req.CurrentPassword), user.PasswordHash, user.PasswordSalt, userKDFParams(user)) {
		jsonError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}

	hash, salt, newKDFParams, err := auth.HashUserPassword([]byte(req.NewPassword))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	if err := s.store.UpdateUserPassword(ctx, user.ID, hash, salt, newKDFParams.Time, newKDFParams.Memory, newKDFParams.Threads); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to update password")
		return
	}

	// Invalidate all existing sessions, then create a fresh one for this request.
	_ = s.store.DeleteUserSessions(ctx, user.ID)

	newSess, err := s.store.CreateSession(ctx, user.ID, time.Now().Add(sessionTTL))
	if err != nil {
		// Password was changed but session creation failed — user can re-login.
		jsonError(w, http.StatusInternalServerError, "password changed but failed to create new session")
		return
	}

	http.SetCookie(w, sessionCookie(r, newSess.ID, int(sessionTTL.Seconds())))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(loginResponse{
		Token:     newSess.ID,
		ExpiresAt: newSess.ExpiresAt.Format(time.RFC3339),
	})
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := sessionFromContext(ctx)
	if sess == nil || sess.UserID == "" {
		jsonError(w, http.StatusForbidden, "user session required")
		return
	}

	user, err := s.store.GetUserByID(ctx, sess.UserID)
	if err != nil || user == nil {
		jsonError(w, http.StatusInternalServerError, "failed to load user")
		return
	}

	if user.Role == "owner" {
		jsonError(w, http.StatusConflict, "owners cannot delete their own account; transfer ownership first")
		return
	}

	_ = s.store.DeleteUserSessions(ctx, user.ID)
	if err := s.store.DeleteUser(ctx, user.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to delete account")
		return
	}

	// Clear session cookie.
	http.SetCookie(w, sessionCookie(r, "", -1))

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
			http.Error(w, `{"error":"authorization required"}`, http.StatusUnauthorized)
			return
		}

		sess, err := s.store.GetSession(r.Context(), token)
		if err != nil || sess == nil {
			http.Error(w, `{"error":"invalid or expired session"}`, http.StatusUnauthorized)
			return
		}
		if time.Now().After(sess.ExpiresAt) {
			http.Error(w, `{"error":"session expired"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), sessionContextKey, sess)
		next(w, r.WithContext(ctx))
	}
}

type scopedSessionRequest struct {
	Vault string `json:"vault"`
}

type scopedSessionResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

func (s *Server) handleScopedSession(w http.ResponseWriter, r *http.Request) {
	var req scopedSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Vault == "" {
		http.Error(w, `{"error":"vault is required"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		http.Error(w, fmt.Sprintf(`{"error":"vault %q not found"}`, req.Vault), http.StatusNotFound)
		return
	}

	// Check that the user has access to this vault.
	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	sess, err := s.store.CreateScopedSession(ctx, ns.ID, "", time.Now().Add(sessionTTL))
	if err != nil {
		http.Error(w, `{"error":"failed to create scoped session"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(scopedSessionResponse{
		Token:     sess.ID,
		ExpiresAt: sess.ExpiresAt.Format(time.RFC3339),
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
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}
	if len(req.Credentials) == 0 {
		http.Error(w, `{"error":"credentials map is required"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		http.Error(w, fmt.Sprintf(`{"error":"vault %q not found"}`, req.Vault), http.StatusNotFound)
		return
	}

	// Setting credentials requires member+ role.
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	var setKeys []string
	for key, value := range req.Credentials {
		ciphertext, nonce, err := crypto.Encrypt([]byte(value), s.encKey)
		if err != nil {
			http.Error(w, `{"error":"encryption failed"}`, http.StatusInternalServerError)
			return
		}
		if _, err := s.store.SetCredential(ctx, ns.ID, key, ciphertext, nonce); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"failed to set credential %q"}`, key), http.StatusInternalServerError)
			return
		}
		setKeys = append(setKeys, key)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(credentialsSetResponse{Set: setKeys})
}

type credentialsListResponse struct {
	Keys []string `json:"keys"`
}

func (s *Server) handleCredentialsList(w http.ResponseWriter, r *http.Request) {
	vault := r.URL.Query().Get("vault")
	if vault == "" {
		vault = store.DefaultVault
	}

	ctx := r.Context()

	ns, err := s.store.GetVault(ctx, vault)
	if err != nil || ns == nil {
		http.Error(w, fmt.Sprintf(`{"error":"vault %q not found"}`, vault), http.StatusNotFound)
		return
	}

	// Check vault access (agent scoping + user role/grants).
	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	creds, err := s.store.ListCredentials(ctx, ns.ID)
	if err != nil {
		http.Error(w, `{"error":"failed to list credentials"}`, http.StatusInternalServerError)
		return
	}

	keys := make([]string, len(creds))
	for i, cred := range creds {
		keys[i] = cred.Key
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(credentialsListResponse{Keys: keys})
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
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}
	if len(req.Keys) == 0 {
		http.Error(w, `{"error":"keys list is required"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		http.Error(w, fmt.Sprintf(`{"error":"vault %q not found"}`, req.Vault), http.StatusNotFound)
		return
	}

	// Deleting credentials requires member+ role.
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	var deleted []string
	for _, key := range req.Keys {
		if err := s.store.DeleteCredential(ctx, ns.ID, key); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"failed to delete credential %q"}`, key), http.StatusInternalServerError)
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
		proxyError(w, http.StatusForbidden, "forbidden", "discovery requires a vault-scoped session")
		return
	}

	ns, err := s.store.GetVaultByID(ctx, sess.VaultID)
	if err != nil || ns == nil {
		proxyError(w, http.StatusInternalServerError, "internal", "failed to resolve vault")
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

	var rules []broker.Rule
	if err := json.Unmarshal([]byte(brokerCfg.RulesJSON), &rules); err != nil {
		proxyError(w, http.StatusInternalServerError, "internal", "failed to parse broker rules")
		return
	}

	services := make([]discoverService, len(rules))
	for i, rule := range rules {
		services[i] = discoverService{
			Host:        rule.Host,
			Description: rule.Description,
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
	Rules       []proposal.Rule       `json:"rules"`
	Credentials []proposal.CredentialSlot `json:"credentials"`
	Message     string                 `json:"message"`
	UserMessage string                 `json:"user_message"`
}

func (s *Server) handleProposalCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Enforce scoped session.
	sess := sessionFromContext(ctx)
	if sess == nil || sess.VaultID == "" {
		jsonError(w, http.StatusForbidden, "proposals require a vault-scoped session")
		return
	}

	var req proposalCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate the proposal.
	if err := proposal.Validate(req.Rules, req.Credentials); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Validate that all credential references resolve to existing or proposed credentials.
	existingKeys := s.listCredentialKeys(ctx, sess.VaultID)
	if err := proposal.ValidateCredentialRefs(req.Rules, req.Credentials, existingKeys); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Check pending limit.
	count, err := s.store.CountPendingProposals(ctx, sess.VaultID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to count pending proposals")
		return
	}
	if count >= maxPendingProposals {
		jsonError(w, http.StatusTooManyRequests, fmt.Sprintf("too many pending proposals (max %d)", maxPendingProposals))
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
				jsonError(w, http.StatusInternalServerError, "encryption failed")
				return
			}
			encCredentials[req.Credentials[i].Key] = store.EncryptedCredential{Ciphertext: ct, Nonce: nonce}
			// Replace value with nil in the metadata and mark has_value.
			req.Credentials[i].Value = nil
			req.Credentials[i].HasValue = true
		}
	}

	rulesJSON, _ := json.Marshal(req.Rules)
	credentialsJSON, _ := json.Marshal(req.Credentials)

	cs, err := s.store.CreateProposal(ctx, sess.VaultID, sess.ID, string(rulesJSON), string(credentialsJSON), req.Message, req.UserMessage, encCredentials)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create proposal")
		return
	}

	// Look up vault name for the response message.
	nsName := sess.VaultID
	if ns, err := s.store.GetVaultByID(ctx, sess.VaultID); err == nil && ns != nil {
		nsName = ns.Name
	}

	approvalURL := fmt.Sprintf("%s/approve/%d?token=%s", s.baseURL, cs.ID, cs.ApprovalToken)

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

func (s *Server) handleProposalGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sess := sessionFromContext(ctx)
	if sess == nil || sess.VaultID == "" {
		jsonError(w, http.StatusForbidden, "proposals require a vault-scoped session")
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid proposal id")
		return
	}

	cs, err := s.store.GetProposal(ctx, sess.VaultID, id)
	if err != nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("proposal %d not found", id))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":          cs.ID,
		"status":      cs.Status,
		"rules":       json.RawMessage(cs.RulesJSON),
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
		jsonError(w, http.StatusForbidden, "proposals require a vault-scoped session")
		return
	}

	status := r.URL.Query().Get("status")
	list, err := s.store.ListProposals(ctx, sess.VaultID, status)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list proposals")
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
		jsonError(w, http.StatusBadRequest, "invalid proposal id")
		return
	}

	var req adminApproveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("vault %q not found", req.Vault))
		return
	}

	// Approving proposals requires member+ role.
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	cs, err := s.store.GetProposal(ctx, ns.ID, id)
	if err != nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("proposal %d not found", id))
		return
	}
	if cs.Status != "pending" {
		jsonError(w, http.StatusConflict, fmt.Sprintf("proposal %d is already %s", id, cs.Status))
		return
	}

	// Parse proposed rules and credential slots.
	var proposedRules []proposal.Rule
	if err := json.Unmarshal([]byte(cs.RulesJSON), &proposedRules); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to parse proposal rules")
		return
	}
	var credentialSlots []proposal.CredentialSlot
	if err := json.Unmarshal([]byte(cs.CredentialsJSON), &credentialSlots); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to parse proposal credentials")
		return
	}

	// Load agent-provided encrypted credentials.
	agentCredentials, err := s.store.GetProposalCredentials(ctx, ns.ID, cs.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to load proposal credentials")
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
				jsonError(w, http.StatusBadRequest, fmt.Sprintf("agent-provided credential %q not found in proposal", slot.Key))
				return
			}
			decrypted, err := crypto.Decrypt(enc.Ciphertext, enc.Nonce, s.encKey)
			if err != nil {
				jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to decrypt agent-provided credential %q", slot.Key))
				return
			}
			plaintext = string(decrypted)
			crypto.WipeBytes(decrypted)
		} else {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("missing value for credential %q", slot.Key))
			return
		}

		if plaintext == "" {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("credential %q cannot be empty", slot.Key))
			return
		}

		ct, nonce, err := crypto.Encrypt([]byte(plaintext), s.encKey)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encrypt credential %q", slot.Key))
			return
		}
		finalCredentials[slot.Key] = store.EncryptedCredential{Ciphertext: ct, Nonce: nonce}
	}

	// Merge rules.
	bc, err := s.store.GetBrokerConfig(ctx, ns.ID)
	if err != nil {
		// No existing config — start fresh.
		bc = &store.BrokerConfig{RulesJSON: "[]"}
	}

	var existingRules []broker.Rule
	if err := json.Unmarshal([]byte(bc.RulesJSON), &existingRules); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to parse existing rules")
		return
	}

	merged, _ := proposal.MergeRules(existingRules, proposedRules)
	mergedJSON, err := json.Marshal(merged)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to marshal merged rules")
		return
	}

	// Apply atomically.
	if err := s.store.ApplyProposal(ctx, ns.ID, cs.ID, string(mergedJSON), finalCredentials, deleteCredentialKeys); err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to apply proposal: %v", err))
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
		jsonError(w, http.StatusBadRequest, "invalid proposal id")
		return
	}

	var req adminRejectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("vault %q not found", req.Vault))
		return
	}

	// Rejecting proposals requires member+ role.
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	cs, err := s.store.GetProposal(ctx, ns.ID, id)
	if err != nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("proposal %d not found", id))
		return
	}
	if cs.Status != "pending" {
		jsonError(w, http.StatusConflict, fmt.Sprintf("proposal %d is already %s", id, cs.Status))
		return
	}

	if err := s.store.UpdateProposalStatus(ctx, ns.ID, id, "rejected", req.Reason); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to reject proposal")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":     id,
		"status": "rejected",
	})
}

// isSecureRequest returns true if the request arrived over TLS (direct or via
// a trusted reverse proxy such as Fly.io or nginx).
func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	return proto == "https"
}

// sessionCookie builds an av_session cookie with all hardening flags set.
// Secure is set dynamically based on whether the request arrived over HTTPS.
func sessionCookie(r *http.Request, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     "av_session",
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	}
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
		"message": fmt.Sprintf("no broker rule matching host %q in vault %q", targetHost, nsName),
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
	"Content-Length",
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
		proxyError(w, http.StatusBadRequest, "bad_request", "missing target host in proxy URL")
		return
	}
	// Split into host and remaining path.
	targetHost, remainingPath, _ := strings.Cut(trimmed, "/")
	if targetHost == "" {
		proxyError(w, http.StatusBadRequest, "bad_request", "missing target host in proxy URL")
		return
	}

	// Validate targetHost is a safe hostname (no @, ?, #, spaces, control chars).
	// This prevents userinfo injection (e.g. host@evil.com) in the outbound URL.
	if !isValidProxyHost(targetHost) {
		proxyError(w, http.StatusBadRequest, "bad_request", "invalid target host")
		return
	}

	ctx := r.Context()

	// 2. Enforce scoped session — global admin sessions may not use the proxy.
	sess := sessionFromContext(ctx)
	if sess == nil || sess.VaultID == "" {
		proxyError(w, http.StatusForbidden, "forbidden", "proxy requires a vault-scoped session")
		return
	}

	// 3. Look up vault name for error messages.
	ns, err := s.store.GetVaultByID(ctx, sess.VaultID)
	if err != nil || ns == nil {
		proxyError(w, http.StatusInternalServerError, "internal", "failed to resolve vault")
		return
	}

	// 4. Load broker config for this vault.
	brokerCfg, err := s.store.GetBrokerConfig(ctx, sess.VaultID)
	if err != nil || brokerCfg == nil {
		proxyForbiddenWithHint(w, targetHost, ns.Name)
		return
	}

	var rules []broker.Rule
	if err := json.Unmarshal([]byte(brokerCfg.RulesJSON), &rules); err != nil {
		proxyError(w, http.StatusInternalServerError, "internal", "failed to parse broker rules")
		return
	}

	// 5. Match host against broker rules.
	matched := broker.MatchHost(targetHost, rules)
	if matched == nil {
		proxyForbiddenWithHint(w, targetHost, ns.Name)
		return
	}

	// 6. Resolve credentials from matched rule's auth config.
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
		proxyError(w, http.StatusBadGateway, "credential_not_found", err.Error())
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
		proxyError(w, http.StatusInternalServerError, "internal", "failed to create outbound request")
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
			fmt.Sprintf("failed to reach %s", targetHost))
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
	SBAddr         string            `json:"av_addr"`
	SBSessionToken string            `json:"av_session_token"`
	SBVault        string            `json:"av_vault"`
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
		proxyError(w, http.StatusNotFound, "invite_not_found", "invite not found")
		return
	}

	// Check status — return distinct codes for each terminal state.
	switch inv.Status {
	case "redeemed":
		proxyError(w, http.StatusGone, "invite_redeemed", "this invite has already been used — ask for a new one")
		return
	case "revoked":
		proxyError(w, http.StatusGone, "invite_revoked", "this invite was revoked — ask for a new one")
		return
	case "expired":
		proxyError(w, http.StatusGone, "invite_expired", "this invite has expired — ask for a new one")
		return
	}

	// Lazy expiry check for pending invites whose TTL has passed.
	if time.Now().After(inv.ExpiresAt) {
		proxyError(w, http.StatusGone, "invite_expired", "this invite has expired — ask for a new one")
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
		jsonError(w, http.StatusInternalServerError, "failed to redeem invite")
		return
	}

	// Create a vault-scoped session for the agent with the invite's role.
	sess, err := s.store.CreateScopedSession(ctx, inv.VaultID, inv.VaultRole, time.Now().Add(sessionTTL))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	// Build the onboarding payload — same data as /discover plus instructions.
	ns, err := s.store.GetVaultByID(ctx, inv.VaultID)
	if err != nil || ns == nil {
		jsonError(w, http.StatusInternalServerError, "failed to resolve vault")
		return
	}

	baseURL := s.baseURL
	services := s.buildServiceList(ctx, inv.VaultID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(inviteRedeemResponse{
		SBAddr:         baseURL,
		SBSessionToken: sess.ID,
		SBVault:        ns.Name,
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
		jsonError(w, http.StatusNotFound, "vault not found")
		return
	}

	// Check vault access.
	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	status := r.URL.Query().Get("status")
	invites, err := s.store.ListInvites(ctx, ns.ID, status)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list invites")
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
		token := inv.Token[len(inv.Token)-8:]
		if isAdmin {
			token = inv.Token
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
			if s, err := s.store.GetSession(ctx, inv.SessionID); err == nil && s != nil {
				e := s.ExpiresAt.Format(time.RFC3339)
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
		proxyError(w, http.StatusNotFound, "invite_not_found", "invite not found")
		return
	}

	// Check vault access for the invite's vault.
	if _, err := s.requireVaultAccess(w, r, inv.VaultID); err != nil {
		return
	}

	if inv.Status != "pending" {
		jsonError(w, http.StatusConflict, fmt.Sprintf("invite is already %s", inv.Status))
		return
	}

	if err := s.store.RevokeInvite(ctx, token); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to revoke invite")
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
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := auth.ValidateEmail(req.Email); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Password) < 8 {
		jsonError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	ctx := r.Context()

	// Check email uniqueness.
	if existing, _ := s.store.GetUserByEmail(ctx, req.Email); existing != nil {
		jsonError(w, http.StatusConflict, fmt.Sprintf("user %q already exists", req.Email))
		return
	}

	hash, salt, kdfP, err := auth.HashUserPassword([]byte(req.Password))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	user, err := s.store.CreateUser(ctx, req.Email, hash, salt, "member", kdfP.Time, kdfP.Memory, kdfP.Threads)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	// Admin-created users are active immediately (no email verification needed).
	if err := s.store.ActivateUser(ctx, user.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to activate user")
		return
	}
	user.IsActive = true

	// Grant vault access.
	for _, nsName := range req.Vaults {
		ns, err := s.store.GetVault(ctx, nsName)
		if err != nil || ns == nil {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("vault %q not found", nsName))
			return
		}
		if err := s.store.GrantVaultRole(ctx, user.ID, ns.ID, "member"); err != nil {
			jsonError(w, http.StatusInternalServerError, fmt.Sprintf("failed to grant vault %q", nsName))
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

func (s *Server) handleUserList(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwner(w, r); err != nil {
		return
	}

	ctx := r.Context()
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list users")
		return
	}

	type userItem struct {
		Email      string   `json:"email"`
		Role       string   `json:"role"`
		Vaults []string `json:"vaults"`
		CreatedAt  string   `json:"created_at"`
	}

	items := make([]userItem, len(users))
	for i, u := range users {
		grants, _ := s.store.ListUserGrants(ctx, u.ID)
		nsNames := make([]string, 0, len(grants))
		for _, g := range grants {
			if ns, err := s.store.GetVaultByID(ctx, g.VaultID); err == nil && ns != nil {
				nsNames = append(nsNames, ns.Name)
			}
		}
		items[i] = userItem{
			Email:      u.Email,
			Role:       u.Role,
			Vaults: nsNames,
			CreatedAt:  u.CreatedAt.Format(time.RFC3339),
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
		jsonError(w, http.StatusForbidden, "user session required")
		return
	}

	caller, err := s.userFromSession(ctx, sess)
	if err != nil || caller == nil {
		jsonError(w, http.StatusForbidden, "invalid session")
		return
	}

	// Allow "me" as a shorthand for the caller's own email.
	if email == "me" {
		email = caller.Email
	}

	// Members can only view themselves.
	if caller.Role != "owner" && caller.Email != email {
		jsonError(w, http.StatusForbidden, "owner role required to view other users")
		return
	}

	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("user %q not found", email))
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
		jsonError(w, http.StatusNotFound, fmt.Sprintf("user %q not found", email))
		return
	}

	// Prevent deleting the last owner.
	if user.Role == "owner" {
		count, err := s.store.CountOwners(ctx)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "failed to count owners")
			return
		}
		if count <= 1 {
			jsonError(w, http.StatusConflict, "cannot remove the last owner")
			return
		}
	}

	// Delete sessions, then user (grants cascade via FK).
	_ = s.store.DeleteUserSessions(ctx, user.ID)
	if err := s.store.DeleteUser(ctx, user.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to delete user")
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
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Role != "owner" && req.Role != "member" {
		jsonError(w, http.StatusBadRequest, "role must be 'owner' or 'member'")
		return
	}

	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("user %q not found", email))
		return
	}

	// Prevent demoting the last owner.
	if user.Role == "owner" && req.Role == "member" {
		count, err := s.store.CountOwners(ctx)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "failed to count owners")
			return
		}
		if count <= 1 {
			jsonError(w, http.StatusConflict, "cannot demote the last owner")
			return
		}
	}

	if err := s.store.UpdateUserRole(ctx, user.ID, req.Role); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to update role")
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

	var rules []broker.Rule
	if err := json.Unmarshal([]byte(brokerCfg.RulesJSON), &rules); err != nil {
		return []discoverService{}
	}

	services := make([]discoverService, len(rules))
	for i, rule := range rules {
		services[i] = discoverService{
			Host:        rule.Host,
			Description: rule.Description,
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

	if err := s.notifier.SendMail(
		[]string{to},
		"Agent Vault \u2014 Test Email",
		"This is a test email from Agent Vault.\nIf you received this, your SMTP configuration is working correctly.",
	); err != nil {
		jsonError(w, http.StatusBadGateway, fmt.Sprintf("failed to send test email: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "test email sent",
		"to":      to,
	})
}

// --- Vault Invite Endpoints ---

const vaultInviteTTL = 48 * time.Hour
const maxPendingVaultInvites = 50

func (s *Server) handleVaultInviteCreate(w http.ResponseWriter, r *http.Request) {
	vaultName := r.PathValue("name")
	ctx := r.Context()

	vault, err := s.store.GetVault(ctx, vaultName)
	if err != nil || vault == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("vault %q not found", vaultName))
		return
	}

	// Vault user invites require admin role (user vault admin or admin agent).
	user, err := s.requireVaultAdminSession(w, r, vault.ID)
	if err != nil {
		return
	}

	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
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
		jsonError(w, http.StatusBadRequest, "role must be 'admin' or 'member'")
		return
	}

	// Check for existing pending invite for this email+vault.
	if pending, _ := s.store.GetPendingVaultInviteByEmailAndVault(ctx, req.Email, vault.ID); pending != nil {
		jsonError(w, http.StatusConflict, fmt.Sprintf("a pending invite already exists for %q in vault %q", req.Email, vaultName))
		return
	}

	// Check if user already has access to this vault.
	if existing, _ := s.store.GetUserByEmail(ctx, req.Email); existing != nil {
		has, _ := s.store.HasVaultAccess(ctx, existing.ID, vault.ID)
		if has {
			jsonError(w, http.StatusConflict, fmt.Sprintf("user %q already has access to vault %q", req.Email, vaultName))
			return
		}
	}

	// Check pending invite limit.
	count, err := s.store.CountPendingVaultInvites(ctx, vault.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to count pending invites")
		return
	}
	if count >= maxPendingVaultInvites {
		jsonError(w, http.StatusTooManyRequests, "too many pending vault invites")
		return
	}

	createdBy := "agent"
	inviterLabel := "an agent"
	if user != nil {
		createdBy = user.ID
		inviterLabel = user.Email
	}

	inv, err := s.store.CreateVaultInvite(ctx, req.Email, vault.ID, req.Role, createdBy, time.Now().Add(vaultInviteTTL))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create invite")
		return
	}

	baseURL := s.baseURL
	inviteLink := baseURL + "/vault-invite/" + inv.Token

	// Send email if SMTP is configured.
	emailSent := false
	if s.notifier.Enabled() {
		emailHTML := userInviteEmailHTML
		emailHTML = strings.ReplaceAll(emailHTML, "{{INVITER_EMAIL}}", html.EscapeString(inviterLabel))
		emailHTML = strings.ReplaceAll(emailHTML, "{{VAULTS}}", html.EscapeString(vaultName))
		emailHTML = strings.ReplaceAll(emailHTML, "{{INVITE_LINK}}", html.EscapeString(inviteLink))

		if err := s.notifier.SendHTMLMail(
			[]string{req.Email},
			fmt.Sprintf("You've been invited to vault %q on Agent Vault", vaultName),
			emailHTML,
		); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"email":       req.Email,
				"invite_link": inviteLink,
				"email_sent":  false,
				"email_error": fmt.Sprintf("failed to send email: %v", err),
				"expires_at":  inv.ExpiresAt.Format(time.RFC3339),
			})
			return
		}
		emailSent = true
	}

	resp := map[string]interface{}{
		"email":      req.Email,
		"role":       req.Role,
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
	http.SetCookie(w, sessionCookie(r, "", -1))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}


func (s *Server) handleVaultInviteAccept(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.PathValue("token")

	var req struct {
		Password string `json:"password"`
	}
	// Body may be empty for existing users.
	_ = json.NewDecoder(r.Body).Decode(&req)

	inv, err := s.store.GetVaultInviteByToken(ctx, token)
	if err != nil || inv == nil {
		jsonError(w, http.StatusNotFound, "invite not found")
		return
	}

	switch inv.Status {
	case "accepted":
		jsonError(w, http.StatusGone, "this invite has already been accepted")
		return
	case "revoked":
		jsonError(w, http.StatusGone, "this invite was revoked")
		return
	case "expired":
		jsonError(w, http.StatusGone, "this invite has expired")
		return
	}

	if time.Now().After(inv.ExpiresAt) {
		jsonError(w, http.StatusGone, "this invite has expired")
		return
	}

	// Atomically claim the invite first (prevents double-spend race).
	// AcceptVaultInvite uses UPDATE ... WHERE status='pending', so only
	// the first concurrent request succeeds.
	if err := s.store.AcceptVaultInvite(ctx, token); err != nil {
		jsonError(w, http.StatusGone, "this invite has already been accepted")
		return
	}

	// Does the invitee already have an account?
	existing, _ := s.store.GetUserByEmail(ctx, inv.Email)
	var user *store.User

	if existing != nil {
		// Existing user — just grant vault role, no password needed.
		user = existing
	} else {
		// New user — require password.
		if len(req.Password) < 8 {
			jsonError(w, http.StatusBadRequest, "password must be at least 8 characters")
			return
		}

		hash, salt, kdfP, err := auth.HashUserPassword([]byte(req.Password))
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "failed to hash password")
			return
		}

		newUser, err := s.store.CreateUser(ctx, inv.Email, hash, salt, "member", kdfP.Time, kdfP.Memory, kdfP.Threads)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "failed to create user")
			return
		}
		// Activate immediately — invite is the verification.
		_ = s.store.ActivateUser(ctx, newUser.ID)
		user = newUser
	}

	// Grant vault access with the invited role.
	if err := s.store.GrantVaultRole(ctx, user.ID, inv.VaultID, inv.VaultRole); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to grant vault access")
		return
	}

	msg := "Vault access granted."
	if existing == nil {
		msg = "Account created and vault access granted. You can now log in using 'agent-vault login'."
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"email":   user.Email,
		"message": msg,
	})
}

func (s *Server) handleVaultInviteList(w http.ResponseWriter, r *http.Request) {
	vaultName := r.PathValue("name")
	ctx := r.Context()

	vault, err := s.store.GetVault(ctx, vaultName)
	if err != nil || vault == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("vault %q not found", vaultName))
		return
	}

	if _, err := s.requireVaultAdminSession(w, r, vault.ID); err != nil {
		return
	}

	status := r.URL.Query().Get("status")
	invites, err := s.store.ListVaultInvites(ctx, vault.ID, status)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list vault invites")
		return
	}

	type inviteItem struct {
		Email     string `json:"email"`
		Token     string `json:"token"`
		Status    string `json:"status"`
		Role      string `json:"role"`
		ExpiresAt string `json:"expires_at"`
		CreatedAt string `json:"created_at"`
	}

	items := make([]inviteItem, len(invites))
	for i, inv := range invites {
		items[i] = inviteItem{
			Email:     inv.Email,
			Token:     inv.Token,
			Status:    inv.Status,
			Role:      inv.VaultRole,
			ExpiresAt: inv.ExpiresAt.Format(time.RFC3339),
			CreatedAt: inv.CreatedAt.Format(time.RFC3339),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"invites": items})
}

func (s *Server) handleVaultInviteRevoke(w http.ResponseWriter, r *http.Request) {
	vaultName := r.PathValue("name")
	ctx := r.Context()

	vault, err := s.store.GetVault(ctx, vaultName)
	if err != nil || vault == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("vault %q not found", vaultName))
		return
	}

	if _, err := s.requireVaultAdminSession(w, r, vault.ID); err != nil {
		return
	}

	token := r.PathValue("token")
	if err := s.store.RevokeVaultInvite(ctx, token, vault.ID); err != nil {
		jsonError(w, http.StatusNotFound, "invite not found or not pending")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "invite revoked"})
}

// handleVaultInviteReinvite revokes an existing pending invite and creates a
// new one for the same email/role, generating a fresh token and link.
func (s *Server) handleVaultInviteReinvite(w http.ResponseWriter, r *http.Request) {
	vaultName := r.PathValue("name")
	ctx := r.Context()

	vault, err := s.store.GetVault(ctx, vaultName)
	if err != nil || vault == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("vault %q not found", vaultName))
		return
	}

	user, err := s.requireVaultAdminSession(w, r, vault.ID)
	if err != nil {
		return
	}

	createdBy := "agent"
	inviterLabel := "an agent"
	if user != nil {
		createdBy = user.ID
		inviterLabel = user.Email
	}

	token := r.PathValue("token")

	// Look up the existing invite to get email and role.
	existing, err := s.store.GetVaultInviteByToken(ctx, token)
	if err != nil || existing == nil {
		jsonError(w, http.StatusNotFound, "invite not found")
		return
	}
	if existing.VaultID != vault.ID {
		jsonError(w, http.StatusNotFound, "invite not found")
		return
	}
	if existing.Status != "pending" {
		jsonError(w, http.StatusConflict, "invite is not pending")
		return
	}

	// Revoke the old invite.
	if err := s.store.RevokeVaultInvite(ctx, token, vault.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to revoke old invite")
		return
	}

	// Create a new invite with the same email and role.
	inv, err := s.store.CreateVaultInvite(ctx, existing.Email, vault.ID, existing.VaultRole, createdBy, time.Now().Add(vaultInviteTTL))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create new invite")
		return
	}

	inviteLink := s.baseURL + "/vault-invite/" + inv.Token

	// Send email if SMTP is configured.
	emailSent := false
	if s.notifier.Enabled() {
		emailHTML := userInviteEmailHTML
		emailHTML = strings.ReplaceAll(emailHTML, "{{INVITER_EMAIL}}", html.EscapeString(inviterLabel))
		emailHTML = strings.ReplaceAll(emailHTML, "{{VAULTS}}", html.EscapeString(vaultName))
		emailHTML = strings.ReplaceAll(emailHTML, "{{INVITE_LINK}}", html.EscapeString(inviteLink))

		if err := s.notifier.SendHTMLMail(
			[]string{existing.Email},
			fmt.Sprintf("You've been re-invited to vault %q on Agent Vault", vaultName),
			emailHTML,
		); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"email":       existing.Email,
				"token":       inv.Token,
				"invite_link": inviteLink,
				"email_sent":  false,
				"email_error": fmt.Sprintf("failed to send email: %v", err),
				"expires_at":  inv.ExpiresAt.Format(time.RFC3339),
			})
			return
		}
		emailSent = true
	}

	resp := map[string]interface{}{
		"email":      existing.Email,
		"token":      inv.Token,
		"role":       existing.VaultRole,
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

// handleVaultInviteUpdate updates a pending invite's role in place.
func (s *Server) handleVaultInviteUpdate(w http.ResponseWriter, r *http.Request) {
	vaultName := r.PathValue("name")
	ctx := r.Context()

	vault, err := s.store.GetVault(ctx, vaultName)
	if err != nil || vault == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("vault %q not found", vaultName))
		return
	}

	if _, err := s.requireVaultAdminSession(w, r, vault.ID); err != nil {
		return
	}

	token := r.PathValue("token")

	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Role != "admin" && req.Role != "member" {
		jsonError(w, http.StatusBadRequest, "role must be 'admin' or 'member'")
		return
	}

	if err := s.store.UpdateVaultInviteRole(ctx, token, vault.ID, req.Role); err != nil {
		jsonError(w, http.StatusNotFound, "invite not found or not pending")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"role": req.Role})
}

// --- Vault User Endpoints ---

func (s *Server) handleVaultUserList(w http.ResponseWriter, r *http.Request) {
	vaultName := r.PathValue("name")
	ctx := r.Context()

	vault, err := s.store.GetVault(ctx, vaultName)
	if err != nil || vault == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("vault %q not found", vaultName))
		return
	}

	if _, err := s.requireVaultAccess(w, r, vault.ID); err != nil {
		return
	}

	grants, err := s.store.ListVaultUsers(ctx, vault.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list vault users")
		return
	}

	type userItem struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}

	var users []userItem
	for _, g := range grants {
		u, err := s.store.GetUserByID(ctx, g.UserID)
		if err != nil || u == nil {
			continue
		}
		users = append(users, userItem{Email: u.Email, Role: g.Role})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"users": users})
}

func (s *Server) handleVaultUserRemove(w http.ResponseWriter, r *http.Request) {
	vaultName := r.PathValue("name")
	email := r.PathValue("email")
	ctx := r.Context()

	vault, err := s.store.GetVault(ctx, vaultName)
	if err != nil || vault == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("vault %q not found", vaultName))
		return
	}

	if _, err := s.requireVaultAdminSession(w, r, vault.ID); err != nil {
		return
	}

	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("user %q not found", email))
		return
	}

	// Guard: can't remove last admin.
	role, _ := s.store.GetVaultRole(ctx, user.ID, vault.ID)
	if role == "admin" {
		adminCount, _ := s.store.CountVaultAdmins(ctx, vault.ID)
		if adminCount <= 1 {
			jsonError(w, http.StatusConflict, "cannot remove the last admin from this vault")
			return
		}
	}

	if err := s.store.RevokeVaultAccess(ctx, user.ID, vault.ID); err != nil {
		jsonError(w, http.StatusNotFound, "user does not belong to this vault")
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
		jsonError(w, http.StatusNotFound, fmt.Sprintf("vault %q not found", vaultName))
		return
	}

	if _, err := s.requireVaultAdminSession(w, r, vault.ID); err != nil {
		return
	}

	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Role != "admin" && req.Role != "member" {
		jsonError(w, http.StatusBadRequest, "role must be 'admin' or 'member'")
		return
	}

	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("user %q not found", email))
		return
	}

	// Guard: can't demote last admin.
	currentRole, _ := s.store.GetVaultRole(ctx, user.ID, vault.ID)
	if currentRole == "" {
		jsonError(w, http.StatusNotFound, "user does not belong to this vault")
		return
	}
	if currentRole == "admin" && req.Role == "member" {
		adminCount, _ := s.store.CountVaultAdmins(ctx, vault.ID)
		if adminCount <= 1 {
			jsonError(w, http.StatusConflict, "cannot demote the last admin of this vault")
			return
		}
	}

	if err := s.store.GrantVaultRole(ctx, user.ID, vault.ID, req.Role); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to update role")
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

//go:embed persistent_instructions_consumer.txt
var persistentInstructionsConsumer string

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
		return instructionsConsumer
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
		return persistentInstructionsConsumer
	}
}

// capabilitiesForRole returns the list of capabilities for a given vault role.
func capabilitiesForRole(role string) []string {
	base := []string{"proxy", "discover", "proposals"}
	switch role {
	case "member":
		return append(base, "credentials:write", "proposals:approve", "policy:manage", "agents:invite:consumer")
	case "admin":
		return append(base, "credentials:write", "proposals:approve", "policy:manage", "agents:invite:any", "users:invite")
	default:
		return base
	}
}

const maxAgentSessions = 10

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

// handleAgentSessionMint mints a short-lived session token from a service token.
// POST /v1/agent/session — no requireAuth; service token is the credential.
func (s *Server) handleAgentSessionMint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract service token from Authorization header.
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer av_agent_") {
		jsonError(w, http.StatusUnauthorized, "valid service token required (Authorization: Bearer av_agent_...)")
		return
	}
	token := strings.TrimPrefix(header, "Bearer ")

	// Extract prefix for lookup (first 16 hex chars after "av_agent_").
	tokenBody := strings.TrimPrefix(token, "av_agent_")
	if len(tokenBody) < 16 {
		jsonError(w, http.StatusUnauthorized, "invalid service token format")
		return
	}
	prefix := tokenBody[:16]

	agent, err := s.store.GetAgentByTokenPrefix(ctx, prefix)
	if err != nil {
		jsonError(w, http.StatusUnauthorized, "invalid or revoked service token")
		return
	}

	// Verify the full token hash.
	if !auth.VerifyUserPassword([]byte(token), agent.ServiceTokenHash, agent.ServiceTokenSalt, crypto.DefaultKDFParams()) {
		jsonError(w, http.StatusUnauthorized, "invalid service token")
		return
	}

	if agent.Status != "active" {
		jsonError(w, http.StatusForbidden, "agent has been revoked")
		return
	}

	// Rate limit: max active sessions per agent.
	count, err := s.store.CountAgentSessions(ctx, agent.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to check session count")
		return
	}
	if count >= maxAgentSessions {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "too_many_sessions",
			"message": fmt.Sprintf("agent has %d active sessions (max %d) — wait for existing sessions to expire", count, maxAgentSessions),
		})
		return
	}

	sess, err := s.store.CreateAgentSession(ctx, agent.ID, agent.VaultID, agent.VaultRole, time.Now().Add(sessionTTL))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	ns, _ := s.store.GetVaultByID(ctx, agent.VaultID)
	nsName := store.DefaultVault
	if ns != nil {
		nsName = ns.Name
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"av_session_token": sess.ID,
		"av_vault":        nsName,
		"vault_role":         agent.VaultRole,
		"capabilities":       capabilitiesForRole(agent.VaultRole),
		"expires_at":         sess.ExpiresAt.Format(time.RFC3339),
	})
}

// handlePersistentInviteRedeem handles POST /invite/{token} for persistent agent invites.
func (s *Server) handlePersistentInviteRedeem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.PathValue("token")

	inv, err := s.store.GetInviteByToken(ctx, token)
	if err != nil || inv == nil {
		proxyError(w, http.StatusNotFound, "invite_not_found", "invite not found")
		return
	}

	// Check status.
	switch inv.Status {
	case "redeemed":
		proxyError(w, http.StatusGone, "invite_redeemed", "this invite has already been used — ask for a new one")
		return
	case "revoked":
		proxyError(w, http.StatusGone, "invite_revoked", "this invite was revoked — ask for a new one")
		return
	case "expired":
		proxyError(w, http.StatusGone, "invite_expired", "this invite has expired — ask for a new one")
		return
	}
	if time.Now().After(inv.ExpiresAt) {
		proxyError(w, http.StatusGone, "invite_expired", "this invite has expired — ask for a new one")
		return
	}

	if !inv.Persistent {
		proxyError(w, http.StatusBadRequest, "not_persistent", "this is a temporary invite — use GET /invite/{token} instead")
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
		proxyError(w, http.StatusBadRequest, "name_required", "agent name is required — provide {\"name\": \"my-agent\"} in the request body")
		return
	}
	if !validateSlug(agentName) {
		proxyError(w, http.StatusBadRequest, "invalid_name", "agent name must be 3-64 characters, lowercase alphanumeric and hyphens only")
		return
	}

	// Check name uniqueness.
	existing, _ := s.store.GetAgentByName(ctx, agentName)
	if existing != nil {
		proxyError(w, http.StatusConflict, "name_taken", fmt.Sprintf("an agent named %q already exists", agentName))
		return
	}

	// Burn the invite first (atomic CAS via status='pending' guard) to prevent
	// double-redeem race conditions. Only one concurrent request can succeed.
	if err := s.store.RedeemInvite(ctx, token, ""); err != nil {
		proxyError(w, http.StatusGone, "invite_redeemed", "this invite has already been used — ask for a new one")
		return
	}

	// Generate service token.
	serviceToken := newServiceToken()
	tokenHash, tokenSalt, _, err := auth.HashUserPassword([]byte(serviceToken))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to hash service token")
		return
	}
	tokenPrefix := serviceTokenPrefix(serviceToken)

	// Create agent record.
	agent, err := s.store.CreateAgent(ctx, agentName, inv.VaultID, tokenHash, tokenSalt, tokenPrefix, inv.VaultRole, inv.CreatedBy)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create agent")
		return
	}

	// Create initial session for immediate use.
	sess, err := s.store.CreateAgentSession(ctx, agent.ID, inv.VaultID, agent.VaultRole, time.Now().Add(sessionTTL))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create session")
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
		"av_agent_token":   serviceToken,
		"av_session_token": sess.ID,
		"av_vault":         nsName,
		"vault_role":          inv.VaultRole,
		"agent_name":          agentName,
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
		proxyError(w, http.StatusGone, "agent_not_found", "the agent for this rotation invite no longer exists or has been revoked")
		return
	}

	// Burn the invite first (atomic CAS via status='pending' guard) to prevent
	// double-redeem race conditions. Only one concurrent request can succeed.
	if err := s.store.RedeemInvite(ctx, token, ""); err != nil {
		proxyError(w, http.StatusGone, "invite_redeemed", "this invite has already been used — ask for a new one")
		return
	}

	// Generate new service token.
	serviceToken := newServiceToken()
	tokenHash, tokenSalt, _, err := auth.HashUserPassword([]byte(serviceToken))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to hash service token")
		return
	}
	tokenPrefix := serviceTokenPrefix(serviceToken)

	// Update the agent's service token (invalidates the old one at this moment).
	if err := s.store.UpdateAgentServiceToken(ctx, agent.ID, tokenHash, tokenSalt, tokenPrefix); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to update service token")
		return
	}

	// Create a fresh session.
	sess, err := s.store.CreateAgentSession(ctx, agent.ID, agent.VaultID, agent.VaultRole, time.Now().Add(sessionTTL))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create session")
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
		"av_agent_token":   serviceToken,
		"av_session_token": sess.ID,
		"av_vault":         nsName,
		"vault_role":          agent.VaultRole,
		"agent_name":          agent.Name,
		"proxy_url":        baseURL + "/proxy",
		"services":         services,
		"instructions":     persistentInstructionsForRole(agent.VaultRole),
	})
}

// --- Agent Admin Endpoints ---

func (s *Server) handleAgentList(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwner(w, r); err != nil {
		return
	}
	ctx := r.Context()

	nsName := r.URL.Query().Get("vault")
	var vaultID string
	if nsName != "" {
		ns, err := s.store.GetVault(ctx, nsName)
		if err != nil || ns == nil {
			jsonError(w, http.StatusNotFound, "vault not found")
			return
		}
		vaultID = ns.ID
	}

	agents, err := s.store.ListAgents(ctx, vaultID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list agents")
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
	if _, err := s.requireOwner(w, r); err != nil {
		return
	}
	ctx := r.Context()
	name := r.PathValue("name")

	agent, err := s.store.GetAgentByName(ctx, name)
	if err != nil {
		jsonError(w, http.StatusNotFound, "agent not found")
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
	if _, err := s.requireOwner(w, r); err != nil {
		return
	}
	ctx := r.Context()
	name := r.PathValue("name")

	agent, err := s.store.GetAgentByName(ctx, name)
	if err != nil {
		jsonError(w, http.StatusNotFound, "agent not found")
		return
	}
	if agent.Status != "active" {
		jsonError(w, http.StatusConflict, "agent is already revoked")
		return
	}

	if err := s.store.RevokeAgent(ctx, agent.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to revoke agent")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": fmt.Sprintf("agent %q revoked", name)})
}

func (s *Server) handleAgentRotate(w http.ResponseWriter, r *http.Request) {
	user, err := s.requireOwner(w, r)
	if err != nil {
		return
	}
	ctx := r.Context()
	name := r.PathValue("name")

	agent, err := s.store.GetAgentByName(ctx, name)
	if err != nil {
		jsonError(w, http.StatusNotFound, "agent not found")
		return
	}
	if agent.Status != "active" {
		jsonError(w, http.StatusConflict, "agent is revoked — cannot rotate")
		return
	}

	// Create a rotation invite.
	inv, err := s.store.CreateRotationInvite(ctx, agent.ID, agent.VaultID, user.ID, time.Now().Add(15*time.Minute))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create rotation invite")
		return
	}

	inviteURL := s.baseURL + "/invite/" + inv.Token
	prompt := fmt.Sprintf(`Your Agent Vault service token is being rotated. To accept the new token, make the following HTTP request:

  POST %s
  Content-Type: application/json

  {}

The response contains your new service token. Store it securely and discard the old one.

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
	if _, err := s.requireOwner(w, r); err != nil {
		return
	}
	ctx := r.Context()
	name := r.PathValue("name")

	agent, err := s.store.GetAgentByName(ctx, name)
	if err != nil {
		jsonError(w, http.StatusNotFound, "agent not found")
		return
	}

	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		jsonError(w, http.StatusBadRequest, "request body must include {\"name\": \"new-name\"}")
		return
	}
	if !validateSlug(body.Name) {
		jsonError(w, http.StatusBadRequest, "agent name must be 3-64 characters, lowercase alphanumeric and hyphens only")
		return
	}

	// Check uniqueness.
	existing, _ := s.store.GetAgentByName(ctx, body.Name)
	if existing != nil {
		jsonError(w, http.StatusConflict, fmt.Sprintf("an agent named %q already exists", body.Name))
		return
	}

	if err := s.store.RenameAgent(ctx, agent.ID, body.Name); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to rename agent")
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
		jsonError(w, http.StatusNotFound, "agent not found")
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
		jsonError(w, http.StatusBadRequest, `request body must include {"role": "consumer|member|admin"}`)
		return
	}
	if body.Role != "consumer" && body.Role != "member" && body.Role != "admin" {
		jsonError(w, http.StatusBadRequest, "role must be one of: consumer, member, admin")
		return
	}

	if err := s.store.UpdateAgentVaultRole(ctx, agent.ID, body.Role); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to update agent role")
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
		jsonError(w, http.StatusForbidden, "authentication required")
		return
	}
	user, err := s.userFromSession(r.Context(), sess)
	if err != nil || user == nil {
		jsonError(w, http.StatusForbidden, "user session required")
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		jsonError(w, http.StatusBadRequest, "name is required")
		return
	}
	if !validateSlug(req.Name) {
		jsonError(w, http.StatusBadRequest, "vault name must be 3-64 characters, lowercase alphanumeric and hyphens only")
		return
	}

	ctx := r.Context()
	ns, err := s.store.CreateVault(ctx, req.Name)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			jsonError(w, http.StatusConflict, fmt.Sprintf("vault %q already exists", req.Name))
			return
		}
		jsonError(w, http.StatusInternalServerError, "failed to create vault")
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
		jsonError(w, http.StatusForbidden, "authentication required")
		return
	}
	user, err := s.userFromSession(r.Context(), sess)
	if err != nil || user == nil {
		jsonError(w, http.StatusForbidden, "user session required")
		return
	}

	ctx := r.Context()

	type nsItem struct {
		ID                string `json:"id"`
		Name              string `json:"name"`
		Role              string `json:"role,omitempty"`
		CreatedAt         string `json:"created_at"`
		PendingProposals int    `json:"pending_proposals"`
	}

	// All users (including owners) see only vaults they have explicit grants for.
	grants, err := s.store.ListUserGrants(ctx, user.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list vaults")
		return
	}

	var items []nsItem
	for _, g := range grants {
		ns, err := s.store.GetVaultByID(ctx, g.VaultID)
		if err != nil || ns == nil {
			continue
		}
		pending, _ := s.store.CountPendingProposals(ctx, ns.ID)
		items = append(items, nsItem{
			ID:                ns.ID,
			Name:              ns.Name,
			Role:              g.Role,
			CreatedAt:         ns.CreatedAt.Format(time.RFC3339),
			PendingProposals: pending,
		})
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
		jsonError(w, http.StatusInternalServerError, "failed to list vaults")
		return
	}

	type vaultItem struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
	}

	items := make([]vaultItem, len(vaults))
	for i, v := range vaults {
		items[i] = vaultItem{
			ID:        v.ID,
			Name:      v.Name,
			CreatedAt: v.CreatedAt.Format(time.RFC3339),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"vaults": items})
}

func (s *Server) handleVaultDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == store.DefaultVault {
		jsonError(w, http.StatusBadRequest, "cannot delete the default vault")
		return
	}

	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("vault %q not found", name))
		return
	}

	// Vault admin OR instance owner can delete.
	sess := sessionFromContext(ctx)
	if sess == nil {
		jsonError(w, http.StatusForbidden, "authentication required")
		return
	}
	user, err := s.userFromSession(ctx, sess)
	if err != nil || user == nil {
		jsonError(w, http.StatusForbidden, "user session required")
		return
	}

	isVaultAdmin := false
	if role, _ := s.store.GetVaultRole(ctx, user.ID, ns.ID); role == "admin" {
		isVaultAdmin = true
	}
	if !isVaultAdmin && user.Role != "owner" {
		jsonError(w, http.StatusForbidden, "vault admin or instance owner required")
		return
	}

	if err := s.store.DeleteVault(ctx, name); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to delete vault")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"name": name, "deleted": true})
}

func (s *Server) handleVaultRename(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == store.DefaultVault {
		jsonError(w, http.StatusBadRequest, "cannot rename the default vault")
		return
	}

	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("vault %q not found", name))
		return
	}

	// Vault admin OR instance owner can rename.
	sess := sessionFromContext(ctx)
	if sess == nil {
		jsonError(w, http.StatusForbidden, "authentication required")
		return
	}
	user, err := s.userFromSession(ctx, sess)
	if err != nil || user == nil {
		jsonError(w, http.StatusForbidden, "user session required")
		return
	}

	isVaultAdmin := false
	if role, _ := s.store.GetVaultRole(ctx, user.ID, ns.ID); role == "admin" {
		isVaultAdmin = true
	}
	if !isVaultAdmin && user.Role != "owner" {
		jsonError(w, http.StatusForbidden, "vault admin or instance owner required")
		return
	}

	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		jsonError(w, http.StatusBadRequest, "request body must include {\"name\": \"new-name\"}")
		return
	}
	if !validateSlug(body.Name) {
		jsonError(w, http.StatusBadRequest, "vault name must be 3-64 characters, lowercase alphanumeric and hyphens only")
		return
	}

	// Check uniqueness.
	existing, _ := s.store.GetVault(ctx, body.Name)
	if existing != nil {
		jsonError(w, http.StatusConflict, fmt.Sprintf("a vault named %q already exists", body.Name))
		return
	}

	if err := s.store.RenameVault(ctx, name, body.Name); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to rename vault")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message":  fmt.Sprintf("vault renamed from %q to %q", name, body.Name),
		"old_name": name,
		"new_name": body.Name,
	})
}

// ---------------------------------------------------------------------------
// Policy endpoints
// ---------------------------------------------------------------------------

func (s *Server) handlePolicyGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("vault %q not found", name))
		return
	}

	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	bc, err := s.store.GetBrokerConfig(ctx, ns.ID)
	if err != nil || bc == nil {
		// No policy set — return empty rules.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"vault": name, "rules": []interface{}{}})
		return
	}

	var rules json.RawMessage
	if err := json.Unmarshal([]byte(bc.RulesJSON), &rules); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to parse policy rules")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"vault": name, "rules": rules})
}

func (s *Server) handlePolicyCredentialUsage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("vault %q not found", name))
		return
	}

	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	key := r.URL.Query().Get("key")
	if key == "" {
		jsonError(w, http.StatusBadRequest, "missing required query parameter: key")
		return
	}

	bc, err := s.store.GetBrokerConfig(ctx, ns.ID)
	if err != nil || bc == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"rules": []interface{}{}})
		return
	}

	var rules []broker.Rule
	if err := json.Unmarshal([]byte(bc.RulesJSON), &rules); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to parse policy rules")
		return
	}

	type ruleRef struct {
		Host        string `json:"host"`
		Description string `json:"description,omitempty"`
	}
	var refs []ruleRef
	for _, rule := range rules {
		for _, sk := range rule.Auth.CredentialKeys() {
			if sk == key {
				ref := ruleRef{Host: rule.Host}
				if rule.Description != nil {
					ref.Description = *rule.Description
				}
				refs = append(refs, ref)
				break
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if refs == nil {
		refs = []ruleRef{}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"rules": refs})
}

func (s *Server) handlePolicySet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("vault %q not found", name))
		return
	}

	// Setting policy requires admin role.
	if _, err := s.requireVaultAdmin(w, r, ns.ID); err != nil {
		return
	}

	var req struct {
		Rules json.RawMessage `json:"rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate rules by unmarshalling into broker.Rule slice and running broker.Validate.
	var rules []broker.Rule
	if err := json.Unmarshal(req.Rules, &rules); err != nil {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("invalid rules: %v", err))
		return
	}
	cfg := broker.Config{Vault: name, Rules: rules}
	if err := broker.Validate(&cfg); err != nil {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("invalid policy: %v", err))
		return
	}

	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to marshal rules")
		return
	}

	if _, err := s.store.SetBrokerConfig(ctx, ns.ID, string(rulesJSON)); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to set policy")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"vault": name, "rules_count": len(rules)})
}

func (s *Server) handlePolicyClear(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	ns, err := s.store.GetVault(ctx, name)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("vault %q not found", name))
		return
	}

	// Clearing policy requires admin role.
	if _, err := s.requireVaultAdmin(w, r, ns.ID); err != nil {
		return
	}

	if _, err := s.store.SetBrokerConfig(ctx, ns.ID, "[]"); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to clear policy")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"vault": name, "cleared": true})
}

// ---------------------------------------------------------------------------
// Invite create endpoint
// ---------------------------------------------------------------------------

func (s *Server) handleInviteCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		Vault      string `json:"vault"`
		Persistent bool   `json:"persistent"`
		TTLSeconds int    `json:"ttl_seconds"`
		AgentName  string `json:"agent_name"`
		VaultRole  string `json:"vault_role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}
	if req.TTLSeconds <= 0 {
		req.TTLSeconds = 900 // 15 minutes default
	}
	// Cap invite TTL: 24 hours for temporary, 7 days for persistent.
	maxTTL := 24 * 60 * 60 // 24 hours
	if req.Persistent {
		maxTTL = 7 * 24 * 60 * 60 // 7 days
	}
	if req.TTLSeconds > maxTTL {
		req.TTLSeconds = maxTTL
	}
	if req.VaultRole == "" {
		req.VaultRole = "consumer"
	}
	if req.VaultRole != "consumer" && req.VaultRole != "member" && req.VaultRole != "admin" {
		jsonError(w, http.StatusBadRequest, "vault_role must be one of: consumer, member, admin")
		return
	}

	if req.AgentName != "" && !req.Persistent {
		jsonError(w, http.StatusBadRequest, "agent_name requires persistent=true")
		return
	}

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("vault %q not found", req.Vault))
		return
	}

	// Role-based invite enforcement:
	// - Consumers cannot invite anyone.
	// - Members can invite agents but only as consumers.
	// - Admins (user vault admin or admin agent) can invite with any role.
	sess := sessionFromContext(ctx)
	if sess == nil {
		jsonError(w, http.StatusForbidden, "authentication required")
		return
	}

	if sess.VaultID != "" {
		// Scoped session (agent or temp invite).
		if sess.VaultID != ns.ID {
			jsonError(w, http.StatusForbidden, "session not authorized for this vault")
			return
		}
		if !agentRoleSatisfies(sess.VaultRole, "member") {
			jsonError(w, http.StatusForbidden, "member role required to create agent invites")
			return
		}
		// Members can only invite consumers.
		if sess.VaultRole == "member" && req.VaultRole != "consumer" {
			req.VaultRole = "consumer"
		}
	} else {
		// User session: require vault access.
		user, err := s.userFromSession(ctx, sess)
		if err != nil || user == nil {
			jsonError(w, http.StatusForbidden, "invalid session")
			return
		}
		has, err := s.store.HasVaultAccess(ctx, user.ID, ns.ID)
		if err != nil || !has {
			jsonError(w, http.StatusForbidden, "no access to this vault")
			return
		}
		// User vault members can only invite consumers.
		role, _ := s.store.GetVaultRole(ctx, user.ID, ns.ID)
		if role != "admin" && req.VaultRole != "consumer" {
			req.VaultRole = "consumer"
		}
	}

	// Check pending invite limit.
	count, err := s.store.CountPendingInvites(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to check pending invites")
		return
	}
	if count >= 10 {
		jsonError(w, http.StatusTooManyRequests, fmt.Sprintf("too many pending invites (%d) — revoke some before creating new ones", count))
		return
	}

	createdBy := "api"
	if sess.UserID != "" {
		createdBy = sess.UserID
	}

	expiresAt := time.Now().Add(time.Duration(req.TTLSeconds) * time.Second)

	if req.Persistent {
		// Check for duplicate agent name.
		if req.AgentName != "" {
			existing, _ := s.store.GetAgentByName(ctx, req.AgentName)
			if existing != nil {
				jsonError(w, http.StatusConflict, fmt.Sprintf("an agent named %q already exists", req.AgentName))
				return
			}
		}

		inv, err := s.store.CreatePersistentInvite(ctx, ns.ID, req.VaultRole, createdBy, req.AgentName, expiresAt)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "failed to create persistent invite")
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

	inv, err := s.store.CreateInvite(ctx, ns.ID, req.VaultRole, createdBy, expiresAt)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create invite")
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
		jsonError(w, http.StatusNotFound, fmt.Sprintf("vault %q not found", nsName))
		return
	}

	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	// Consumer-role agents can only view pending proposals (to avoid duplicates).
	sess := sessionFromContext(r.Context())
	isConsumer := sess != nil && sess.VaultID != "" && sess.VaultRole == "consumer"

	// Lazy expiration.
	_, _ = s.store.ExpirePendingProposals(ctx, time.Now().Add(-7*24*time.Hour))

	status := r.URL.Query().Get("status")
	if isConsumer {
		status = "pending"
	}
	list, err := s.store.ListProposals(ctx, ns.ID, status)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list proposals")
		return
	}

	type csItem struct {
		ID          int     `json:"id"`
		Status      string  `json:"status"`
		Message     string  `json:"message"`
		RulesJSON   string  `json:"rules_json"`
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
			RulesJSON:   cs.RulesJSON,
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
		jsonError(w, http.StatusNotFound, fmt.Sprintf("vault %q not found", nsName))
		return
	}

	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid proposal id")
		return
	}

	cs, err := s.store.GetProposal(ctx, ns.ID, id)
	if err != nil || cs == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("proposal #%d not found in vault %q", id, nsName))
		return
	}

	// Consumer-role agents can only view pending proposals.
	sess := sessionFromContext(r.Context())
	if sess != nil && sess.VaultID != "" && sess.VaultRole == "consumer" && cs.Status != "pending" {
		jsonError(w, http.StatusForbidden, "consumer agents can only view pending proposals")
		return
	}

	resp := map[string]interface{}{
		"id":           cs.ID,
		"status":       cs.Status,
		"message":      cs.Message,
		"user_message": cs.UserMessage,
		"rules_json":   cs.RulesJSON,
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

// newServiceToken generates a cryptographically random service token.
func newServiceToken() string {
	var b [32]byte
	if _, err := io.ReadFull(crand.Reader, b[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return "av_agent_" + fmt.Sprintf("%x", b[:])
}

// serviceTokenPrefix extracts the first 16 hex chars after the "av_agent_" prefix.
func serviceTokenPrefix(token string) string {
	body := strings.TrimPrefix(token, "av_agent_")
	if len(body) < 16 {
		return body
	}
	return body[:16]
}
