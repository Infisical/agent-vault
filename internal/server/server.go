package server

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"net"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/pidfile"
	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/requestlog"
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
	skillCLI       []byte       // embedded CLI skill content (served at GET /v1/skills/cli)
	skillHTTP      []byte       // embedded HTTP skill content (served at GET /v1/skills/http)
	mitm           *mitm.Proxy          // transparent MITM proxy; nil only when --mitm-port 0
	logger         *slog.Logger         // structured logger for per-request observability
	rateLimit      *ratelimit.Registry  // tiered rate limiter; shared with the MITM ingress
	logSink        requestlog.Sink      // per-request persistence sink; never nil (Nop default)
}

// RateLimit returns the server's rate-limit registry. Exported so the
// MITM ingress can share the same tier state (see cmd/server.go).
func (s *Server) RateLimit() *ratelimit.Registry { return s.rateLimit }

// AttachMITM registers an optional transparent MITM proxy whose lifecycle
// is bound to this Server: Start launches it, and SIGINT/SIGTERM/Shutdown
// stops it alongside the HTTP server.
func (s *Server) AttachMITM(p *mitm.Proxy) { s.mitm = p }

// AttachLogSink swaps the per-request log sink. Safe to call once at
// startup, before the HTTP server begins accepting connections. nil
// resets to a Nop sink.
func (s *Server) AttachLogSink(sink requestlog.Sink) {
	if sink == nil {
		sink = requestlog.Nop{}
	}
	s.logSink = sink
}

// LogSink returns the server's log sink. Shared with the MITM ingress so
// both paths feed the same pipeline.
func (s *Server) LogSink() requestlog.Sink { return s.logSink }

// SessionResolver returns a brokercore.SessionResolver backed by this
// server's store.
func (s *Server) SessionResolver() brokercore.SessionResolver {
	return brokercore.NewStoreSessionResolver(s.store)
}

// CredentialProvider returns a brokercore.CredentialProvider backed by
// this server's store and encryption key.
func (s *Server) CredentialProvider() brokercore.CredentialProvider {
	return brokercore.NewStoreCredentialProvider(s.store, s.encKey)
}

// Logger returns the server's structured logger. Callers (e.g. the MITM
// proxy constructed outside the server) use this to share a single logger
// across ingress paths.
func (s *Server) Logger() *slog.Logger { return s.logger }

// BaseURL returns the externally-reachable base URL of the server
// (e.g. "http://127.0.0.1:14321").
func (s *Server) BaseURL() string { return s.baseURL }

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
	CountAgentTokens(ctx context.Context, agentID string) (int, error)
	GetLatestAgentTokenExpiry(ctx context.Context, agentID string) (*time.Time, error)
	DeleteAgentTokens(ctx context.Context, agentID string) error
	CreateAgentToken(ctx context.Context, agentID string, expiresAt *time.Time) (*store.Session, error)
	CountAllOwners(ctx context.Context) (int, error)

	// Request logs
	InsertRequestLogs(ctx context.Context, rows []store.RequestLog) error
	ListRequestLogs(ctx context.Context, opts store.ListRequestLogsOpts) ([]store.RequestLog, error)
	DeleteOldRequestLogs(ctx context.Context, before time.Time) (int64, error)
	TrimRequestLogsToCap(ctx context.Context, vaultID string, cap int64) (int64, error)
	VaultIDsWithLogs(ctx context.Context) ([]string, error)

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
// logger must be non-nil; tests can pass slog.New(slog.DiscardHandler).
func New(addr string, store Store, encKey []byte, notifier *notify.Notifier, initialized bool, baseURL string, oauthProviders map[string]oauth.Provider, logger *slog.Logger) *Server {
	mux := http.NewServeMux()

	// Initialize proxy client once (reads AGENT_VAULT_NETWORK_MODE after env is configured).
	if proxyClient == nil {
		proxyClient = newProxyClient()
	}

	rlCfg, _ := ratelimit.LoadFromEnv()
	rl := ratelimit.New(rlCfg)

	s := &Server{
		httpServer: &http.Server{
			Addr:              addr,
			Handler:           securityHeaders(rl.GlobalMiddleware(logger)(mux)),
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
		logger:         logger,
		rateLimit:      rl,
		logSink:        requestlog.Nop{},
	}

	ipAuth := s.tier(ratelimit.TierAuth, s.ipKeyer())
	ipInviteToken := s.tier(ratelimit.TierAuth, s.tokenKeyer("token"))

	// /health, /v1/status, and other public static routes rely on the
	// server-wide TierGlobal backstop; no per-route limit is useful.
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /v1/status", s.handleStatus)
	mux.HandleFunc("POST /v1/auth/register", ipAuth(limitBody(s.handleRegister)))
	mux.HandleFunc("POST /v1/auth/verify", ipAuth(limitBody(s.handleVerify)))
	mux.HandleFunc("POST /v1/auth/resend-verification", ipAuth(limitBody(s.handleResendVerification)))
	mux.HandleFunc("POST /v1/auth/forgot-password", ipAuth(limitBody(s.handleForgotPassword)))
	mux.HandleFunc("POST /v1/auth/reset-password", ipAuth(limitBody(s.handleResetPassword)))

	actorAuthed := s.tier(ratelimit.TierAuthed, s.actorKeyer())

	// Require initialization
	mux.HandleFunc("GET /v1/auth/me", s.requireInitialized(s.requireAuth(actorAuthed(s.handleAuthMe))))
	mux.HandleFunc("POST /v1/auth/login", s.requireInitialized(ipAuth(limitBody(s.handleLogin))))
	mux.HandleFunc("POST /v1/auth/change-password", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleChangePassword)))))
	mux.HandleFunc("DELETE /v1/auth/account", s.requireInitialized(s.requireAuth(actorAuthed(s.handleDeleteAccount))))
	mux.HandleFunc("POST /v1/sessions", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleScopedSession)))))
	mux.HandleFunc("GET /v1/credentials", s.requireInitialized(s.requireAuth(actorAuthed(s.handleCredentialsList))))
	mux.HandleFunc("POST /v1/credentials", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleCredentialsSet)))))
	mux.HandleFunc("DELETE /v1/credentials", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleCredentialsDelete)))))
	mux.HandleFunc("GET /discover", s.requireInitialized(s.requireAuth(actorAuthed(s.handleDiscover))))
	mux.HandleFunc("POST /v1/proposals", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleProposalCreate)))))
	mux.HandleFunc("GET /v1/proposals/{id}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleProposalGet))))
	mux.HandleFunc("GET /v1/proposals", s.requireInitialized(s.requireAuth(actorAuthed(s.handleProposalList))))
	mux.HandleFunc("POST /v1/admin/proposals/{id}/approve", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleAdminProposalApprove)))))
	mux.HandleFunc("POST /v1/admin/proposals/{id}/reject", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleAdminProposalReject)))))
	// /proxy/ enforces its rate limit inside the handler (needs the resolved vault).
	mux.HandleFunc("/proxy/", s.requireInitialized(s.requireAuth(s.handleProxy)))

	// Agent invite redemption (no auth — token is the credential)
	mux.HandleFunc("GET /invite/{token}", s.requireInitialized(ipInviteToken(s.handleInviteRedeem)))
	mux.HandleFunc("POST /invite/{token}", s.requireInitialized(ipInviteToken(limitBody(s.handlePersistentInviteRedeem))))

	ipUserInviteToken := s.tier(ratelimit.TierAuth, ratelimit.IPTokenKey(clientIP, func(r *http.Request) string {
		return r.PathValue("token")
	}))
	ipApprovalToken := s.tier(ratelimit.TierAuth, ratelimit.IPTokenKey(clientIP, func(r *http.Request) string {
		return r.URL.Query().Get("token")
	}))
	// OAuth callback: keyed on the hashed state query param.
	ipOAuthCallback := s.tier(ratelimit.TierAuth, ratelimit.IPTokenKey(clientIP, func(r *http.Request) string {
		return r.URL.Query().Get("state")
	}))

	// Agent invites (instance-level, requires auth)
	mux.HandleFunc("POST /v1/agents/invites", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleAgentInviteCreate)))))
	mux.HandleFunc("GET /v1/agents/invites", s.requireInitialized(s.requireAuth(actorAuthed(s.handleAgentInviteList))))
	mux.HandleFunc("DELETE /v1/agents/invites/{token}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleAgentInviteRevoke))))
	mux.HandleFunc("DELETE /v1/agents/invites/by-id/{id}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleAgentInviteRevokeByID))))

	// Agent management (instance-level)
	mux.HandleFunc("GET /v1/agents", s.requireInitialized(s.requireAuth(actorAuthed(s.handleAgentList))))
	mux.HandleFunc("GET /v1/agents/{name}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleAgentGet))))
	mux.HandleFunc("DELETE /v1/agents/{name}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleAgentRevoke))))
	mux.HandleFunc("POST /v1/agents/{name}/rotate", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleAgentRotate)))))
	mux.HandleFunc("POST /v1/agents/{name}/rename", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleAgentRename)))))
	mux.HandleFunc("POST /v1/agents/{name}/role", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleAgentSetRole)))))

	// Vault-level agent management
	mux.HandleFunc("GET /v1/vaults/{name}/agents", s.requireInitialized(s.requireAuth(actorAuthed(s.handleVaultAgentList))))
	mux.HandleFunc("POST /v1/vaults/{name}/agents", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleVaultAgentAdd)))))
	mux.HandleFunc("DELETE /v1/vaults/{name}/agents/{agentName}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleVaultAgentRemove))))
	mux.HandleFunc("POST /v1/vaults/{name}/agents/{agentName}/role", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleVaultAgentSetRole)))))

	// Instance settings (owner-only)
	mux.HandleFunc("GET /v1/admin/settings", s.requireInitialized(s.requireAuth(actorAuthed(s.handleGetSettings))))
	mux.HandleFunc("PUT /v1/admin/settings", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleUpdateSettings)))))
	mux.HandleFunc("POST /v1/admin/settings/rate-limit/preview", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleRateLimitPreview)))))

	// Public user list (any authenticated user)
	mux.HandleFunc("GET /v1/users", s.requireInitialized(s.requireAuth(actorAuthed(s.handlePublicUserList))))

	// User management (owner-only, except GET self)
	mux.HandleFunc("GET /v1/admin/users/{email}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleUserGet))))
	mux.HandleFunc("DELETE /v1/admin/users/{email}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleUserDelete))))
	mux.HandleFunc("POST /v1/admin/users/{email}/role", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleUserSetRole)))))

	// Vault management (any auth'd user)
	mux.HandleFunc("GET /v1/vaults/{name}/context", s.requireInitialized(s.requireAuth(actorAuthed(s.handleVaultContext))))
	mux.HandleFunc("POST /v1/vaults", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleVaultCreate)))))
	mux.HandleFunc("GET /v1/vaults", s.requireInitialized(s.requireAuth(actorAuthed(s.handleVaultList))))
	mux.HandleFunc("DELETE /v1/vaults/{name}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleVaultDelete))))
	mux.HandleFunc("POST /v1/vaults/{name}/rename", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleVaultRename)))))
	mux.HandleFunc("POST /v1/vaults/{name}/join", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleVaultJoin)))))

	// Vault admin (owner-only)
	mux.HandleFunc("GET /v1/admin/vaults", s.requireInitialized(s.requireAuth(actorAuthed(s.handleAdminVaultList))))
	mux.HandleFunc("GET /v1/vaults/{name}/services", s.requireInitialized(s.requireAuth(actorAuthed(s.handleServicesGet))))
	mux.HandleFunc("POST /v1/vaults/{name}/services", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleServicesUpsert)))))
	mux.HandleFunc("PUT /v1/vaults/{name}/services", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleServicesSet)))))
	mux.HandleFunc("PATCH /v1/vaults/{name}/services/{host}", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleServicePatch)))))
	mux.HandleFunc("DELETE /v1/vaults/{name}/services/{host}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleServiceRemove))))
	mux.HandleFunc("DELETE /v1/vaults/{name}/services", s.requireInitialized(s.requireAuth(actorAuthed(s.handleServicesClear))))
	mux.HandleFunc("GET /v1/vaults/{name}/services/credential-usage", s.requireInitialized(s.requireAuth(actorAuthed(s.handleServicesCredentialUsage))))
	mux.HandleFunc("GET /v1/vaults/{name}/logs", s.requireInitialized(s.requireAuth(actorAuthed(s.handleVaultLogsList))))
	// Public static reads — immutable payloads with no credentials on
	// the wire. TierGlobal is the only useful backstop; TierAuth would
	// punish `vault run` (CA fetch per invocation) and the dashboard
	// (re-mount poll) without defending any real surface.
	mux.HandleFunc("GET /v1/service-catalog", s.requireInitialized(s.handleServiceCatalog))
	mux.HandleFunc("GET /v1/skills/cli", s.requireInitialized(s.handleSkillCLI))
	mux.HandleFunc("GET /v1/skills/http", s.requireInitialized(s.handleSkillHTTP))
	// CA PEM is not wrapped in requireInitialized — the CA lifecycle is
	// tied to --mitm-port, not owner registration.
	mux.HandleFunc("GET /v1/mitm/ca.pem", s.handleMITMCA)

	// Instance-level user invites
	mux.HandleFunc("POST /v1/users/invites", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleUserInviteCreate)))))
	mux.HandleFunc("GET /v1/users/invites", s.requireInitialized(s.requireAuth(actorAuthed(s.handleUserInviteList))))
	mux.HandleFunc("DELETE /v1/users/invites/{token}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleUserInviteRevoke))))
	mux.HandleFunc("POST /v1/users/invites/{token}/reinvite", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleUserInviteReinvite)))))
	mux.HandleFunc("GET /v1/users/invites/{token}/details", s.requireInitialized(ipUserInviteToken(s.handleUserInviteDetails)))
	mux.HandleFunc("POST /v1/users/invites/{token}/accept", s.requireInitialized(ipUserInviteToken(limitBody(s.handleUserInviteAccept))))

	// Vault user management (vault admin)
	mux.HandleFunc("GET /v1/vaults/{name}/users", s.requireInitialized(s.requireAuth(actorAuthed(s.handleVaultUserList))))
	mux.HandleFunc("POST /v1/vaults/{name}/users", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleVaultUserAdd)))))
	mux.HandleFunc("DELETE /v1/vaults/{name}/users/{email}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleVaultUserRemove))))
	mux.HandleFunc("POST /v1/vaults/{name}/users/{email}/role", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleVaultUserSetRole)))))

	// Proposal approval details (token-based, no auth required)
	mux.HandleFunc("GET /v1/proposals/approve-details", s.requireInitialized(ipApprovalToken(s.handleProposalApproveDetails)))

	// Admin proposal management
	mux.HandleFunc("GET /v1/admin/proposals", s.requireInitialized(s.requireAuth(actorAuthed(s.handleAdminProposalList))))
	mux.HandleFunc("GET /v1/admin/proposals/{id}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleAdminProposalGet))))

	// Email
	mux.HandleFunc("POST /v1/admin/email/test", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleEmailTest)))))

	mux.HandleFunc("POST /v1/auth/logout", s.requireInitialized(ipAuth(s.handleLogout)))

	// OAuth
	mux.HandleFunc("GET /v1/auth/oauth/providers", ipAuth(s.handleOAuthProviders))
	mux.HandleFunc("GET /v1/auth/oauth/{provider}/login", s.requireInitialized(ipAuth(s.optionalAuth(s.handleOAuthLogin))))
	mux.HandleFunc("GET /v1/auth/oauth/{provider}/callback", s.requireInitialized(ipOAuthCallback(s.handleOAuthCallback)))
	mux.HandleFunc("POST /v1/auth/oauth/{provider}/connect", s.requireInitialized(s.requireAuth(actorAuthed(s.handleOAuthConnect))))
	mux.HandleFunc("DELETE /v1/auth/oauth/{provider}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleOAuthDisconnect))))

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
	// Non-fatal: registry already holds env-based config from New().
	if s.initialized {
		if _, err := s.applyRateLimitSettingToRegistry(context.Background()); err != nil {
			s.logger.Warn("ratelimit setting load failed", "err", err.Error())
		}
	}

	// Bind synchronously so EADDRINUSE returns from Start() before any pidfile
	// work happens. Keeps a foreground invocation against an already-running
	// daemon from clobbering the daemon's PID file.
	httpLn, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.httpServer.Addr, err)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		fmt.Printf("Agent Vault server listening on %s\n", s.baseURL)
		if !s.initialized {
			fmt.Printf("Run `agent-vault auth register` or visit %s to create the owner account\n", s.baseURL)
		}
		if err := s.httpServer.Serve(httpLn); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	if s.mitm != nil {
		go func() {
			l, err := net.Listen("tcp", s.mitm.Addr())
			if err != nil {
				// MITM is best-effort (e.g. default-on port conflict shouldn't
				// kill the core HTTP server). Log and let the goroutine exit.
				fmt.Fprintf(os.Stderr, "warning: transparent proxy unavailable: %v\n", err)
				return
			}
			fmt.Printf("Agent Vault transparent proxy listening on %s\n", s.mitm.Addr())
			if err := s.mitm.Serve(l); err != nil && err != http.ErrServerClosed {
				fmt.Fprintf(os.Stderr, "warning: transparent proxy stopped: %v\n", err)
			}
		}()
	}

	if err := pidfile.WriteIfFree(os.Getpid()); err != nil {
		if errors.Is(err, pidfile.ErrAlreadyRunning) {
			s.logger.Warn("pidfile owned by another process; not claiming or removing it")
		} else {
			fmt.Fprintf(os.Stderr, "warning: could not write PID file: %v\n", err)
		}
	} else {
		defer func() { _ = pidfile.Remove() }()
	}

	select {
	case err := <-errCh:
		return err
	case <-stop:
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fmt.Println("shutting down server...")
	if s.mitm != nil {
		if err := s.mitm.Shutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "warning: mitm proxy shutdown: %v\n", err)
		}
	}
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

// ipKeyer returns a ratelimit.Keyer that keys on the request's client IP
// (honoring AGENT_VAULT_TRUSTED_PROXIES via clientIP).
func (s *Server) ipKeyer() ratelimit.Keyer {
	return ratelimit.IPKey(clientIP)
}

// actorKeyer returns a ratelimit.Keyer that keys on the authenticated
// actor (user or agent). Returns "" if no session is on the context;
// the middleware then skips the check, which is safe because actor
// tiers are wrapped *after* requireAuth.
func (s *Server) actorKeyer() ratelimit.Keyer {
	return ratelimit.ActorKey(func(r *http.Request) string {
		sess := sessionFromContext(r.Context())
		if sess == nil {
			return ""
		}
		if sess.UserID != "" {
			return "u:" + sess.UserID
		}
		return "a:" + sess.AgentID
	})
}

// tokenKeyer returns a ratelimit.Keyer that combines clientIP with a
// hashed URL path value so token-enumeration attempts are bounded by
// both the caller's IP and the token being probed.
func (s *Server) tokenKeyer(pathValue string) ratelimit.Keyer {
	return ratelimit.IPTokenKey(clientIP, func(r *http.Request) string {
		return r.PathValue(pathValue)
	})
}

// tier wraps handler with a rate-limit check for tier keyed by keyer.
// On denial the middleware writes a 429 with standard headers; on
// allow, it calls handler. This is the canonical way new routes in
// server.go register tier enforcement.
func (s *Server) tier(t ratelimit.Tier, keyer ratelimit.Keyer) func(http.HandlerFunc) http.HandlerFunc {
	return s.rateLimit.HandlerFunc(t, keyer, s.logger)
}

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

const settingRateLimitConfig = "ratelimit_config"
