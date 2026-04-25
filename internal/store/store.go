package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// ErrNotFirstUser is returned by RegisterFirstUser when users already exist.
var ErrNotFirstUser = errors.New("users already exist; not first user")

// DefaultVault is the name of the automatically-seeded vault.
const DefaultVault = "default"

// Vault represents a logical grouping of credentials.
type Vault struct {
	ID        string
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// VaultGrant represents an actor's (user or agent) access to a vault with a specific role.
type VaultGrant struct {
	ActorID   string
	ActorType string // "user" or "agent"
	VaultID   string
	VaultName string // populated via JOIN on reads (optional)
	Role      string // "proxy", "member", or "admin"
	CreatedAt time.Time
}

// Credential represents an encrypted credential within a vault.
// Ciphertext and Nonce are opaque bytes, encryption is handled
// by the caller, not the store.
type Credential struct {
	ID         string
	VaultID    string
	Key        string
	Ciphertext []byte
	Nonce      []byte
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// MasterKeyRecord holds the KEK/DEK key-wrapping artifacts.
// The sentinel is always encrypted with the DEK for verification.
// In password-protected mode: DEKCiphertext/DEKNonce hold the KEK-wrapped DEK.
// In passwordless mode: DEKPlaintext holds the unwrapped DEK.
type MasterKeyRecord struct {
	Sentinel      []byte // sentinel ciphertext (encrypted with DEK)
	SentinelNonce []byte // sentinel GCM nonce
	DEKCiphertext []byte // wrapped DEK (nil in passwordless mode)
	DEKNonce      []byte // DEK wrapping nonce (nil in passwordless mode)
	DEKPlaintext  []byte // unwrapped DEK (nil when password-protected)
	Salt          []byte // KDF salt (nil in passwordless mode)
	KDFTime       *uint32
	KDFMemory     *uint32
	KDFThreads    *uint8
	CreatedAt     time.Time
}

// Session represents an authenticated session.
// User sessions: VaultID may be set (scoped) or empty (global login).
// Agent tokens: VaultID is empty; vault resolved per-request via X-Vault header.
type Session struct {
	ID        string
	UserID    string     // non-empty for user login sessions, empty for agent tokens
	VaultID   string     // empty for global/agent tokens, non-empty for user scoped sessions
	AgentID   string     // non-empty for agent tokens
	VaultRole string     // set for user scoped sessions; empty for agent tokens (resolved per-request)
	ExpiresAt *time.Time // nil = never expires
	CreatedAt time.Time

	// User-session sliding-expiry fields. Populated by CreateUserSession;
	// left zero for scoped sessions and agent tokens.
	PublicID      string        // short opaque handle for revoke endpoint; empty for scoped/agent
	LastUsedAt    *time.Time    // last time the token was successfully resolved
	IdleTTL       time.Duration // 0 = no idle expiry (agent tokens, legacy rows)
	DeviceLabel   string        // user-visible label, e.g. hostname
	LastIP        string
	LastUserAgent string
}

// IsExpired reports whether the session is past its absolute expiry or its
// idle window. Single source of truth for expiry checks across the server
// (requireAuth) and proxy ingress (brokercore.SessionResolver).
func (s *Session) IsExpired(now time.Time) bool {
	if s.ExpiresAt != nil && now.After(*s.ExpiresAt) {
		return true
	}
	if s.IdleTTL > 0 && s.LastUsedAt != nil && now.Sub(*s.LastUsedAt) > s.IdleTTL {
		return true
	}
	return false
}

// CreateUserSessionParams carries all the fields persisted on a fresh
// user-login session. Captured as a struct so login, OAuth callback, and
// password-change call sites stay aligned without positional drift.
type CreateUserSessionParams struct {
	UserID        string
	ExpiresAt     time.Time
	IdleTTL       time.Duration
	DeviceLabel   string
	LastIP        string
	LastUserAgent string
}

// User represents a human user account.
type User struct {
	ID           string
	Email        string
	PasswordHash []byte
	PasswordSalt []byte
	KDFTime      uint32 // Argon2id time parameter used when password was hashed
	KDFMemory    uint32 // Argon2id memory parameter (KiB) used when password was hashed
	KDFThreads   uint8  // Argon2id threads parameter used when password was hashed
	Role         string // "owner" or "member"
	IsActive     bool   // false until email is verified (first user is auto-active)
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// BrokerConfig holds the brokering services for a vault.
type BrokerConfig struct {
	ID          string
	VaultID     string
	ServicesJSON string // JSON-encoded []broker.Service
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Proposal represents a proposed set of changes (services + credential slots)
// created by an agent, pending human approval.
type Proposal struct {
	ID                     int // sequential per vault (1, 2, 3, ...)
	VaultID                string
	SessionID              string
	Status                 string
	ServicesJSON           string
	CredentialsJSON        string
	Message                string
	UserMessage            string // human-facing explanation shown on the browser approval page
	ReviewNote             string
	ReviewedAt             *string
	ApprovalToken          string     // random token for browser-based approval URL
	ApprovalTokenExpiresAt *time.Time // expiry for the approval token (default 24h)
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// EncryptedCredential holds an encrypted credential value (ciphertext + nonce).
type EncryptedCredential struct {
	Ciphertext []byte
	Nonce      []byte
}

// RequestLog is a persisted record of a single proxied request. Secret-free
// by construction: no header values, no bodies, no query strings — only
// metadata already safe to log (see internal/brokercore/logging.go).
type RequestLog struct {
	ID             int64
	VaultID        string
	ActorType      string // brokercore.ActorType{User,Agent} or ""
	ActorID        string
	Ingress        string // brokercore.Ingress{Explicit,MITM}
	Method         string
	Host           string
	Path           string
	MatchedService string
	CredentialKeys []string
	Status         int
	LatencyMs      int64
	ErrorCode      string
	CreatedAt      time.Time
}

// ListRequestLogsOpts controls the ListRequestLogs query.
// Exactly one of Before or After may be set (both zero returns the newest page).
// VaultID == nil means "all vaults" — reserved for a future owner-only endpoint.
type ListRequestLogsOpts struct {
	VaultID        *string
	Ingress        string // "", "explicit", "mitm"
	StatusBucket   string // "", "2xx", "3xx", "4xx", "5xx", "err"
	MatchedService string
	Before         int64 // rows with id < Before (pagination going back)
	After          int64 // rows with id > After (polling for new rows)
	Limit          int   // capped at 200 by handler; store trusts caller
}

// Invite represents a named agent invite with optional vault pre-assignments.
// All invites create named, instance-level agents on redemption.
type Invite struct {
	ID                int
	Token             string
	AgentName         string             // required: agent name (3-64 chars, lowercase alphanumeric + hyphens)
	AgentID           string             // set for rotation invites (references existing agent)
	AgentRole         string             // "owner" or "member" — instance role for the agent
	SessionTTLSeconds int                // desired session lifetime when redeemed (0 = no expiry)
	Status            string             // pending, redeemed, expired, revoked
	SessionID         string             // populated after redemption
	CreatedBy         string             // session ID of the creator
	Vaults            []AgentInviteVault // pre-assigned vault access
	CreatedAt         time.Time
	ExpiresAt         time.Time
	RedeemedAt        *time.Time
	RevokedAt         *time.Time
}

// AgentInviteVault represents a pre-assigned vault grant on an agent invite.
type AgentInviteVault struct {
	VaultID   string
	VaultName string // populated via JOIN on reads
	VaultRole string // "proxy", "member", or "admin"
}

// Agent represents a named, instance-level agent entity.
// Agents have multi-vault access via VaultGrant records and an instance-level role.
type Agent struct {
	ID        string
	Name      string
	Role      string // "owner" or "member" (instance-level role, like users)
	Status    string // "active" or "revoked"
	CreatedBy string // user ID of the creator
	Vaults    []VaultGrant
	CreatedAt time.Time
	UpdatedAt time.Time
	RevokedAt *time.Time
}

// UserInvite represents an instance-level invitation for a new user.
// Invites bring users into the instance, with optional vault pre-assignment.
type UserInvite struct {
	ID         int
	Token      string // only populated on creation (not stored in DB)
	Email      string
	Role       string // "owner" or "member" — instance role for the invited user
	Status     string // pending, accepted, expired, revoked
	CreatedBy  string // user ID of the inviter
	CreatedAt  time.Time
	ExpiresAt  time.Time
	AcceptedAt *time.Time
	Vaults     []UserInviteVault // pre-assigned vault access
}

// UserInviteVault represents a pre-assigned vault grant on a user invite.
type UserInviteVault struct {
	VaultID   string
	VaultName string // populated via JOIN on reads
	VaultRole string // "admin" or "member"
}

// EmailVerification holds a verification code for self-signup email confirmation.
type EmailVerification struct {
	ID        int
	Email     string
	Code      string
	Status    string // "pending", "verified", "expired"
	CreatedAt time.Time
	ExpiresAt time.Time
}

// PasswordReset holds a reset code for the forgot-password flow.
type PasswordReset struct {
	ID        int
	Email     string
	Code      string
	Status    string // "pending", "used", "expired"
	CreatedAt time.Time
	ExpiresAt time.Time
}

// OAuthAccount links a user to an external OAuth provider identity.
type OAuthAccount struct {
	ID             string
	UserID         string
	Provider       string // "google", "github", etc.
	ProviderUserID string // unique ID from provider (e.g. "sub" claim)
	Email          string // email from provider (for display)
	Name           string
	AvatarURL      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// OAuthState holds CSRF state and PKCE verifier for an in-progress OAuth flow.
type OAuthState struct {
	ID           string
	StateHash    string // SHA-256 of the state parameter
	CodeVerifier string // PKCE code_verifier
	Nonce        string // OIDC nonce for ID token binding
	RedirectURL  string // where to redirect after auth
	Mode         string // "login" or "connect"
	UserID       string // set when mode is "connect" (authenticated linking)
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// Store is the persistence interface for Agent Vault.
// All methods are safe for concurrent use.
type Store interface {
	// Vaults
	CreateVault(ctx context.Context, name string) (*Vault, error)
	GetVault(ctx context.Context, name string) (*Vault, error)
	GetVaultByID(ctx context.Context, id string) (*Vault, error)
	ListVaults(ctx context.Context) ([]Vault, error)
	DeleteVault(ctx context.Context, name string) error
	RenameVault(ctx context.Context, oldName string, newName string) error

	// Credentials
	SetCredential(ctx context.Context, vaultID, key string, ciphertext, nonce []byte) (*Credential, error)
	GetCredential(ctx context.Context, vaultID, key string) (*Credential, error)
	ListCredentials(ctx context.Context, vaultID string) ([]Credential, error)
	DeleteCredential(ctx context.Context, vaultID, key string) error

	// Users
	CreateUser(ctx context.Context, email string, passwordHash, passwordSalt []byte, role string, kdfTime uint32, kdfMemory uint32, kdfThreads uint8) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByID(ctx context.Context, id string) (*User, error)
	ListUsers(ctx context.Context) ([]User, error)
	UpdateUserRole(ctx context.Context, userID, role string) error
	UpdateUserPassword(ctx context.Context, userID string, passwordHash, passwordSalt []byte, kdfTime uint32, kdfMemory uint32, kdfThreads uint8) error
	DeleteUser(ctx context.Context, userID string) error
	CountUsers(ctx context.Context) (int, error)
	CountOwners(ctx context.Context) (int, error)
	RegisterFirstUser(ctx context.Context, email string, passwordHash, passwordSalt []byte, defaultVaultID string, kdfTime uint32, kdfMemory uint32, kdfThreads uint8) (*User, error)

	// Vault grants (unified: actor_id + actor_type)
	GrantVaultRole(ctx context.Context, actorID, actorType, vaultID, role string) error
	RevokeVaultAccess(ctx context.Context, actorID, vaultID string) error
	ListActorGrants(ctx context.Context, actorID string) ([]VaultGrant, error)
	HasVaultAccess(ctx context.Context, actorID, vaultID string) (bool, error)
	GetVaultRole(ctx context.Context, actorID, vaultID string) (string, error)
	CountVaultAdmins(ctx context.Context, vaultID string) (int, error)
	ListVaultMembers(ctx context.Context, vaultID string) ([]VaultGrant, error)
	ListVaultMembersByType(ctx context.Context, vaultID, actorType string) ([]VaultGrant, error)

	// User activation
	ActivateUser(ctx context.Context, userID string) error

	// Session cleanup
	DeleteUserSessions(ctx context.Context, userID string) error

	// Sessions
	CreateUserSession(ctx context.Context, p CreateUserSessionParams) (*Session, error)
	CreateScopedSession(ctx context.Context, vaultID, vaultRole string, expiresAt *time.Time) (*Session, error)
	GetSession(ctx context.Context, id string) (*Session, error)
	DeleteSession(ctx context.Context, id string) error
	// TouchSession bumps last_used_at for the given raw token and
	// refreshes last_ip + last_user_agent (empty values leave the
	// existing column unchanged). Throttled internally so per-request
	// calls collapse to one write per minute. Returns no error when the
	// session is missing (best-effort).
	TouchSession(ctx context.Context, rawToken, ip, userAgent string) error
	// ListUserSessions returns every non-expired user session for userID
	// (ordered most-recent activity first). Used by the auth-sessions UI.
	ListUserSessions(ctx context.Context, userID string) ([]Session, error)
	// RevokeUserSession deletes a session matching both userID
	// and publicID. Scoping by userID prevents cross-account revocation.
	RevokeUserSession(ctx context.Context, userID, publicID string) error

	// Broker configs
	SetBrokerConfig(ctx context.Context, vaultID string, servicesJSON string) (*BrokerConfig, error)
	GetBrokerConfig(ctx context.Context, vaultID string) (*BrokerConfig, error)

	// Master key
	GetMasterKeyRecord(ctx context.Context) (*MasterKeyRecord, error)
	SetMasterKeyRecord(ctx context.Context, record *MasterKeyRecord) error
	UpdateMasterKeyRecord(ctx context.Context, record *MasterKeyRecord) error

	// Proposals
	CreateProposal(ctx context.Context, vaultID, sessionID, servicesJSON, credentialsJSON, message, userMessage string, credentials map[string]EncryptedCredential) (*Proposal, error)
	GetProposal(ctx context.Context, vaultID string, id int) (*Proposal, error)
	GetProposalByApprovalToken(ctx context.Context, token string) (*Proposal, error)
	ListProposals(ctx context.Context, vaultID, status string) ([]Proposal, error)
	UpdateProposalStatus(ctx context.Context, vaultID string, id int, status, reviewNote string) error
	CountPendingProposals(ctx context.Context, vaultID string) (int, error)
	ExpirePendingProposals(ctx context.Context, before time.Time) (int, error)
	GetProposalCredentials(ctx context.Context, vaultID string, proposalID int) (map[string]EncryptedCredential, error)
	ApplyProposal(ctx context.Context, vaultID string, proposalID int, mergedServicesJSON string, credentials map[string]EncryptedCredential, deleteCredentialKeys []string) error

	// Agent invites (instance-level)
	CreateAgentInvite(ctx context.Context, agentName, createdBy string, expiresAt time.Time, sessionTTLSeconds int, agentRole string, vaults []AgentInviteVault) (*Invite, error)
	CreateRotationInvite(ctx context.Context, agentID, createdBy string, expiresAt time.Time) (*Invite, error)
	GetInviteByToken(ctx context.Context, token string) (*Invite, error)
	ListInvites(ctx context.Context, status string) ([]Invite, error)
	ListInvitesByVault(ctx context.Context, vaultID, status string) ([]Invite, error)
	RedeemInvite(ctx context.Context, token, sessionID string) error
	UpdateInviteSessionID(ctx context.Context, inviteID int, sessionID string) error
	RevokeInvite(ctx context.Context, token string) error
	GetInviteByID(ctx context.Context, id int) (*Invite, error)
	RevokeInviteByID(ctx context.Context, id int) error
	CountPendingInvites(ctx context.Context) (int, error)
	HasPendingInviteByAgentName(ctx context.Context, name string) (bool, error)
	GetPendingInviteByAgentName(ctx context.Context, name string) (*Invite, error)
	AddAgentInviteVault(ctx context.Context, inviteID int, vaultID, role string) error
	RemoveAgentInviteVault(ctx context.Context, inviteID int, vaultID string) error
	UpdateAgentInviteVaultRole(ctx context.Context, inviteID int, vaultID, role string) error
	ExpirePendingInvites(ctx context.Context, before time.Time) (int, error)

	// User invites (instance-level)
	CreateUserInvite(ctx context.Context, email, createdBy, role string, expiresAt time.Time, vaults []UserInviteVault) (*UserInvite, error)
	GetUserInviteByToken(ctx context.Context, token string) (*UserInvite, error)
	GetPendingUserInviteByEmail(ctx context.Context, email string) (*UserInvite, error)
	ListUserInvites(ctx context.Context, status string) ([]UserInvite, error)
	ListUserInvitesByVault(ctx context.Context, vaultID, status string) ([]UserInvite, error)
	AcceptUserInvite(ctx context.Context, token string) error
	RevokeUserInvite(ctx context.Context, token string) error
	UpdateUserInviteVaults(ctx context.Context, token string, vaults []UserInviteVault) error
	CountPendingUserInvites(ctx context.Context) (int, error)

	// Email verification
	CreateEmailVerification(ctx context.Context, email, code string, expiresAt time.Time) (*EmailVerification, error)
	GetPendingEmailVerification(ctx context.Context, email, code string) (*EmailVerification, error)
	MarkEmailVerificationUsed(ctx context.Context, id int) error
	CountPendingEmailVerifications(ctx context.Context, email string) (int, error)

	// Password resets
	CreatePasswordReset(ctx context.Context, email, code string, expiresAt time.Time) (*PasswordReset, error)
	GetPendingPasswordReset(ctx context.Context, email, code string) (*PasswordReset, error)
	MarkPasswordResetUsed(ctx context.Context, id int) error
	CountPendingPasswordResets(ctx context.Context, email string) (int, error)
	ExpirePendingPasswordResets(ctx context.Context, before time.Time) (int, error)

	// OAuth accounts
	CreateOAuthAccount(ctx context.Context, userID, provider, providerUserID, email, name, avatarURL string) (*OAuthAccount, error)
	GetOAuthAccount(ctx context.Context, provider, providerUserID string) (*OAuthAccount, error)
	GetOAuthAccountByUser(ctx context.Context, userID, provider string) (*OAuthAccount, error)
	ListUserOAuthAccounts(ctx context.Context, userID string) ([]OAuthAccount, error)
	DeleteOAuthAccount(ctx context.Context, userID, provider string) error

	// OAuth state (CSRF + PKCE)
	CreateOAuthState(ctx context.Context, stateHash, codeVerifier, nonce, redirectURL, mode, userID string, expiresAt time.Time) (*OAuthState, error)
	GetOAuthStateByHash(ctx context.Context, stateHash string) (*OAuthState, error)
	DeleteOAuthState(ctx context.Context, id string) error
	ExpireOAuthStates(ctx context.Context, before time.Time) (int, error)

	// User creation without password (for OAuth registration)
	CreateOAuthUser(ctx context.Context, email, role string) (*User, error)
	// CreateOAuthUserAndAccount atomically creates a passwordless user and links an OAuth identity.
	CreateOAuthUserAndAccount(ctx context.Context, email, role, provider, providerUserID, oauthEmail, name, avatarURL string) (*User, *OAuthAccount, error)

	// Agents
	CreateAgent(ctx context.Context, name, createdBy, role string) (*Agent, error)
	GetAgentByID(ctx context.Context, id string) (*Agent, error)
	GetAgentByName(ctx context.Context, name string) (*Agent, error)
	ListAgents(ctx context.Context, vaultID string) ([]Agent, error)
	ListAllAgents(ctx context.Context) ([]Agent, error)
	RevokeAgent(ctx context.Context, id string) error
	RenameAgent(ctx context.Context, id string, newName string) error
	UpdateAgentRole(ctx context.Context, agentID, role string) error
	CountAgentTokens(ctx context.Context, agentID string) (int, error)
	GetLatestAgentTokenExpiry(ctx context.Context, agentID string) (*time.Time, error)
	DeleteAgentTokens(ctx context.Context, agentID string) error
	CreateAgentToken(ctx context.Context, agentID string, expiresAt *time.Time) (*Session, error)
	CountAllOwners(ctx context.Context) (int, error)

	// Instance settings
	GetSetting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
	GetAllSettings(ctx context.Context) (map[string]string, error)

	// Request logs
	InsertRequestLogs(ctx context.Context, rows []RequestLog) error
	ListRequestLogs(ctx context.Context, opts ListRequestLogsOpts) ([]RequestLog, error)
	DeleteOldRequestLogs(ctx context.Context, before time.Time) (int64, error)
	TrimRequestLogsToCap(ctx context.Context, vaultID string, cap int64) (int64, error)
	VaultIDsWithLogs(ctx context.Context) ([]string, error)

	// Lifecycle
	Close() error
}

// DefaultDBPath returns the default path for the SQLite database file (~/.agent-vault/agent-vault.db).
// It creates the ~/.agent-vault/ directory with 0700 permissions if it does not exist.
func DefaultDBPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".agent-vault")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "agent-vault.db"), nil
}
