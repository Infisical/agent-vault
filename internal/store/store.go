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

// VaultGrant represents a user's access to a vault with a specific role.
type VaultGrant struct {
	UserID    string
	VaultID   string
	Role      string // "admin" or "member"
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

// MasterKeyRecord holds the KDF salt and encrypted sentinel used to verify
// the master password on subsequent server startups.
type MasterKeyRecord struct {
	Salt       []byte
	Sentinel   []byte
	Nonce      []byte
	KDFTime    uint32
	KDFMemory  uint32
	KDFThreads uint8
	CreatedAt  time.Time
}

// Session represents an authenticated session.
// If VaultID is non-empty, the session is scoped to that vault.
type Session struct {
	ID        string
	UserID    string // non-empty for user login sessions, empty for agent sessions
	VaultID   string // empty = global (admin), non-empty = scoped to vault
	AgentID   string // non-empty for sessions minted by a persistent agent
	VaultRole string // "consumer", "member", or "admin" — set for scoped sessions (temp invite + agent)
	Label     string // optional label for direct-connect sessions
	ExpiresAt time.Time
	CreatedAt time.Time
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

// BrokerConfig holds the brokering rules for a vault.
type BrokerConfig struct {
	ID        string
	VaultID   string
	RulesJSON string // JSON-encoded []broker.Rule
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Proposal represents a proposed set of changes (rules + credential slots)
// created by an agent, pending human approval.
type Proposal struct {
	ID                     int // sequential per vault (1, 2, 3, ...)
	VaultID                string
	SessionID              string
	Status                 string
	RulesJSON              string
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

// Invite represents a one-time-use, time-limited token that an agent
// can redeem to receive a vault-scoped session.
type Invite struct {
	ID                int
	Token             string
	VaultID           string
	VaultRole         string     // "consumer", "member", or "admin"
	Status            string     // pending, redeemed, expired, revoked
	SessionID         string     // populated after redemption
	CreatedBy         string     // session ID of the creator
	Persistent        bool       // true for persistent agent invites (redeemed via POST)
	AgentName         string     // pre-set agent name (persistent invites only)
	AgentID           string     // set for rotation invites (references existing agent)
	SessionTTLSeconds int        // desired session lifetime when redeemed (0 = use default)
	SessionLabel      string     // label to attach to the session created on redemption
	CreatedAt         time.Time
	ExpiresAt         time.Time
	RedeemedAt        *time.Time
	RevokedAt         *time.Time
}

// Agent represents a named, persistent agent with a long-lived service token.
type Agent struct {
	ID                 string
	Name               string
	VaultID            string
	ServiceTokenHash   []byte
	ServiceTokenSalt   []byte
	ServiceTokenPrefix string // first 16 hex chars of the token, for lookup
	VaultRole          string // "consumer", "member", or "admin"
	Status             string // "active" or "revoked"
	CreatedBy          string // user ID of the creator
	CreatedAt          time.Time
	UpdatedAt          time.Time
	RevokedAt          *time.Time
}

// VaultInvite represents an invitation for a user to join a specific vault
// with a given role. If the user doesn't have an account, they create one
// during acceptance.
type VaultInvite struct {
	ID         int
	Token      string
	Email      string
	VaultID    string
	VaultRole  string // "admin" or "member"
	Status     string // pending, accepted, expired, revoked
	CreatedBy  string // user ID of the inviter
	CreatedAt  time.Time
	ExpiresAt  time.Time
	AcceptedAt *time.Time
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

	// Vault grants
	GrantVaultRole(ctx context.Context, userID, vaultID, role string) error
	RevokeVaultAccess(ctx context.Context, userID, vaultID string) error
	ListUserGrants(ctx context.Context, userID string) ([]VaultGrant, error)
	HasVaultAccess(ctx context.Context, userID, vaultID string) (bool, error)
	GetVaultRole(ctx context.Context, userID, vaultID string) (string, error)
	CountVaultAdmins(ctx context.Context, vaultID string) (int, error)
	ListVaultUsers(ctx context.Context, vaultID string) ([]VaultGrant, error)

	// User activation
	ActivateUser(ctx context.Context, userID string) error

	// Session cleanup
	DeleteUserSessions(ctx context.Context, userID string) error

	// Sessions
	CreateSession(ctx context.Context, userID string, expiresAt time.Time) (*Session, error)
	CreateScopedSession(ctx context.Context, vaultID, vaultRole, label string, expiresAt time.Time) (*Session, error)
	GetSession(ctx context.Context, id string) (*Session, error)
	DeleteSession(ctx context.Context, id string) error

	// Broker configs
	SetBrokerConfig(ctx context.Context, vaultID string, rulesJSON string) (*BrokerConfig, error)
	GetBrokerConfig(ctx context.Context, vaultID string) (*BrokerConfig, error)

	// Master key
	GetMasterKeyRecord(ctx context.Context) (*MasterKeyRecord, error)
	SetMasterKeyRecord(ctx context.Context, record *MasterKeyRecord) error

	// Proposals
	CreateProposal(ctx context.Context, vaultID, sessionID, rulesJSON, credentialsJSON, message, userMessage string, credentials map[string]EncryptedCredential) (*Proposal, error)
	GetProposal(ctx context.Context, vaultID string, id int) (*Proposal, error)
	GetProposalByApprovalToken(ctx context.Context, token string) (*Proposal, error)
	ListProposals(ctx context.Context, vaultID, status string) ([]Proposal, error)
	UpdateProposalStatus(ctx context.Context, vaultID string, id int, status, reviewNote string) error
	CountPendingProposals(ctx context.Context, vaultID string) (int, error)
	ExpirePendingProposals(ctx context.Context, before time.Time) (int, error)
	GetProposalCredentials(ctx context.Context, vaultID string, proposalID int) (map[string]EncryptedCredential, error)
	ApplyProposal(ctx context.Context, vaultID string, proposalID int, mergedRulesJSON string, credentials map[string]EncryptedCredential, deleteCredentialKeys []string) error

	// Invites
	CreateInvite(ctx context.Context, vaultID, vaultRole, createdBy string, expiresAt time.Time, sessionTTLSeconds int, sessionLabel string) (*Invite, error)
	GetInviteByToken(ctx context.Context, token string) (*Invite, error)
	ListInvites(ctx context.Context, vaultID, status string) ([]Invite, error)
	RedeemInvite(ctx context.Context, token, sessionID string) error
	RevokeInvite(ctx context.Context, token string) error
	CountPendingInvites(ctx context.Context, vaultID string) (int, error)
	ExpirePendingInvites(ctx context.Context, before time.Time) (int, error)

	// Vault invites
	CreateVaultInvite(ctx context.Context, email, vaultID, vaultRole, createdBy string, expiresAt time.Time) (*VaultInvite, error)
	GetVaultInviteByToken(ctx context.Context, token string) (*VaultInvite, error)
	GetPendingVaultInviteByEmailAndVault(ctx context.Context, email, vaultID string) (*VaultInvite, error)
	ListVaultInvites(ctx context.Context, vaultID, status string) ([]VaultInvite, error)
	AcceptVaultInvite(ctx context.Context, token string) error
	RevokeVaultInvite(ctx context.Context, token, vaultID string) error
	UpdateVaultInviteRole(ctx context.Context, token, vaultID, newRole string) error
	CountPendingVaultInvites(ctx context.Context, vaultID string) (int, error)

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
	CreateAgent(ctx context.Context, name, vaultID string, tokenHash, tokenSalt []byte, tokenPrefix, vaultRole, createdBy string) (*Agent, error)
	GetAgentByID(ctx context.Context, id string) (*Agent, error)
	GetAgentByName(ctx context.Context, name string) (*Agent, error)
	GetAgentByTokenPrefix(ctx context.Context, prefix string) (*Agent, error)
	ListAgents(ctx context.Context, vaultID string) ([]Agent, error)
	ListAllAgents(ctx context.Context) ([]Agent, error)
	RevokeAgent(ctx context.Context, id string) error
	UpdateAgentServiceToken(ctx context.Context, id string, tokenHash, tokenSalt []byte, tokenPrefix string) error
	UpdateAgentVaultRole(ctx context.Context, id, role string) error
	RenameAgent(ctx context.Context, id string, newName string) error
	CountAgentSessions(ctx context.Context, agentID string) (int, error)
	GetLatestAgentSessionExpiry(ctx context.Context, agentID string) (*time.Time, error)
	DeleteAgentSessions(ctx context.Context, agentID string) error
	CreateAgentSession(ctx context.Context, agentID, vaultID, vaultRole string, expiresAt time.Time) (*Session, error)
	CreatePersistentInvite(ctx context.Context, vaultID, vaultRole, createdBy string, agentName string, expiresAt time.Time) (*Invite, error)
	CreateRotationInvite(ctx context.Context, agentID, vaultID, createdBy string, expiresAt time.Time) (*Invite, error)

	// Instance settings
	GetSetting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
	GetAllSettings(ctx context.Context) (map[string]string, error)

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
