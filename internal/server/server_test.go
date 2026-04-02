package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/store"
)

// mockStore implements Store for testing.
type mockStore struct {
	masterKeyRecord    *store.MasterKeyRecord
	sessions           map[string]*store.Session
	vaults             map[string]*store.Vault
	credentials        map[string]*store.Credential             // keyed by "vaultID:key"
	brokerConfigs      map[string]*store.BrokerConfig       // keyed by vaultID
	proposals          map[string][]store.Proposal           // keyed by vaultID
	invites            map[string]*store.Invite              // keyed by token
	users              map[string]*store.User                // keyed by email
	grants             map[string]map[string]string          // keyed by userID -> vaultID -> role
	vaultInvites       map[string]*store.VaultInvite         // keyed by token
	emailVerifications []*store.EmailVerification
	passwordResets     []*store.PasswordReset
	agents             map[string]*store.Agent               // keyed by name
	settings           map[string]string                     // instance settings
	sessionCounter     int
}

func newMockStore() *mockStore {
	ms := &mockStore{
		sessions:      make(map[string]*store.Session),
		vaults:        make(map[string]*store.Vault),
		credentials:   make(map[string]*store.Credential),
		brokerConfigs: make(map[string]*store.BrokerConfig),
		invites:       make(map[string]*store.Invite),
		users:         make(map[string]*store.User),
		vaultInvites:  make(map[string]*store.VaultInvite),
		agents:        make(map[string]*store.Agent),
		settings:      make(map[string]string),
	}
	// Seed root vault
	ms.vaults["default"] = &store.Vault{ID: "root-ns-id", Name: "default"}
	return ms
}

func (m *mockStore) GetMasterKeyRecord(_ context.Context) (*store.MasterKeyRecord, error) {
	return m.masterKeyRecord, nil
}

func (m *mockStore) CreateUser(_ context.Context, email string, passwordHash, passwordSalt []byte, role string, kdfTime uint32, kdfMemory uint32, kdfThreads uint8) (*store.User, error) {
	u := &store.User{
		ID: "user-" + email, Email: email,
		PasswordHash: passwordHash, PasswordSalt: passwordSalt,
		KDFTime: kdfTime, KDFMemory: kdfMemory, KDFThreads: kdfThreads,
		Role: role, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	m.users[email] = u
	return u, nil
}

func (m *mockStore) RegisterFirstUser(_ context.Context, email string, passwordHash, passwordSalt []byte, defaultVaultID string, kdfTime uint32, kdfMemory uint32, kdfThreads uint8) (*store.User, error) {
	if len(m.users) > 0 {
		return nil, store.ErrNotFirstUser
	}
	u := &store.User{
		ID: "user-" + email, Email: email,
		PasswordHash: passwordHash, PasswordSalt: passwordSalt,
		KDFTime: kdfTime, KDFMemory: kdfMemory, KDFThreads: kdfThreads,
		Role: "owner", IsActive: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	m.users[email] = u
	if defaultVaultID != "" {
		if m.grants == nil {
			m.grants = make(map[string]map[string]string)
		}
		if m.grants[u.ID] == nil {
			m.grants[u.ID] = make(map[string]string)
		}
		m.grants[u.ID][defaultVaultID] = "admin"
	}
	return u, nil
}

func (m *mockStore) GetUserByEmail(_ context.Context, email string) (*store.User, error) {
	u, ok := m.users[email]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}
	return u, nil
}

func (m *mockStore) CountUsers(_ context.Context) (int, error) {
	return len(m.users), nil
}

func (m *mockStore) CreateSession(_ context.Context, userID string, expiresAt time.Time) (*store.Session, error) {
	m.sessionCounter++
	s := &store.Session{
		ID:        fmt.Sprintf("test-session-id-%d", m.sessionCounter),
		UserID:    userID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
	m.sessions[s.ID] = s
	return s, nil
}

func (m *mockStore) CreateScopedSession(_ context.Context, vaultID, vaultRole, label string, expiresAt time.Time) (*store.Session, error) {
	s := &store.Session{
		ID:        "scoped-session-id",
		VaultID:   vaultID,
		VaultRole: vaultRole,
		Label:     label,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
	m.sessions[s.ID] = s
	return s, nil
}

func (m *mockStore) GetSession(_ context.Context, id string) (*store.Session, error) {
	s, ok := m.sessions[id]
	if !ok {
		return nil, nil
	}
	return s, nil
}

func (m *mockStore) GetVault(_ context.Context, name string) (*store.Vault, error) {
	ns, ok := m.vaults[name]
	if !ok {
		return nil, nil
	}
	return ns, nil
}

func (m *mockStore) SetCredential(_ context.Context, vaultID, key string, ciphertext, nonce []byte) (*store.Credential, error) {
	s := &store.Credential{
		ID:          "credential-" + key,
		VaultID: vaultID,
		Key:         key,
		Ciphertext:  ciphertext,
		Nonce:       nonce,
	}
	m.credentials[vaultID+":"+key] = s
	return s, nil
}

func (m *mockStore) ListCredentials(_ context.Context, vaultID string) ([]store.Credential, error) {
	var creds []store.Credential
	for _, s := range m.credentials {
		if s.VaultID == vaultID {
			creds = append(creds, *s)
		}
	}
	return creds, nil
}

func (m *mockStore) DeleteCredential(_ context.Context, vaultID, key string) error {
	k := vaultID + ":" + key
	if _, ok := m.credentials[k]; !ok {
		return fmt.Errorf("credential not found")
	}
	delete(m.credentials, k)
	return nil
}

func (m *mockStore) GetVaultByID(_ context.Context, id string) (*store.Vault, error) {
	for _, ns := range m.vaults {
		if ns.ID == id {
			return ns, nil
		}
	}
	return nil, nil
}

func (m *mockStore) GetCredential(_ context.Context, vaultID, key string) (*store.Credential, error) {
	s, ok := m.credentials[vaultID+":"+key]
	if !ok {
		return nil, fmt.Errorf("credential not found")
	}
	return s, nil
}

func (m *mockStore) GetBrokerConfig(_ context.Context, vaultID string) (*store.BrokerConfig, error) {
	bc, ok := m.brokerConfigs[vaultID]
	if !ok {
		return nil, nil
	}
	return bc, nil
}

func (m *mockStore) CreateProposal(_ context.Context, vaultID, sessionID, rulesJSON, credentialsJSON, message, userMessage string, credentials map[string]store.EncryptedCredential) (*store.Proposal, error) {
	if m.proposals == nil {
		m.proposals = make(map[string][]store.Proposal)
	}
	existing := m.proposals[vaultID]
	nextID := len(existing) + 1
	cs := store.Proposal{
		ID:          nextID,
		VaultID: vaultID,
		SessionID:   sessionID,
		Status:      "pending",
		RulesJSON:   rulesJSON,
		CredentialsJSON: credentialsJSON,
		Message:     message,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	m.proposals[vaultID] = append(m.proposals[vaultID], cs)
	return &cs, nil
}

func (m *mockStore) GetProposal(_ context.Context, vaultID string, id int) (*store.Proposal, error) {
	for _, cs := range m.proposals[vaultID] {
		if cs.ID == id {
			return &cs, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

func (m *mockStore) ListProposals(_ context.Context, vaultID, status string) ([]store.Proposal, error) {
	var result []store.Proposal
	for _, cs := range m.proposals[vaultID] {
		if status == "" || cs.Status == status {
			result = append(result, cs)
		}
	}
	return result, nil
}

func (m *mockStore) CountPendingProposals(_ context.Context, vaultID string) (int, error) {
	count := 0
	for _, cs := range m.proposals[vaultID] {
		if cs.Status == "pending" {
			count++
		}
	}
	return count, nil
}

func (m *mockStore) UpdateProposalStatus(_ context.Context, vaultID string, id int, status, reviewNote string) error {
	css := m.proposals[vaultID]
	for i, cs := range css {
		if cs.ID == id {
			css[i].Status = status
			css[i].ReviewNote = reviewNote
			m.proposals[vaultID] = css
			return nil
		}
	}
	return fmt.Errorf("proposal %d not found", id)
}

func (m *mockStore) GetProposalCredentials(_ context.Context, vaultID string, proposalID int) (map[string]store.EncryptedCredential, error) {
	return map[string]store.EncryptedCredential{}, nil
}

func (m *mockStore) ApplyProposal(_ context.Context, vaultID string, proposalID int, mergedRulesJSON string, credentials map[string]store.EncryptedCredential, deleteCredentialKeys []string) error {
	// Update proposal status to applied.
	css := m.proposals[vaultID]
	for i, cs := range css {
		if cs.ID == proposalID {
			css[i].Status = "applied"
			m.proposals[vaultID] = css
			break
		}
	}
	// Update broker config.
	m.brokerConfigs[vaultID] = &store.BrokerConfig{
		VaultID: vaultID,
		RulesJSON:   mergedRulesJSON,
	}
	return nil
}

func (m *mockStore) ExpirePendingProposals(_ context.Context, before time.Time) (int, error) {
	return 0, nil
}

// --- Invite mocks ---

func (m *mockStore) CreateInvite(_ context.Context, vaultID, vaultRole, createdBy string, expiresAt time.Time, sessionTTLSeconds int, sessionLabel string) (*store.Invite, error) {
	inv := &store.Invite{
		ID: len(m.invites) + 1, Token: "av_inv_test" + fmt.Sprintf("%d", len(m.invites)),
		VaultID: vaultID, VaultRole: vaultRole, Status: "pending", CreatedBy: createdBy,
		SessionTTLSeconds: sessionTTLSeconds, SessionLabel: sessionLabel,
		CreatedAt: time.Now(), ExpiresAt: expiresAt,
	}
	m.invites[inv.Token] = inv
	return inv, nil
}

func (m *mockStore) GetInviteByToken(_ context.Context, token string) (*store.Invite, error) {
	inv, ok := m.invites[token]
	if !ok {
		return nil, nil
	}
	return inv, nil
}

func (m *mockStore) ListInvites(_ context.Context, vaultID, status string) ([]store.Invite, error) {
	var result []store.Invite
	for _, inv := range m.invites {
		if inv.VaultID == vaultID && (status == "" || inv.Status == status) {
			result = append(result, *inv)
		}
	}
	return result, nil
}

func (m *mockStore) RedeemInvite(_ context.Context, token, sessionID string) error {
	inv, ok := m.invites[token]
	if !ok {
		return fmt.Errorf("not found")
	}
	inv.Status = "redeemed"
	inv.SessionID = sessionID
	return nil
}

func (m *mockStore) RevokeInvite(_ context.Context, token string) error {
	inv, ok := m.invites[token]
	if !ok {
		return fmt.Errorf("not found")
	}
	inv.Status = "revoked"
	return nil
}

func (m *mockStore) CountPendingInvites(_ context.Context, vaultID string) (int, error) {
	count := 0
	for _, inv := range m.invites {
		if inv.VaultID == vaultID && inv.Status == "pending" {
			count++
		}
	}
	return count, nil
}

func (m *mockStore) Close() error { return nil }

// --- Multi-user permission model mocks ---

func (m *mockStore) GetUserByID(_ context.Context, id string) (*store.User, error) {
	for _, u := range m.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (m *mockStore) ListUsers(_ context.Context) ([]store.User, error) {
	var users []store.User
	for _, u := range m.users {
		users = append(users, *u)
	}
	return users, nil
}

func (m *mockStore) UpdateUserRole(_ context.Context, userID, role string) error {
	for _, u := range m.users {
		if u.ID == userID {
			u.Role = role
			return nil
		}
	}
	return fmt.Errorf("user not found")
}

func (m *mockStore) UpdateUserPassword(_ context.Context, userID string, passwordHash, passwordSalt []byte, kdfTime uint32, kdfMemory uint32, kdfThreads uint8) error {
	for _, u := range m.users {
		if u.ID == userID {
			u.PasswordHash = passwordHash
			u.PasswordSalt = passwordSalt
			u.KDFTime = kdfTime
			u.KDFMemory = kdfMemory
			u.KDFThreads = kdfThreads
			return nil
		}
	}
	return fmt.Errorf("user not found")
}

func (m *mockStore) DeleteUser(_ context.Context, userID string) error {
	for email, u := range m.users {
		if u.ID == userID {
			delete(m.users, email)
			return nil
		}
	}
	return fmt.Errorf("user not found")
}

func (m *mockStore) CountOwners(_ context.Context) (int, error) {
	count := 0
	for _, u := range m.users {
		if u.Role == "owner" {
			count++
		}
	}
	return count, nil
}

func (m *mockStore) DeleteUserSessions(_ context.Context, userID string) error {
	for id, sess := range m.sessions {
		if sess.UserID == userID {
			delete(m.sessions, id)
		}
	}
	return nil
}

func (m *mockStore) CreateVault(_ context.Context, name string) (*store.Vault, error) {
	if _, exists := m.vaults[name]; exists {
		return nil, fmt.Errorf("UNIQUE constraint failed")
	}
	ns := &store.Vault{
		ID:        "ns-" + name,
		Name:      name,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	m.vaults[name] = ns
	return ns, nil
}

func (m *mockStore) ListVaults(_ context.Context) ([]store.Vault, error) {
	var vaults []store.Vault
	for _, ns := range m.vaults {
		vaults = append(vaults, *ns)
	}
	return vaults, nil
}

func (m *mockStore) DeleteVault(_ context.Context, name string) error {
	if _, ok := m.vaults[name]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.vaults, name)
	return nil
}

func (m *mockStore) RenameVault(_ context.Context, oldName string, newName string) error {
	v, ok := m.vaults[oldName]
	if !ok {
		return fmt.Errorf("not found")
	}
	if _, exists := m.vaults[newName]; exists {
		return fmt.Errorf("duplicate name")
	}
	v.Name = newName
	delete(m.vaults, oldName)
	m.vaults[newName] = v
	return nil
}

func (m *mockStore) SetBrokerConfig(_ context.Context, vaultID, rulesJSON string) (*store.BrokerConfig, error) {
	bc := &store.BrokerConfig{
		ID:          "bc-" + vaultID,
		VaultID: vaultID,
		RulesJSON:   rulesJSON,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	m.brokerConfigs[vaultID] = bc
	return bc, nil
}

func (m *mockStore) ExpirePendingInvites(_ context.Context, before time.Time) (int, error) {
	return 0, nil
}


func (m *mockStore) GrantVaultRole(_ context.Context, userID, vaultID, role string) error {
	if m.grants == nil {
		m.grants = make(map[string]map[string]string)
	}
	if m.grants[userID] == nil {
		m.grants[userID] = make(map[string]string)
	}
	m.grants[userID][vaultID] = role
	return nil
}

func (m *mockStore) RevokeVaultAccess(_ context.Context, userID, vaultID string) error {
	if m.grants != nil && m.grants[userID] != nil {
		delete(m.grants[userID], vaultID)
		return nil
	}
	return fmt.Errorf("grant not found")
}

func (m *mockStore) ListUserGrants(_ context.Context, userID string) ([]store.VaultGrant, error) {
	var grants []store.VaultGrant
	if m.grants != nil && m.grants[userID] != nil {
		for nsID, role := range m.grants[userID] {
			grants = append(grants, store.VaultGrant{UserID: userID, VaultID: nsID, Role: role})
		}
	}
	return grants, nil
}

func (m *mockStore) HasVaultAccess(_ context.Context, userID, vaultID string) (bool, error) {
	if m.grants != nil && m.grants[userID] != nil {
		_, ok := m.grants[userID][vaultID]
		return ok, nil
	}
	return false, nil
}

func (m *mockStore) GetVaultRole(_ context.Context, userID, vaultID string) (string, error) {
	if m.grants != nil && m.grants[userID] != nil {
		if role, ok := m.grants[userID][vaultID]; ok {
			return role, nil
		}
	}
	return "", fmt.Errorf("no grant found")
}

func (m *mockStore) CountVaultAdmins(_ context.Context, vaultID string) (int, error) {
	count := 0
	for _, userGrants := range m.grants {
		if role, ok := userGrants[vaultID]; ok && role == "admin" {
			count++
		}
	}
	return count, nil
}

func (m *mockStore) ListVaultUsers(_ context.Context, vaultID string) ([]store.VaultGrant, error) {
	var result []store.VaultGrant
	for userID, userGrants := range m.grants {
		if role, ok := userGrants[vaultID]; ok {
			result = append(result, store.VaultGrant{UserID: userID, VaultID: vaultID, Role: role})
		}
	}
	return result, nil
}

func (m *mockStore) ActivateUser(_ context.Context, userID string) error {
	for _, u := range m.users {
		if u.ID == userID {
			u.IsActive = true
			return nil
		}
	}
	return fmt.Errorf("user not found")
}

func (m *mockStore) DeleteSession(_ context.Context, id string) error {
	delete(m.sessions, id)
	return nil
}

func (m *mockStore) SetMasterKeyRecord(_ context.Context, record *store.MasterKeyRecord) error {
	m.masterKeyRecord = record
	return nil
}

// --- Vault Invite mock methods ---

func (m *mockStore) CreateVaultInvite(_ context.Context, email, vaultID, vaultRole, createdBy string, expiresAt time.Time) (*store.VaultInvite, error) {
	token := "av_vinv_testtoken_" + email
	inv := &store.VaultInvite{
		ID:        len(m.vaultInvites) + 1,
		Token:     token,
		Email:     email,
		VaultID:   vaultID,
		VaultRole: vaultRole,
		Status:    "pending",
		CreatedBy: createdBy,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}
	m.vaultInvites[token] = inv
	return inv, nil
}

func (m *mockStore) GetVaultInviteByToken(_ context.Context, token string) (*store.VaultInvite, error) {
	inv, ok := m.vaultInvites[token]
	if !ok {
		return nil, fmt.Errorf("vault invite not found")
	}
	return inv, nil
}

func (m *mockStore) GetPendingVaultInviteByEmailAndVault(_ context.Context, email, vaultID string) (*store.VaultInvite, error) {
	for _, inv := range m.vaultInvites {
		if inv.Email == email && inv.VaultID == vaultID && inv.Status == "pending" && time.Now().Before(inv.ExpiresAt) {
			return inv, nil
		}
	}
	return nil, nil
}

func (m *mockStore) ListVaultInvites(_ context.Context, vaultID, status string) ([]store.VaultInvite, error) {
	var result []store.VaultInvite
	for _, inv := range m.vaultInvites {
		if inv.VaultID == vaultID && (status == "" || inv.Status == status) {
			result = append(result, *inv)
		}
	}
	return result, nil
}

func (m *mockStore) AcceptVaultInvite(_ context.Context, token string) error {
	inv, ok := m.vaultInvites[token]
	if !ok || inv.Status != "pending" {
		return fmt.Errorf("not found or not pending")
	}
	inv.Status = "accepted"
	now := time.Now()
	inv.AcceptedAt = &now
	return nil
}

func (m *mockStore) RevokeVaultInvite(_ context.Context, token, vaultID string) error {
	inv, ok := m.vaultInvites[token]
	if !ok || inv.Status != "pending" || inv.VaultID != vaultID {
		return fmt.Errorf("not found or not pending")
	}
	inv.Status = "revoked"
	return nil
}

func (m *mockStore) UpdateVaultInviteRole(_ context.Context, token, vaultID, newRole string) error {
	inv, ok := m.vaultInvites[token]
	if !ok || inv.Status != "pending" || inv.VaultID != vaultID {
		return fmt.Errorf("not found or not pending")
	}
	inv.VaultRole = newRole
	return nil
}

func (m *mockStore) CountPendingVaultInvites(_ context.Context, vaultID string) (int, error) {
	count := 0
	for _, inv := range m.vaultInvites {
		if inv.VaultID == vaultID && inv.Status == "pending" {
			count++
		}
	}
	return count, nil
}

// --- Email Verification mock methods ---

func (m *mockStore) CreateEmailVerification(_ context.Context, email, code string, expiresAt time.Time) (*store.EmailVerification, error) {
	ev := &store.EmailVerification{
		ID:        len(m.emailVerifications) + 1,
		Email:     email,
		Code:      code,
		Status:    "pending",
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}
	m.emailVerifications = append(m.emailVerifications, ev)
	return ev, nil
}

func (m *mockStore) GetPendingEmailVerification(_ context.Context, email, code string) (*store.EmailVerification, error) {
	for _, ev := range m.emailVerifications {
		if ev.Email == email && ev.Code == code && ev.Status == "pending" && time.Now().Before(ev.ExpiresAt) {
			return ev, nil
		}
	}
	return nil, nil
}

func (m *mockStore) MarkEmailVerificationUsed(_ context.Context, id int) error {
	for _, ev := range m.emailVerifications {
		if ev.ID == id {
			ev.Status = "verified"
			return nil
		}
	}
	return fmt.Errorf("not found")
}

func (m *mockStore) CountPendingEmailVerifications(_ context.Context, email string) (int, error) {
	count := 0
	for _, ev := range m.emailVerifications {
		if ev.Email == email && ev.Status == "pending" {
			count++
		}
	}
	return count, nil
}

func (m *mockStore) CreatePasswordReset(_ context.Context, email, code string, expiresAt time.Time) (*store.PasswordReset, error) {
	pr := &store.PasswordReset{
		ID:        len(m.passwordResets) + 1,
		Email:     email,
		Code:      code,
		Status:    "pending",
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}
	m.passwordResets = append(m.passwordResets, pr)
	return pr, nil
}

func (m *mockStore) GetPendingPasswordReset(_ context.Context, email, code string) (*store.PasswordReset, error) {
	for _, pr := range m.passwordResets {
		if pr.Email == email && pr.Code == code && pr.Status == "pending" && time.Now().Before(pr.ExpiresAt) {
			return pr, nil
		}
	}
	return nil, nil
}

func (m *mockStore) MarkPasswordResetUsed(_ context.Context, id int) error {
	for _, pr := range m.passwordResets {
		if pr.ID == id {
			pr.Status = "used"
			return nil
		}
	}
	return fmt.Errorf("not found")
}

func (m *mockStore) CountPendingPasswordResets(_ context.Context, email string) (int, error) {
	count := 0
	for _, pr := range m.passwordResets {
		if pr.Email == email && pr.Status == "pending" {
			count++
		}
	}
	return count, nil
}

func (m *mockStore) ExpirePendingPasswordResets(_ context.Context, before time.Time) (int, error) {
	count := 0
	for _, pr := range m.passwordResets {
		if pr.Status == "pending" && pr.ExpiresAt.Before(before) {
			pr.Status = "expired"
			count++
		}
	}
	return count, nil
}

func (m *mockStore) GetProposalByApprovalToken(_ context.Context, token string) (*store.Proposal, error) {
	return nil, nil
}

// --- Agent mock methods ---

func (m *mockStore) CreateAgent(_ context.Context, name, vaultID string, tokenHash, tokenSalt []byte, tokenPrefix, vaultRole, createdBy string) (*store.Agent, error) {
	ag := &store.Agent{
		ID:                 "agent-" + name,
		Name:               name,
		VaultID:            vaultID,
		ServiceTokenHash:   tokenHash,
		ServiceTokenSalt:   tokenSalt,
		ServiceTokenPrefix: tokenPrefix,
		VaultRole:          vaultRole,
		Status:             "active",
		CreatedBy:          createdBy,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	m.agents[name] = ag
	return ag, nil
}

func (m *mockStore) GetAgentByName(_ context.Context, name string) (*store.Agent, error) {
	ag, ok := m.agents[name]
	if !ok {
		return nil, fmt.Errorf("agent not found")
	}
	return ag, nil
}

func (m *mockStore) GetAgentByID(_ context.Context, id string) (*store.Agent, error) {
	for _, ag := range m.agents {
		if ag.ID == id {
			return ag, nil
		}
	}
	return nil, fmt.Errorf("agent not found")
}

func (m *mockStore) UpdateAgentVaultRole(_ context.Context, id, role string) error {
	for _, ag := range m.agents {
		if ag.ID == id {
			ag.VaultRole = role
			return nil
		}
	}
	return fmt.Errorf("agent not found")
}

func (m *mockStore) GetAgentByTokenPrefix(_ context.Context, prefix string) (*store.Agent, error) {
	for _, ag := range m.agents {
		if ag.ServiceTokenPrefix == prefix && ag.Status == "active" {
			return ag, nil
		}
	}
	return nil, fmt.Errorf("agent not found")
}

func (m *mockStore) ListAgents(_ context.Context, vaultID string) ([]store.Agent, error) {
	if vaultID == "" {
		return nil, fmt.Errorf("vaultID is required")
	}
	var result []store.Agent
	for _, ag := range m.agents {
		if ag.VaultID == vaultID {
			result = append(result, *ag)
		}
	}
	return result, nil
}

func (m *mockStore) ListAllAgents(_ context.Context) ([]store.Agent, error) {
	var result []store.Agent
	for _, ag := range m.agents {
		result = append(result, *ag)
	}
	return result, nil
}

func (m *mockStore) RevokeAgent(_ context.Context, id string) error {
	for _, ag := range m.agents {
		if ag.ID == id {
			ag.Status = "revoked"
			now := time.Now()
			ag.RevokedAt = &now
			// Cascade delete sessions
			for sid, sess := range m.sessions {
				if sess.AgentID == id {
					delete(m.sessions, sid)
				}
			}
			return nil
		}
	}
	return fmt.Errorf("agent not found")
}

func (m *mockStore) UpdateAgentServiceToken(_ context.Context, id string, tokenHash, tokenSalt []byte, tokenPrefix string) error {
	for _, ag := range m.agents {
		if ag.ID == id {
			ag.ServiceTokenHash = tokenHash
			ag.ServiceTokenSalt = tokenSalt
			ag.ServiceTokenPrefix = tokenPrefix
			return nil
		}
	}
	return fmt.Errorf("agent not found")
}

func (m *mockStore) RenameAgent(_ context.Context, id string, newName string) error {
	for name, ag := range m.agents {
		if ag.ID == id {
			ag.Name = newName
			delete(m.agents, name)
			m.agents[newName] = ag
			return nil
		}
	}
	return fmt.Errorf("agent not found")
}

func (m *mockStore) CountAgentSessions(_ context.Context, agentID string) (int, error) {
	count := 0
	for _, sess := range m.sessions {
		if sess.AgentID == agentID && time.Now().Before(sess.ExpiresAt) {
			count++
		}
	}
	return count, nil
}

func (m *mockStore) GetLatestAgentSessionExpiry(_ context.Context, agentID string) (*time.Time, error) {
	var latest *time.Time
	now := time.Now()
	for _, sess := range m.sessions {
		if sess.AgentID == agentID && sess.ExpiresAt.After(now) {
			t := sess.ExpiresAt
			if latest == nil || t.After(*latest) {
				latest = &t
			}
		}
	}
	return latest, nil
}

func (m *mockStore) DeleteAgentSessions(_ context.Context, agentID string) error {
	for id, sess := range m.sessions {
		if sess.AgentID == agentID {
			delete(m.sessions, id)
		}
	}
	return nil
}

func (m *mockStore) CreateAgentSession(_ context.Context, agentID, vaultID, vaultRole string, expiresAt time.Time) (*store.Session, error) {
	id := "agent-session-" + agentID + "-" + fmt.Sprintf("%d", len(m.sessions))
	s := &store.Session{
		ID:        id,
		VaultID:   vaultID,
		AgentID:   agentID,
		VaultRole: vaultRole,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
	m.sessions[s.ID] = s
	return s, nil
}

func (m *mockStore) CreatePersistentInvite(_ context.Context, vaultID, vaultRole, createdBy string, agentName string, expiresAt time.Time) (*store.Invite, error) {
	token := "av_inv_persistent_" + fmt.Sprintf("%d", len(m.invites))
	inv := &store.Invite{
		ID: len(m.invites) + 1, Token: token,
		VaultID: vaultID, VaultRole: vaultRole, Status: "pending", CreatedBy: createdBy,
		Persistent: true, AgentName: agentName,
		CreatedAt: time.Now(), ExpiresAt: expiresAt,
	}
	m.invites[token] = inv
	return inv, nil
}

func (m *mockStore) CreateRotationInvite(_ context.Context, agentID, vaultID, createdBy string, expiresAt time.Time) (*store.Invite, error) {
	token := "av_inv_rotation_" + fmt.Sprintf("%d", len(m.invites))
	inv := &store.Invite{
		ID: len(m.invites) + 1, Token: token,
		VaultID: vaultID, Status: "pending", CreatedBy: createdBy,
		Persistent: true, AgentID: agentID,
		CreatedAt: time.Now(), ExpiresAt: expiresAt,
	}
	m.invites[token] = inv
	return inv, nil
}

// --- OAuth mock methods (no-op stubs for interface compliance) ---

func (m *mockStore) CreateOAuthAccount(_ context.Context, userID, provider, providerUserID, email, name, avatarURL string) (*store.OAuthAccount, error) {
	return &store.OAuthAccount{
		ID: "oa-" + provider + "-" + providerUserID, UserID: userID,
		Provider: provider, ProviderUserID: providerUserID,
		Email: email, Name: name, AvatarURL: avatarURL,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}, nil
}

func (m *mockStore) GetOAuthAccount(_ context.Context, provider, providerUserID string) (*store.OAuthAccount, error) {
	return nil, nil
}

func (m *mockStore) GetOAuthAccountByUser(_ context.Context, userID, provider string) (*store.OAuthAccount, error) {
	return nil, nil
}

func (m *mockStore) ListUserOAuthAccounts(_ context.Context, userID string) ([]store.OAuthAccount, error) {
	return nil, nil
}

func (m *mockStore) DeleteOAuthAccount(_ context.Context, userID, provider string) error {
	return nil
}

func (m *mockStore) CreateOAuthState(_ context.Context, stateHash, codeVerifier, nonce, redirectURL, mode, userID string, expiresAt time.Time) (*store.OAuthState, error) {
	return &store.OAuthState{
		ID: "state-1", StateHash: stateHash, CodeVerifier: codeVerifier, Nonce: nonce,
		RedirectURL: redirectURL, Mode: mode, UserID: userID,
		CreatedAt: time.Now(), ExpiresAt: expiresAt,
	}, nil
}

func (m *mockStore) GetOAuthStateByHash(_ context.Context, stateHash string) (*store.OAuthState, error) {
	return nil, nil
}

func (m *mockStore) DeleteOAuthState(_ context.Context, id string) error {
	return nil
}

func (m *mockStore) ExpireOAuthStates(_ context.Context, before time.Time) (int, error) {
	return 0, nil
}

func (m *mockStore) CreateOAuthUser(_ context.Context, email, role string) (*store.User, error) {
	id := fmt.Sprintf("user-%d", len(m.users)+1)
	u := &store.User{ID: id, Email: email, Role: role, IsActive: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	m.users[email] = u
	return u, nil
}

func (m *mockStore) CreateOAuthUserAndAccount(_ context.Context, email, role, provider, providerUserID, oauthEmail, name, avatarURL string) (*store.User, *store.OAuthAccount, error) {
	u, err := m.CreateOAuthUser(context.Background(), email, role)
	if err != nil {
		return nil, nil, err
	}
	oa, err := m.CreateOAuthAccount(context.Background(), u.ID, provider, providerUserID, oauthEmail, name, avatarURL)
	if err != nil {
		return nil, nil, err
	}
	return u, oa, nil
}

// --- Instance settings mock methods ---

func (m *mockStore) GetSetting(_ context.Context, key string) (string, error) {
	if v, ok := m.settings[key]; ok {
		return v, nil
	}
	return "", sql.ErrNoRows
}

func (m *mockStore) SetSetting(_ context.Context, key, value string) error {
	m.settings[key] = value
	return nil
}

func (m *mockStore) GetAllSettings(_ context.Context) (map[string]string, error) {
	result := make(map[string]string)
	for k, v := range m.settings {
		result[k] = v
	}
	return result, nil
}

// testKDFParams returns fast KDF params suitable for tests.
func testKDFParams() crypto.KDFParams {
	return crypto.KDFParams{Time: 1, Memory: 64, Threads: 1, KeyLen: 32, SaltLen: 16}
}

// setupMockStoreWithPassword creates a mock store with a master key record
// derived from the given password using fast test KDF params.
func setupMockStoreWithPassword(t *testing.T, password string) *mockStore {
	t.Helper()
	ms := newMockStore()
	params := testKDFParams()
	salt, err := crypto.GenerateSalt(int(params.SaltLen))
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	key := crypto.DeriveKey([]byte(password), salt, params)
	sentinel := []byte("agent-vault-master-key-check")
	ciphertext, nonce, err := crypto.Encrypt(sentinel, key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ms.masterKeyRecord = &store.MasterKeyRecord{
		Salt:       salt,
		Sentinel:   ciphertext,
		Nonce:      nonce,
		KDFTime:    params.Time,
		KDFMemory:  params.Memory,
		KDFThreads: params.Threads,
	}
	return ms
}

func TestHealthEndpoint(t *testing.T) {
	srv := New("127.0.0.1:0", newMockStore(), make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("expected status ok, got %q", body["status"])
	}
}

func TestHealthEndpointRejectsPost(t *testing.T) {
	srv := New("127.0.0.1:0", newMockStore(), make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("expected non-200 status for POST /health")
	}
}

// setupMockStoreWithUser creates a mock store with a user account.
func setupMockStoreWithUser(t *testing.T, email, password string) *mockStore {
	t.Helper()
	ms := newMockStore()
	hash, salt, kdfP, err := auth.HashUserPassword([]byte(password))
	if err != nil {
		t.Fatalf("HashUserPassword: %v", err)
	}
	ms.users[email] = &store.User{
		ID: "user-id", Email: email,
		PasswordHash: hash, PasswordSalt: salt,
		KDFTime: kdfP.Time, KDFMemory: kdfP.Memory, KDFThreads: kdfP.Threads,
		Role: "owner", IsActive: true,
	}
	return ms
}

func TestLoginSuccess(t *testing.T) {
	ms := setupMockStoreWithUser(t, "admin@test.com", "test-password-123")
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"email":"admin@test.com","password":"test-password-123"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(body))
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp loginResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("expected non-empty token")
	}
	if resp.ExpiresAt == "" {
		t.Fatal("expected non-empty expires_at")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	ms := setupMockStoreWithUser(t, "admin@test.com", "correct-password-123")
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"email":"admin@test.com","password":"wrong-password-123"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(body))
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLoginEmptyFields(t *testing.T) {
	srv := New("127.0.0.1:0", newMockStore(), make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"email":"","password":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(body))
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestLoginUserNotFound(t *testing.T) {
	ms := newMockStore() // no users
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"email":"nobody@test.com","password":"some-password-123"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(body))
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// helper to create a mock store with a valid session and return (store, token).
func setupMockStoreWithSession(t *testing.T) (*mockStore, string) {
	t.Helper()
	ms := newMockStore()
	// Create an owner user and associate the session with it.
	ms.users["owner@test.com"] = &store.User{
		ID: "owner-user-id", Email: "owner@test.com",
		Role: "owner", IsActive: true,
	}
	// Grant owner access to the default vault.
	ms.GrantVaultRole(context.Background(), "owner-user-id", "root-ns-id", "admin")
	sess, err := ms.CreateSession(context.Background(), "owner-user-id", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return ms, sess.ID
}

func TestCredentialsSetSuccess(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	encKey := make([]byte, 32)
	srv := New("127.0.0.1:0", ms, encKey, nil, true, "http://127.0.0.1:14321", nil)

	body := `{"vault":"default","credentials":{"FOO":"bar","BAZ":"qux"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/credentials", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp credentialsSetResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Set) != 2 {
		t.Fatalf("expected 2 keys set, got %d", len(resp.Set))
	}
	// Verify credentials were stored
	if len(ms.credentials) != 2 {
		t.Fatalf("expected 2 credentials in store, got %d", len(ms.credentials))
	}
}

func TestCredentialsSetUnauthenticated(t *testing.T) {
	ms := newMockStore()
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"vault":"default","credentials":{"FOO":"bar"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/credentials", strings.NewReader(body))
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCredentialsSetInvalidVault(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"vault":"/nonexistent","credentials":{"FOO":"bar"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/credentials", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCredentialsDeleteSuccess(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	encKey := make([]byte, 32)
	srv := New("127.0.0.1:0", ms, encKey, nil, true, "http://127.0.0.1:14321", nil)

	// Pre-populate a credential
	ms.credentials["root-ns-id:FOO"] = &store.Credential{
		ID: "credential-FOO", VaultID: "root-ns-id", Key: "FOO",
	}

	body := `{"vault":"default","keys":["FOO"]}`
	req := httptest.NewRequest(http.MethodDelete, "/v1/credentials", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp credentialsDeleteResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Deleted) != 1 || resp.Deleted[0] != "FOO" {
		t.Fatalf("expected [FOO], got %v", resp.Deleted)
	}
	if len(ms.credentials) != 0 {
		t.Fatalf("expected 0 credentials in store, got %d", len(ms.credentials))
	}
}

func TestCredentialsDeleteUnauthenticated(t *testing.T) {
	ms := newMockStore()
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"vault":"default","keys":["FOO"]}`
	req := httptest.NewRequest(http.MethodDelete, "/v1/credentials", strings.NewReader(body))
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCredentialsDeleteNotFound(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"vault":"default","keys":["NONEXISTENT"]}`
	req := httptest.NewRequest(http.MethodDelete, "/v1/credentials", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- Scoped Sessions ---

func TestScopedSessionSuccess(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"vault":"default"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions/scoped", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp scopedSessionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("expected non-empty scoped token")
	}
	if resp.ExpiresAt == "" {
		t.Fatal("expected non-empty expires_at")
	}
	// Verify the scoped session was stored with vault_id
	scopedSess := ms.sessions[resp.Token]
	if scopedSess == nil {
		t.Fatal("scoped session not found in store")
	}
	if scopedSess.VaultID != "root-ns-id" {
		t.Fatalf("expected vault_id root-ns-id, got %q", scopedSess.VaultID)
	}
}

func TestScopedSessionVaultNotFound(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"vault":"nonexistent"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions/scoped", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestScopedSessionUnauthenticated(t *testing.T) {
	ms := newMockStore()
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"vault":"default"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions/scoped", strings.NewReader(body))
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- Vault Enforcement ---

func setupMockStoreWithScopedSession(t *testing.T, vaultName, vaultID string) (*mockStore, string) {
	return setupMockStoreWithScopedSessionRole(t, vaultName, vaultID, "consumer")
}

func setupMockStoreWithScopedSessionRole(t *testing.T, vaultName, vaultID, role string) (*mockStore, string) {
	t.Helper()
	ms := newMockStore()
	// Add a second vault
	if vaultName != "default" {
		ms.vaults[vaultName] = &store.Vault{ID: vaultID, Name: vaultName}
	}
	// Create a scoped session locked to the given vault
	sess, err := ms.CreateScopedSession(context.Background(), vaultID, role, "", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateScopedSession: %v", err)
	}
	return ms, sess.ID
}

func TestScopedSessionEnforcesVaultOnSet(t *testing.T) {
	// Create a scoped session for vault "proj" (not "default")
	ms, token := setupMockStoreWithScopedSession(t, "proj", "proj-ns-id")
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	// Try to set credentials in "default" vault with a token scoped to "proj"
	body := `{"vault":"default","credentials":{"FOO":"bar"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/credentials", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestScopedSessionAllowsOwnVaultOnSet(t *testing.T) {
	ms, token := setupMockStoreWithScopedSessionRole(t, "default", "root-ns-id", "member")
	encKey := make([]byte, 32)
	srv := New("127.0.0.1:0", ms, encKey, nil, true, "http://127.0.0.1:14321", nil)

	body := `{"vault":"default","credentials":{"FOO":"bar"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/credentials", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCredentialsListSuccess(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	// Pre-populate credentials
	ms.credentials["root-ns-id:FOO"] = &store.Credential{
		ID: "credential-FOO", VaultID: "root-ns-id", Key: "FOO",
	}
	ms.credentials["root-ns-id:BAR"] = &store.Credential{
		ID: "credential-BAR", VaultID: "root-ns-id", Key: "BAR",
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/credentials?vault=default", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp credentialsListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(resp.Keys))
	}
}

func TestCredentialsListEmpty(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/credentials?vault=default", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp credentialsListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Keys) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(resp.Keys))
	}
}

func TestCredentialsListUnauthenticated(t *testing.T) {
	ms := newMockStore()
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/credentials?vault=default", nil)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCredentialsListDefaultVault(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	// No vault query param — should default to "default"
	req := httptest.NewRequest(http.MethodGet, "/v1/credentials", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestScopedSessionEnforcesVaultOnList(t *testing.T) {
	ms, token := setupMockStoreWithScopedSession(t, "proj", "proj-ns-id")
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	// Try to list credentials in "default" with a token scoped to "proj"
	req := httptest.NewRequest(http.MethodGet, "/v1/credentials?vault=default", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestScopedSessionEnforcesVaultOnDelete(t *testing.T) {
	ms, token := setupMockStoreWithScopedSession(t, "proj", "proj-ns-id")
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	// Pre-populate a credential in the root vault
	ms.credentials["root-ns-id:FOO"] = &store.Credential{
		ID: "credential-FOO", VaultID: "root-ns-id", Key: "FOO",
	}

	body := `{"vault":"default","keys":["FOO"]}`
	req := httptest.NewRequest(http.MethodDelete, "/v1/credentials", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- Proxy Endpoint ---

// setupProxyTest creates a mock store with a scoped session, broker config, and
// encrypted credential. It returns the store, scoped token, and encryption key.
func setupProxyTest(t *testing.T, rulesJSON string) (*mockStore, string, []byte) {
	t.Helper()
	ms := newMockStore()
	encKey := make([]byte, 32)

	// Create a scoped session for root vault.
	sess, err := ms.CreateScopedSession(context.Background(), "root-ns-id", "consumer", "", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateScopedSession: %v", err)
	}

	// Set broker config.
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID:          "bc-1",
		VaultID: "root-ns-id",
		RulesJSON:   rulesJSON,
	}

	// Store an encrypted credential "STRIPE_KEY" = "sk_live_xxx".
	ct, nonce, err := crypto.Encrypt([]byte("sk_live_xxx"), encKey)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ms.credentials["root-ns-id:STRIPE_KEY"] = &store.Credential{
		ID: "credential-stripe", VaultID: "root-ns-id", Key: "STRIPE_KEY",
		Ciphertext: ct, Nonce: nonce,
	}

	return ms, sess.ID, encKey
}

func TestProxySuccess(t *testing.T) {
	// Start a fake upstream server.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer sk_live_xxx" {
			t.Errorf("expected injected auth header, got %q", got)
		}
		if r.URL.Path != "/v1/charges" {
			t.Errorf("expected path /v1/charges, got %s", r.URL.Path)
		}
		if r.URL.RawQuery != "limit=10" {
			t.Errorf("expected query limit=10, got %s", r.URL.RawQuery)
		}
		w.Header().Set("X-Upstream", "true")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "https://")
	ruleHost, _, _ := net.SplitHostPort(upstreamHost)
	rules := fmt.Sprintf(`[{"host":"%s","auth":{"type":"bearer","token":"STRIPE_KEY"}}]`, ruleHost)
	ms, token, encKey := setupProxyTest(t, rules)
	srv := New("127.0.0.1:0", ms, encKey, nil, true, "http://127.0.0.1:14321", nil)

	origClient := proxyClient
	proxyClient = upstream.Client()
	defer func() { proxyClient = origClient }()

	req := httptest.NewRequest(http.MethodPost, "/proxy/"+upstreamHost+"/v1/charges?limit=10",
		strings.NewReader("amount=2000"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Upstream") != "true" {
		t.Fatal("expected X-Upstream header from upstream")
	}
	body, _ := io.ReadAll(rec.Body)
	if string(body) != `{"ok":true}` {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestProxyNoMatchingRule(t *testing.T) {
	rules := `[{"host":"api.stripe.com","auth":{"type":"bearer","token":"STRIPE_KEY"}}]`
	ms, token, encKey := setupProxyTest(t, rules)
	srv := New("127.0.0.1:0", ms, encKey, nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodGet, "/proxy/evil.com/exfiltrate", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "forbidden" {
		t.Fatalf("expected error 'forbidden', got %q", resp["error"])
	}
	// Verify proposal_hint is present.
	hint, ok := resp["proposal_hint"].(map[string]interface{})
	if !ok {
		t.Fatal("expected proposal_hint in 403 response")
	}
	if hint["host"] != "evil.com" {
		t.Fatalf("expected proposal_hint host 'evil.com', got %q", hint["host"])
	}
	if hint["endpoint"] != "POST /v1/proposals" {
		t.Fatalf("expected proposal_hint endpoint, got %q", hint["endpoint"])
	}
}

func TestProxyMissingCredential(t *testing.T) {
	rules := `[{"host":"api.stripe.com","auth":{"type":"bearer","token":"nonexistent_key"}}]`
	ms, token, encKey := setupProxyTest(t, rules)
	srv := New("127.0.0.1:0", ms, encKey, nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodGet, "/proxy/api.stripe.com/v1/charges", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "credential_not_found" {
		t.Fatalf("expected error 'credential_not_found', got %q", resp["error"])
	}
}

func TestProxyUnauthenticated(t *testing.T) {
	ms := newMockStore()
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodGet, "/proxy/api.stripe.com/v1/charges", nil)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestProxyGlobalSessionForbidden(t *testing.T) {
	ms := newMockStore()
	sess, _ := ms.CreateSession(context.Background(), "", time.Now().Add(time.Hour))
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodGet, "/proxy/api.stripe.com/v1/charges", nil)
	req.Header.Set("Authorization", "Bearer "+sess.ID)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestProxyStripsAuthHeader(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if strings.Contains(auth, "scoped-session") {
			t.Errorf("agent session token leaked to upstream: %q", auth)
		}
		if auth != "Bearer sk_live_xxx" {
			t.Errorf("expected injected auth, got %q", auth)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "https://")
	ruleHost, _, _ := net.SplitHostPort(upstreamHost)
	rules := fmt.Sprintf(`[{"host":"%s","auth":{"type":"bearer","token":"STRIPE_KEY"}}]`, ruleHost)
	ms, token, encKey := setupProxyTest(t, rules)
	srv := New("127.0.0.1:0", ms, encKey, nil, true, "http://127.0.0.1:14321", nil)

	origClient := proxyClient
	proxyClient = upstream.Client()
	defer func() { proxyClient = origClient }()

	req := httptest.NewRequest(http.MethodGet, "/proxy/"+upstreamHost+"/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestProxyPreservesMethod(t *testing.T) {
	var receivedMethod string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "https://")
	ruleHost, _, _ := net.SplitHostPort(upstreamHost)
	rules := fmt.Sprintf(`[{"host":"%s","auth":{"type":"bearer","token":"STRIPE_KEY"}}]`, ruleHost)
	ms, token, encKey := setupProxyTest(t, rules)
	srv := New("127.0.0.1:0", ms, encKey, nil, true, "http://127.0.0.1:14321", nil)

	origClient := proxyClient
	proxyClient = upstream.Client()
	defer func() { proxyClient = origClient }()

	req := httptest.NewRequest(http.MethodDelete, "/proxy/"+upstreamHost+"/resource/42", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if receivedMethod != http.MethodDelete {
		t.Fatalf("expected DELETE, got %s", receivedMethod)
	}
}

func TestProxyHeaderMerge(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Custom"); got != "injected-value" {
			t.Errorf("expected injected header to win, got %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("expected agent header preserved, got %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "https://")
	ruleHost, _, _ := net.SplitHostPort(upstreamHost)
	rules := fmt.Sprintf(`[{"host":"%s","auth":{"type":"custom","headers":{"Authorization":"Bearer {{ STRIPE_KEY }}","X-Custom":"injected-value"}}}]`, ruleHost)
	ms, token, encKey := setupProxyTest(t, rules)
	srv := New("127.0.0.1:0", ms, encKey, nil, true, "http://127.0.0.1:14321", nil)

	origClient := proxyClient
	proxyClient = upstream.Client()
	defer func() { proxyClient = origClient }()

	req := httptest.NewRequest(http.MethodGet, "/proxy/"+upstreamHost+"/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Custom", "agent-value")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- Discovery endpoint tests ---

func TestDiscoverSuccess(t *testing.T) {
	desc := "GitHub API"
	rulesJSON := `[{"host":"*.github.com","description":"GitHub API","auth":{"type":"bearer","token":"GITHUB_TOKEN"}},{"host":"api.stripe.com","auth":{"type":"bearer","token":"STRIPE_KEY"}}]`
	ms, token, _ := setupProxyTest(t, rulesJSON)
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodGet, "/discover", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp discoverResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Vault != "default" {
		t.Fatalf("expected vault 'default', got %q", resp.Vault)
	}
	if !strings.HasSuffix(resp.ProxyURL, "/proxy") {
		t.Fatalf("expected proxy_url to end with /proxy, got %q", resp.ProxyURL)
	}
	if len(resp.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(resp.Services))
	}
	if resp.Services[0].Host != "*.github.com" {
		t.Fatalf("expected host '*.github.com', got %q", resp.Services[0].Host)
	}
	if resp.Services[0].Description == nil || *resp.Services[0].Description != desc {
		t.Fatalf("expected description %q, got %v", desc, resp.Services[0].Description)
	}
	// Second service has no description — should be null.
	if resp.Services[1].Host != "api.stripe.com" {
		t.Fatalf("expected host 'api.stripe.com', got %q", resp.Services[1].Host)
	}
	if resp.Services[1].Description != nil {
		t.Fatalf("expected nil description, got %q", *resp.Services[1].Description)
	}
	// setupProxyTest seeds "STRIPE_KEY" — verify it appears in available_credentials.
	if len(resp.AvailableCredentials) != 1 || resp.AvailableCredentials[0] != "STRIPE_KEY" {
		t.Fatalf("expected available_credentials [STRIPE_KEY], got %v", resp.AvailableCredentials)
	}
}

func TestDiscoverUnauthenticated(t *testing.T) {
	srv := New("127.0.0.1:0", newMockStore(), make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodGet, "/discover", nil)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestDiscoverGlobalSessionForbidden(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodGet, "/discover", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDiscoverEmptyRules(t *testing.T) {
	ms, token, _ := setupProxyTest(t, "[]")
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodGet, "/discover", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp discoverResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Services) != 0 {
		t.Fatalf("expected 0 services, got %d", len(resp.Services))
	}
	// setupProxyTest seeds "STRIPE_KEY" — still available even with empty rules.
	if len(resp.AvailableCredentials) != 1 || resp.AvailableCredentials[0] != "STRIPE_KEY" {
		t.Fatalf("expected available_credentials [STRIPE_KEY], got %v", resp.AvailableCredentials)
	}
}

func TestDiscoverNoCredentials(t *testing.T) {
	ms := newMockStore()
	sess, err := ms.CreateScopedSession(context.Background(), "root-ns-id", "consumer", "", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateScopedSession: %v", err)
	}
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id",
		RulesJSON: `[{"host":"example.com","auth":{"type":"custom","headers":{"X":"static"}}}]`,
	}

	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)
	req := httptest.NewRequest(http.MethodGet, "/discover", nil)
	req.Header.Set("Authorization", "Bearer "+sess.ID)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp discoverResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(resp.Services))
	}
	if resp.AvailableCredentials == nil || len(resp.AvailableCredentials) != 0 {
		t.Fatalf("expected empty available_credentials array, got %v", resp.AvailableCredentials)
	}
}

// --- Proposal endpoint tests ---

func setupProposalTest(t *testing.T) (*Server, *mockStore, string) {
	t.Helper()
	ms := newMockStore()
	ms.proposals = make(map[string][]store.Proposal)
	encKey := make([]byte, 32)
	srv := New("127.0.0.1:0", ms, encKey, nil, true, "http://127.0.0.1:14321", nil)

	// Create a scoped session for the root vault.
	sess := &store.Session{
		ID:          "scoped-cs-token",
		VaultID: "root-ns-id",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		CreatedAt:   time.Now(),
	}
	ms.sessions["scoped-cs-token"] = sess
	return srv, ms, "scoped-cs-token"
}

func TestProposalCreateSuccess(t *testing.T) {
	srv, _, token := setupProposalTest(t)

	body := `{
		"rules": [{"action": "set", "host": "api.stripe.com", "auth": {"type": "bearer", "token": "STRIPE_KEY"}}],
		"credentials": [{"action": "set", "key": "STRIPE_KEY", "description": "Stripe key"}],
		"message": "need stripe"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proposals", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["status"] != "pending" {
		t.Fatalf("expected status pending, got %v", resp["status"])
	}
	if resp["id"].(float64) != 1 {
		t.Fatalf("expected id 1, got %v", resp["id"])
	}
}

func TestProposalCreateRequiresScopedSession(t *testing.T) {
	ms := newMockStore()
	ms.proposals = make(map[string][]store.Proposal)
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	// Create a global (admin) session.
	sess := &store.Session{
		ID:        "admin-token",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
	}
	ms.sessions["admin-token"] = sess

	body := `{"rules": [{"action": "set", "host": "x.com", "auth": {"type": "custom", "headers": {"X": "v"}}}], "message": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proposals", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for global session, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestProposalCreateValidation(t *testing.T) {
	srv, _, token := setupProposalTest(t)

	// No rules or credentials.
	body := `{"rules": [], "message": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proposals", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestProposalGetSuccess(t *testing.T) {
	srv, _, token := setupProposalTest(t)

	// Create a proposal first.
	body := `{
		"rules": [{"action": "set", "host": "api.stripe.com", "auth": {"type": "bearer", "token": "SK"}}],
		"credentials": [{"action": "set", "key": "SK"}],
		"message": "test get"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proposals", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	// Now get it.
	req = httptest.NewRequest(http.MethodGet, "/v1/proposals/1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["message"] != "test get" {
		t.Fatalf("expected message 'test get', got %v", resp["message"])
	}
}

func TestProposalGetNotFound(t *testing.T) {
	srv, _, token := setupProposalTest(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/proposals/999", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestProposalListSuccess(t *testing.T) {
	srv, _, token := setupProposalTest(t)

	// Create two proposals.
	for _, msg := range []string{"first", "second"} {
		body := fmt.Sprintf(`{
			"rules": [{"action": "set", "host": "%s.com", "auth": {"type": "custom", "headers": {"X": "v"}}}],
			"message": "%s"
		}`, msg, msg)
		req := httptest.NewRequest(http.MethodPost, "/v1/proposals", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
	}

	// List all.
	req := httptest.NewRequest(http.MethodGet, "/v1/proposals", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	items := resp["proposals"].([]interface{})
	if len(items) != 2 {
		t.Fatalf("expected 2 proposals, got %d", len(items))
	}
}

func TestProposalCreateWithAgentCredential(t *testing.T) {
	srv, _, token := setupProposalTest(t)

	body := `{
		"rules": [{"action": "set", "host": "api.stripe.com", "auth": {"type": "bearer", "token": "SK"}}],
		"credentials": [{"action": "set", "key": "SK", "value": "sk_live_abc123", "description": "Stripe key"}],
		"message": "with credential value"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proposals", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestProposalCreateUnresolvedCredentialRef(t *testing.T) {
	srv, _, token := setupProposalTest(t)

	// Rule references {{ MISSING_KEY }} but no slot or existing credential provides it.
	body := `{
		"rules": [{"action": "set", "host": "api.stripe.com", "auth": {"type": "bearer", "token": "MISSING_KEY"}}],
		"credentials": [],
		"message": "should fail"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proposals", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "MISSING_KEY") {
		t.Fatalf("expected error mentioning MISSING_KEY, got: %s", rec.Body.String())
	}
}

func TestProposalCreateRefFromExistingCredential(t *testing.T) {
	srv, ms, token := setupProposalTest(t)

	// Seed an existing credential in the vault, no slot needed in the proposal.
	ms.credentials["root-ns-id:STRIPE_KEY"] = &store.Credential{
		ID: "s-1", VaultID: "root-ns-id", Key: "STRIPE_KEY",
		Ciphertext: []byte("ct"), Nonce: []byte("n"),
	}

	body := `{
		"rules": [{"action": "set", "host": "api.stripe.com", "auth": {"type": "bearer", "token": "STRIPE_KEY"}}],
		"credentials": [],
		"message": "uses existing credential"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proposals", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestProposalCreateWithDeleteAction(t *testing.T) {
	srv, _, token := setupProposalTest(t)

	body := `{
		"rules": [{"action": "delete", "host": "api.slack.com"}],
		"credentials": [{"action": "delete", "key": "SLACK_TOKEN"}],
		"message": "remove slack access"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proposals", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestProposalCreateMixedActions(t *testing.T) {
	srv, _, token := setupProposalTest(t)

	body := `{
		"rules": [
			{"action": "set", "host": "api.stripe.com", "auth": {"type": "bearer", "token": "SK"}},
			{"action": "delete", "host": "api.slack.com"}
		],
		"credentials": [
			{"action": "set", "key": "SK"},
			{"action": "delete", "key": "SLACK_TOKEN"}
		],
		"message": "add stripe, remove slack"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proposals", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- Invite handler tests ---

func setupInviteTest(t *testing.T) (*Server, *mockStore) {
	t.Helper()
	ms := setupMockStoreWithPassword(t, "test-pass")
	ms.vaults["default"] = &store.Vault{ID: "root-ns-id", Name: "default"}
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		RulesJSON: `[{"host":"api.stripe.com","description":"Stripe API","auth":{"type":"bearer","token":"SK"}}]`,
	}
	encKey := make([]byte, 32)
	srv := New(":0", ms, encKey, nil, true, "http://127.0.0.1:14321", nil)
	return srv, ms
}

// --- Admin Proposal Tests ---

func setupAdminProposalTest(t *testing.T) (*Server, *mockStore, string) {
	t.Helper()
	ms := newMockStore()

	// Create an owner user and admin session.
	ms.users["owner@test.com"] = &store.User{
		ID: "owner-user-id", Email: "owner@test.com", Role: "owner", IsActive: true,
	}
	ms.GrantVaultRole(context.Background(), "owner-user-id", "root-ns-id", "admin")
	adminSess := &store.Session{
		ID:        "admin-session",
		UserID:    "owner-user-id",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	ms.sessions[adminSess.ID] = adminSess

	encKey := make([]byte, 32)
	srv := New(":0", ms, encKey, nil, true, "http://127.0.0.1:14321", nil)

	// Seed a broker config and a pending proposal.
	ms.proposals = make(map[string][]store.Proposal)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		VaultID: "root-ns-id",
		RulesJSON:   `[]`,
	}
	ms.proposals["root-ns-id"] = []store.Proposal{
		{
			ID:          1,
			VaultID: "root-ns-id",
			Status:      "pending",
			RulesJSON:   `[{"action":"set","host":"api.example.com","auth":{"type":"bearer","token":"MY_KEY"}}]`,
			CredentialsJSON: `[{"action":"set","key":"MY_KEY","description":"Example key"}]`,
			Message:     "Add example API",
			CreatedAt:   time.Now(),
		},
	}

	return srv, ms, adminSess.ID
}

func TestAdminProposalApproveSuccess(t *testing.T) {
	srv, ms, token := setupAdminProposalTest(t)

	body := `{"vault":"default","credentials":{"MY_KEY":"credential_value"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/proposals/1/approve", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["status"] != "applied" {
		t.Fatalf("expected status applied, got %v", resp["status"])
	}

	// Verify proposal was applied.
	cs := ms.proposals["root-ns-id"][0]
	if cs.Status != "applied" {
		t.Fatalf("expected proposal status applied, got %s", cs.Status)
	}
}

func TestAdminProposalApproveRequiresAdminSession(t *testing.T) {
	srv, ms, _ := setupAdminProposalTest(t)

	// Create a scoped (non-admin) session.
	scopedSess := &store.Session{
		ID:          "scoped-session",
		VaultID: "root-ns-id",
		ExpiresAt:   time.Now().Add(time.Hour),
		CreatedAt:   time.Now(),
	}
	ms.sessions[scopedSess.ID] = scopedSess

	body := `{"vault":"default","credentials":{"MY_KEY":"credential_value"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/proposals/1/approve", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+scopedSess.ID)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminProposalApproveMissingCredential(t *testing.T) {
	srv, _, token := setupAdminProposalTest(t)

	// Don't provide the required "MY_KEY" credential.
	body := `{"vault":"default","credentials":{}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/proposals/1/approve", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminProposalApproveAlreadyApplied(t *testing.T) {
	srv, ms, token := setupAdminProposalTest(t)

	// Mark the proposal as already applied.
	ms.proposals["root-ns-id"][0].Status = "applied"

	body := `{"vault":"default","credentials":{"MY_KEY":"val"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/proposals/1/approve", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminProposalRejectSuccess(t *testing.T) {
	srv, ms, token := setupAdminProposalTest(t)

	body := `{"vault":"default","reason":"not needed"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/proposals/1/reject", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["status"] != "rejected" {
		t.Fatalf("expected status rejected, got %v", resp["status"])
	}

	cs := ms.proposals["root-ns-id"][0]
	if cs.Status != "rejected" {
		t.Fatalf("expected proposal status rejected, got %s", cs.Status)
	}
}

func TestAdminProposalRejectRequiresAdminSession(t *testing.T) {
	srv, ms, _ := setupAdminProposalTest(t)

	scopedSess := &store.Session{
		ID:          "scoped-session",
		VaultID: "root-ns-id",
		ExpiresAt:   time.Now().Add(time.Hour),
		CreatedAt:   time.Now(),
	}
	ms.sessions[scopedSess.ID] = scopedSess

	body := `{"vault":"default","reason":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/proposals/1/reject", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+scopedSess.ID)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleInviteRedeem(t *testing.T) {
	srv, ms := setupInviteTest(t)

	// Seed a valid invite.
	inv := &store.Invite{
		ID: 1, Token: "av_inv_validtoken1234567890abcdef",
		VaultID: "root-ns-id", Status: "pending",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	ms.invites[inv.Token] = inv

	req := httptest.NewRequest(http.MethodGet, "/invite/"+inv.Token, nil)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp inviteRedeemResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.SBSessionToken == "" {
		t.Fatal("expected non-empty session token")
	}
	if resp.SBVault != "default" {
		t.Fatalf("expected vault default, got %s", resp.SBVault)
	}
	if len(resp.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(resp.Services))
	}
	if resp.Instructions == "" {
		t.Fatal("expected non-empty instructions")
	}

	// Verify the invite is now redeemed.
	if inv.Status != "redeemed" {
		t.Fatalf("expected invite status redeemed, got %s", inv.Status)
	}
}

func TestHandleInviteRedeem_NotFound(t *testing.T) {
	srv, _ := setupInviteTest(t)

	req := httptest.NewRequest(http.MethodGet, "/invite/av_inv_nonexistent", nil)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestHandleInviteRedeem_Expired(t *testing.T) {
	srv, ms := setupInviteTest(t)

	inv := &store.Invite{
		ID: 1, Token: "av_inv_expiredtoken12345678abcdef",
		VaultID: "root-ns-id", Status: "pending",
		CreatedAt: time.Now().Add(-20 * time.Minute), ExpiresAt: time.Now().Add(-5 * time.Minute),
	}
	ms.invites[inv.Token] = inv

	req := httptest.NewRequest(http.MethodGet, "/invite/"+inv.Token, nil)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d: %s", rec.Code, rec.Body.String())
	}

	var body map[string]string
	json.NewDecoder(rec.Body).Decode(&body)
	if body["error"] != "invite_expired" {
		t.Fatalf("expected error code invite_expired, got %s", body["error"])
	}
}

func TestHandleInviteRedeem_AlreadyRedeemed(t *testing.T) {
	srv, ms := setupInviteTest(t)

	inv := &store.Invite{
		ID: 1, Token: "av_inv_redeemedtoken123456abcdef",
		VaultID: "root-ns-id", Status: "redeemed",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	ms.invites[inv.Token] = inv

	req := httptest.NewRequest(http.MethodGet, "/invite/"+inv.Token, nil)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d", rec.Code)
	}

	var body map[string]string
	json.NewDecoder(rec.Body).Decode(&body)
	if body["error"] != "invite_redeemed" {
		t.Fatalf("expected error code invite_redeemed, got %s", body["error"])
	}
}

func TestHandleInviteRedeem_Revoked(t *testing.T) {
	srv, ms := setupInviteTest(t)

	inv := &store.Invite{
		ID: 1, Token: "av_inv_revokedtoken1234567abcdef",
		VaultID: "root-ns-id", Status: "revoked",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	ms.invites[inv.Token] = inv

	req := httptest.NewRequest(http.MethodGet, "/invite/"+inv.Token, nil)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d", rec.Code)
	}

	var body map[string]string
	json.NewDecoder(rec.Body).Decode(&body)
	if body["error"] != "invite_revoked" {
		t.Fatalf("expected error code invite_revoked, got %s", body["error"])
	}
}

// --- Multi-User Permission Model Tests ---

// setupMemberSession creates a member user with a login session and optional vault grants.
func setupMemberSession(t *testing.T, ms *mockStore, grantVaultIDs ...string) string {
	t.Helper()
	ms.users["member@test.com"] = &store.User{
		ID: "member-user-id", Email: "member@test.com", Role: "member", IsActive: true,
	}
	memberSess := &store.Session{
		ID:        "member-session",
		UserID:    "member-user-id",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	ms.sessions[memberSess.ID] = memberSess

	for _, nsID := range grantVaultIDs {
		ms.GrantVaultRole(context.Background(), "member-user-id", nsID, "member")
	}
	return memberSess.ID
}

func TestMemberCanAccessGrantedVault(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	memberToken := setupMemberSession(t, ms, "root-ns-id")
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/credentials?vault=default", nil)
	req.Header.Set("Authorization", "Bearer "+memberToken)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMemberCannotAccessNonGrantedVault(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	// Create member without grants
	memberToken := setupMemberSession(t, ms)
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/credentials?vault=default", nil)
	req.Header.Set("Authorization", "Bearer "+memberToken)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestOwnerCannotAccessVaultWithoutGrant(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	// Add a second vault — owner should NOT access without explicit grant.
	ms.vaults["prod"] = &store.Vault{ID: "prod-ns-id", Name: "prod"}
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/credentials?vault=prod", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestVaultCreateSlugValidation(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	tests := []struct {
		name       string
		vaultName  string
		wantStatus int
	}{
		{"valid slug", "my-vault", http.StatusCreated},
		{"uppercase rejected", "My-Vault", http.StatusBadRequest},
		{"spaces rejected", "my vault", http.StatusBadRequest},
		{"too short", "ab", http.StatusBadRequest},
		{"underscores rejected", "my_vault", http.StatusBadRequest},
		{"valid numeric", "vault-123", http.StatusCreated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"name":%q}`, tt.vaultName)
			req := httptest.NewRequest(http.MethodPost, "/v1/vaults", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+ownerToken)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("vault name %q: expected %d, got %d: %s", tt.vaultName, tt.wantStatus, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestMemberCanApproveProposalInAnyMemberVault(t *testing.T) {
	ms := newMockStore()
	ms.users["owner@test.com"] = &store.User{ID: "owner-user-id", Email: "owner@test.com", Role: "owner", IsActive: true}
	memberToken := setupMemberSession(t, ms, "root-ns-id")

	encKey := make([]byte, 32)
	srv := New(":0", ms, encKey, nil, true, "http://127.0.0.1:14321", nil)

	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{VaultID: "root-ns-id", RulesJSON: `[]`}
	ms.proposals = map[string][]store.Proposal{
		"root-ns-id": {{
			ID: 1, VaultID: "root-ns-id", Status: "pending",
			RulesJSON: `[]`, CredentialsJSON: `[]`,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}},
	}

	body := `{"vault":"default","credentials":{}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/proposals/1/approve", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+memberToken)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUserCreateRequiresOwner(t *testing.T) {
	ms := newMockStore()
	memberToken := setupMemberSession(t, ms, "root-ns-id")
	srv := New(":0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"email":"new@test.com","password":"password12345","vaults":[]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/users", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+memberToken)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUserCreateSuccess(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := New(":0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"email":"new@test.com","password":"password12345","vaults":["default"]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/users", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["email"] != "new@test.com" {
		t.Fatalf("expected email new@test.com, got %v", resp["email"])
	}
	if resp["role"] != "member" {
		t.Fatalf("expected role member, got %v", resp["role"])
	}
}

func TestLastOwnerCannotBeDemoted(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := New(":0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"role":"member"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/users/owner@test.com/role", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLastOwnerCannotBeRemoved(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := New(":0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodDelete, "/v1/admin/users/owner@test.com", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}


func TestEmailTestRequiresOwner(t *testing.T) {
	ms, agentToken := setupMockStoreWithScopedSession(t, "default", "root-ns-id")
	srv := New(":0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/email/test", nil)
	req.Header.Set("Authorization", "Bearer "+agentToken)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestEmailTestMemberForbidden(t *testing.T) {
	ms := newMockStore()
	memberToken := setupMemberSession(t, ms, "root-ns-id")
	srv := New(":0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/email/test", nil)
	req.Header.Set("Authorization", "Bearer "+memberToken)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestEmailTestSMTPNotConfigured(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	// nil notifier = SMTP not configured
	srv := New(":0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/email/test", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "SMTP is not configured" {
		t.Fatalf("unexpected error: %s", resp["error"])
	}
}

func TestEmailTestSMTPFailure(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	// Create a notifier with an unreachable SMTP host to trigger a send failure.
	notifier := notify.New(&notify.SMTPConfig{
		Host: "127.0.0.1",
		Port: 1, // unreachable port
		From: "test@example.com",
	})
	srv := New(":0", ms, make([]byte, 32), notifier, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/email/test", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- User Invite Tests (removed — old user invite system replaced by vault invites) ---

// --- Persistent Agent Identity Tests ---

func setupAgentTest(t *testing.T) (*Server, *mockStore, string) {
	t.Helper()
	ms := newMockStore()
	ms.users["owner@test.com"] = &store.User{
		ID: "owner-user-id", Email: "owner@test.com", Role: "owner", IsActive: true,
	}
	ms.GrantVaultRole(context.Background(), "owner-user-id", "root-ns-id", "admin")
	adminSess := &store.Session{
		ID: "admin-session", UserID: "owner-user-id",
		ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
	}
	ms.sessions[adminSess.ID] = adminSess
	encKey := make([]byte, 32)
	srv := New(":0", ms, encKey, nil, true, "http://127.0.0.1:14321", nil)
	return srv, ms, adminSess.ID
}

func TestPersistentInviteRedeemGET405(t *testing.T) {
	srv, ms := setupInviteTest(t)

	inv := &store.Invite{
		ID: 1, Token: "av_inv_persistent_test",
		VaultID: "root-ns-id", Status: "pending", Persistent: true,
		AgentName: "testbot",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	ms.invites[inv.Token] = inv

	req := httptest.NewRequest(http.MethodGet, "/invite/"+inv.Token, nil)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET on persistent invite, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPersistentInviteRedeemPOST(t *testing.T) {
	srv, ms := setupInviteTest(t)

	inv := &store.Invite{
		ID: 1, Token: "av_inv_persistent_post",
		VaultID: "root-ns-id", Status: "pending", Persistent: true,
		AgentName: "mybot", CreatedBy: "owner-user-id",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	ms.invites[inv.Token] = inv

	body := strings.NewReader(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/invite/"+inv.Token, body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp["av_agent_token"] == nil || resp["av_agent_token"].(string) == "" {
		t.Fatal("expected non-empty av_agent_token")
	}
	if resp["agent_name"] != "mybot" {
		t.Fatalf("expected agent_name mybot, got %v", resp["agent_name"])
	}
	if resp["av_session_token"] == nil || resp["av_session_token"].(string) == "" {
		t.Fatal("expected non-empty av_session_token")
	}

	// Verify agent was created.
	ag, err := ms.GetAgentByName(context.Background(), "mybot")
	if err != nil {
		t.Fatalf("expected agent to be created: %v", err)
	}
	if ag.Status != "active" {
		t.Fatalf("expected active, got %s", ag.Status)
	}

	// Verify invite was redeemed.
	if inv.Status != "redeemed" {
		t.Fatalf("expected invite redeemed, got %s", inv.Status)
	}
}

func TestPersistentInviteRedeemPOST_NameFromBody(t *testing.T) {
	srv, ms := setupInviteTest(t)

	inv := &store.Invite{
		ID: 1, Token: "av_inv_persistent_nobody",
		VaultID: "root-ns-id", Status: "pending", Persistent: true,
		CreatedBy: "owner-user-id",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	ms.invites[inv.Token] = inv

	body := strings.NewReader(`{"name": "bodybot"}`)
	req := httptest.NewRequest(http.MethodPost, "/invite/"+inv.Token, body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["agent_name"] != "bodybot" {
		t.Fatalf("expected agent_name bodybot, got %v", resp["agent_name"])
	}
}

func TestPersistentInviteRedeemPOST_NoName400(t *testing.T) {
	srv, ms := setupInviteTest(t)

	inv := &store.Invite{
		ID: 1, Token: "av_inv_persistent_noname",
		VaultID: "root-ns-id", Status: "pending", Persistent: true,
		CreatedBy: "owner-user-id",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	ms.invites[inv.Token] = inv

	body := strings.NewReader(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/invite/"+inv.Token, body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing name, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTemporaryInvitePOST400(t *testing.T) {
	srv, ms := setupInviteTest(t)

	inv := &store.Invite{
		ID: 1, Token: "av_inv_temp_post",
		VaultID: "root-ns-id", Status: "pending", Persistent: false,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	ms.invites[inv.Token] = inv

	body := strings.NewReader(`{"name": "bot"}`)
	req := httptest.NewRequest(http.MethodPost, "/invite/"+inv.Token, body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for POST on temporary invite, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDuplicateAgentName409(t *testing.T) {
	srv, ms := setupInviteTest(t)

	// Pre-create an agent.
	ms.agents["existing"] = &store.Agent{
		ID: "agent-existing", Name: "existing", VaultID: "root-ns-id", Status: "active",
	}

	inv := &store.Invite{
		ID: 1, Token: "av_inv_dup_name",
		VaultID: "root-ns-id", Status: "pending", Persistent: true,
		AgentName: "existing", CreatedBy: "owner-user-id",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	ms.invites[inv.Token] = inv

	body := strings.NewReader(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/invite/"+inv.Token, body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate name, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAgentSessionMint(t *testing.T) {
	srv, ms := setupInviteTest(t)

	// Create an agent with known token hash.
	token := "av_agent_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	hash, salt, _, _ := auth.HashUserPassword([]byte(token))
	prefix := token[len("av_agent_"):][:16]

	ms.agents["mintbot"] = &store.Agent{
		ID: "agent-mintbot", Name: "mintbot", VaultID: "root-ns-id",
		ServiceTokenHash: hash, ServiceTokenSalt: salt, ServiceTokenPrefix: prefix,
		Status: "active",
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/agent/session", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp["av_session_token"] == nil || resp["av_session_token"].(string) == "" {
		t.Fatal("expected non-empty session token")
	}
	if resp["av_vault"] != "default" {
		t.Fatalf("expected vault default, got %v", resp["av_vault"])
	}
}

func TestAgentSessionMint_InvalidToken(t *testing.T) {
	srv, _ := setupInviteTest(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/agent/session", nil)
	req.Header.Set("Authorization", "Bearer av_agent_badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAgentSessionMint_NoBearer(t *testing.T) {
	srv, _ := setupInviteTest(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/agent/session", nil)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAgentList(t *testing.T) {
	srv, ms, sessID := setupAgentTest(t)

	ms.agents["bot1"] = &store.Agent{ID: "a1", Name: "bot1", VaultID: "root-ns-id", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	ms.agents["bot2"] = &store.Agent{ID: "a2", Name: "bot2", VaultID: "root-ns-id", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/agents", nil)
	req.Header.Set("Authorization", "Bearer "+sessID)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	agents := resp["agents"].([]interface{})
	if len(agents) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(agents))
	}
}

func TestAgentRevoke(t *testing.T) {
	srv, ms, sessID := setupAgentTest(t)

	ms.agents["revokebot"] = &store.Agent{ID: "a1", Name: "revokebot", VaultID: "root-ns-id", Status: "active"}

	req := httptest.NewRequest(http.MethodDelete, "/v1/admin/agents/revokebot", nil)
	req.Header.Set("Authorization", "Bearer "+sessID)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	ag := ms.agents["revokebot"]
	if ag.Status != "revoked" {
		t.Fatalf("expected revoked, got %s", ag.Status)
	}
}

func TestAgentRotate(t *testing.T) {
	srv, ms, sessID := setupAgentTest(t)

	ms.agents["rotatebot"] = &store.Agent{ID: "a1", Name: "rotatebot", VaultID: "root-ns-id", Status: "active"}

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/agents/rotatebot/rotate", nil)
	req.Header.Set("Authorization", "Bearer "+sessID)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["invite_url"] == nil || resp["invite_url"].(string) == "" {
		t.Fatal("expected non-empty invite_url")
	}
	if resp["prompt"] == nil || resp["prompt"].(string) == "" {
		t.Fatal("expected non-empty prompt")
	}
}

func TestAgentRename(t *testing.T) {
	srv, ms, sessID := setupAgentTest(t)

	ms.agents["oldbot"] = &store.Agent{ID: "a1", Name: "oldbot", VaultID: "root-ns-id", Status: "active"}

	body := strings.NewReader(`{"name": "newbot"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/agents/oldbot/rename", body)
	req.Header.Set("Authorization", "Bearer "+sessID)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify rename.
	_, err := ms.GetAgentByName(context.Background(), "newbot")
	if err != nil {
		t.Fatal("expected agent to be renamed to newbot")
	}
	_, err = ms.GetAgentByName(context.Background(), "oldbot")
	if err == nil {
		t.Fatal("expected oldbot to not exist after rename")
	}
}

func TestVaultRename(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := New(":0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	// Create a non-default vault to rename.
	ms.vaults["oldvault"] = &store.Vault{ID: "old-vault-id", Name: "oldvault"}
	ms.GrantVaultRole(context.Background(), "owner-user-id", "old-vault-id", "admin")

	t.Run("success", func(t *testing.T) {
		body := strings.NewReader(`{"name": "newvault"}`)
		req := httptest.NewRequest(http.MethodPost, "/v1/vaults/oldvault/rename", body)
		req.Header.Set("Authorization", "Bearer "+ownerToken)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}

		if _, ok := ms.vaults["newvault"]; !ok {
			t.Fatal("expected vault to be renamed to newvault")
		}
		if _, ok := ms.vaults["oldvault"]; ok {
			t.Fatal("expected oldvault to not exist after rename")
		}
	})

	t.Run("cannot rename default vault", func(t *testing.T) {
		body := strings.NewReader(`{"name": "other"}`)
		req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/rename", body)
		req.Header.Set("Authorization", "Bearer "+ownerToken)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("invalid slug rejected", func(t *testing.T) {
		ms.vaults["testvault"] = &store.Vault{ID: "tv-id", Name: "testvault"}
		body := strings.NewReader(`{"name": "Bad Name"}`)
		req := httptest.NewRequest(http.MethodPost, "/v1/vaults/testvault/rename", body)
		req.Header.Set("Authorization", "Bearer "+ownerToken)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestUserGetMe(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := New(":0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["email"] != "owner@test.com" {
		t.Fatalf("expected owner@test.com, got %v", resp["email"])
	}
	if resp["role"] != "owner" {
		t.Fatalf("expected owner role, got %v", resp["role"])
	}
}

// --- Change Password Tests ---

// loginAndGetToken is a helper that logs in and returns the session token.
func loginAndGetToken(t *testing.T, srv *Server, email, password string) string {
	t.Helper()
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Body.String())
	}
	var resp loginResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	return resp.Token
}

func TestChangePasswordSuccess(t *testing.T) {
	ms := setupMockStoreWithUser(t, "admin@test.com", "old-password-123")
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	token := loginAndGetToken(t, srv, "admin@test.com", "old-password-123")

	// Change password
	body := `{"current_password":"old-password-123","new_password":"new-password-456"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/change-password", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify response contains a new session token
	var resp loginResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Token == "" {
		t.Fatal("expected non-empty token in response")
	}

	// Old token should be invalidated — verify by trying /v1/auth/me
	meReq := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+token)
	meRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(meRec, meReq)
	if meRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected old token to be invalidated, got %d", meRec.Code)
	}

	// Login with new password should succeed
	newToken := loginAndGetToken(t, srv, "admin@test.com", "new-password-456")
	if newToken == "" {
		t.Fatal("login with new password failed")
	}
}

func TestChangePasswordWrongCurrent(t *testing.T) {
	ms := setupMockStoreWithUser(t, "admin@test.com", "correct-password-123")
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	token := loginAndGetToken(t, srv, "admin@test.com", "correct-password-123")

	body := `{"current_password":"wrong-password","new_password":"new-password-456"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/change-password", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestChangePasswordTooShort(t *testing.T) {
	ms := setupMockStoreWithUser(t, "admin@test.com", "old-password-123")
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	token := loginAndGetToken(t, srv, "admin@test.com", "old-password-123")

	body := `{"current_password":"old-password-123","new_password":"short"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/change-password", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestChangePasswordNoAuth(t *testing.T) {
	srv := New("127.0.0.1:0", newMockStore(), make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"current_password":"old","new_password":"new-password-456"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/change-password", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteAccountMemberSuccess(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	memberToken := setupMemberSession(t, ms, "root-ns-id")
	srv := New(":0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodDelete, "/v1/auth/account", nil)
	req.Header.Set("Authorization", "Bearer "+memberToken)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify user is gone.
	if _, ok := ms.users["member@test.com"]; ok {
		t.Fatal("expected member user to be deleted")
	}
}

func TestDeleteAccountOwnerBlocked(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := New(":0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodDelete, "/v1/auth/account", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteAccountNoAuth(t *testing.T) {
	srv := New("127.0.0.1:0", newMockStore(), make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodDelete, "/v1/auth/account", nil)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestForgotPasswordSuccess(t *testing.T) {
	ms := setupMockStoreWithUser(t, "admin@test.com", "old-password-123")
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"email":"admin@test.com"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/forgot-password", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["message"] == nil {
		t.Fatal("expected message in response")
	}

	// Verify a password reset was created in the store.
	if len(ms.passwordResets) != 1 {
		t.Fatalf("expected 1 password reset, got %d", len(ms.passwordResets))
	}
}

func TestForgotPasswordUnknownEmail(t *testing.T) {
	ms := setupMockStoreWithUser(t, "admin@test.com", "old-password-123")
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	// Request reset for unknown email — should return 200 (uniform response).
	body := `{"email":"unknown@test.com"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/forgot-password", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// No password reset should have been created.
	if len(ms.passwordResets) != 0 {
		t.Fatalf("expected 0 password resets, got %d", len(ms.passwordResets))
	}
}

func TestForgotPasswordEmptyEmail(t *testing.T) {
	srv := New("127.0.0.1:0", newMockStore(), make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"email":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/forgot-password", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestResetPasswordSuccess(t *testing.T) {
	ms := setupMockStoreWithUser(t, "admin@test.com", "old-password-123")
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	// First request a reset code.
	forgotBody := `{"email":"admin@test.com"}`
	forgotReq := httptest.NewRequest(http.MethodPost, "/v1/auth/forgot-password", strings.NewReader(forgotBody))
	forgotRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(forgotRec, forgotReq)
	if forgotRec.Code != http.StatusOK {
		t.Fatalf("forgot-password: expected 200, got %d", forgotRec.Code)
	}

	// Get the code from the mock store.
	if len(ms.passwordResets) == 0 {
		t.Fatal("no password reset created")
	}
	code := ms.passwordResets[0].Code

	// Reset password.
	resetBody := fmt.Sprintf(`{"email":"admin@test.com","code":"%s","new_password":"new-password-456"}`, code)
	resetReq := httptest.NewRequest(http.MethodPost, "/v1/auth/reset-password", strings.NewReader(resetBody))
	resetRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(resetRec, resetReq)

	if resetRec.Code != http.StatusOK {
		t.Fatalf("reset-password: expected 200, got %d: %s", resetRec.Code, resetRec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(resetRec.Body).Decode(&resp)
	if resp["authenticated"] != true {
		t.Fatalf("expected authenticated=true, got %v", resp["authenticated"])
	}

	// Login with new password should succeed.
	newToken := loginAndGetToken(t, srv, "admin@test.com", "new-password-456")
	if newToken == "" {
		t.Fatal("login with new password failed")
	}
}

func TestResetPasswordWrongCode(t *testing.T) {
	ms := setupMockStoreWithUser(t, "admin@test.com", "old-password-123")
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	// Request a reset code.
	forgotBody := `{"email":"admin@test.com"}`
	forgotReq := httptest.NewRequest(http.MethodPost, "/v1/auth/forgot-password", strings.NewReader(forgotBody))
	forgotRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(forgotRec, forgotReq)

	// Try wrong code.
	resetBody := `{"email":"admin@test.com","code":"000000","new_password":"new-password-456"}`
	resetReq := httptest.NewRequest(http.MethodPost, "/v1/auth/reset-password", strings.NewReader(resetBody))
	resetRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(resetRec, resetReq)

	if resetRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", resetRec.Code, resetRec.Body.String())
	}
}

func TestResetPasswordTooShort(t *testing.T) {
	srv := New("127.0.0.1:0", newMockStore(), make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"email":"admin@test.com","code":"123456","new_password":"short"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/reset-password", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestResetPasswordMissingFields(t *testing.T) {
	srv := New("127.0.0.1:0", newMockStore(), make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"email":"admin@test.com","code":"","new_password":"new-password-456"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/reset-password", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestInviteOnlyBlocksRegistration(t *testing.T) {
	ms := setupMockStoreWithUser(t, "owner@test.com", "owner-password-123")
	ms.settings[settingInviteOnly] = "true"
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"email":"new@test.com","password":"test-password-123"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when invite-only is enabled, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invite-only") {
		t.Fatalf("expected invite-only error message, got: %s", rec.Body.String())
	}
}

func TestInviteOnlyAllowsFirstUser(t *testing.T) {
	// Even with invite-only enabled, the first user (owner) should be able to register.
	ms := newMockStore()
	ms.settings[settingInviteOnly] = "true"
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"email":"owner@test.com","password":"owner-password-123"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 for first user even with invite-only, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestInviteOnlyDisabledAllowsRegistration(t *testing.T) {
	ms := setupMockStoreWithUser(t, "owner@test.com", "owner-password-123")
	// invite_only not set (default: disabled)
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"email":"new@test.com","password":"test-password-123"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	// Should succeed (201 with verification required)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 when invite-only is disabled, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestInviteOnlyAppearsInStatus(t *testing.T) {
	ms := setupMockStoreWithUser(t, "owner@test.com", "owner-password-123")
	ms.settings[settingInviteOnly] = "true"
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	inviteOnly, ok := resp["invite_only"]
	if !ok {
		t.Fatal("expected invite_only in status response")
	}
	if inviteOnly != true {
		t.Fatalf("expected invite_only=true, got %v", inviteOnly)
	}
}

func TestInviteOnlyNotInStatusWhenDisabled(t *testing.T) {
	ms := setupMockStoreWithUser(t, "owner@test.com", "owner-password-123")
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if _, ok := resp["invite_only"]; ok {
		t.Fatal("invite_only should not appear in status when disabled")
	}
}

func TestSettingsGetIncludesInviteOnly(t *testing.T) {
	ms := setupMockStoreWithUser(t, "owner@test.com", "owner-password-123")
	ms.settings[settingInviteOnly] = "true"
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	// Login to get a session token
	loginBody := `{"email":"owner@test.com","password":"owner-password-123"}`
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(loginBody))
	loginRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(loginRec, loginReq)

	var loginResp loginResponse
	json.NewDecoder(loginRec.Body).Decode(&loginResp)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/settings", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["invite_only"] != true {
		t.Fatalf("expected invite_only=true in settings, got %v", resp["invite_only"])
	}
	if resp["smtp_configured"] != false {
		t.Fatalf("expected smtp_configured=false (nil notifier), got %v", resp["smtp_configured"])
	}
}

func TestSettingsGetIncludesSMTPConfigured(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	n := notify.New(nil) // disabled notifier
	srv := New("127.0.0.1:0", ms, make([]byte, 32), n, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/settings", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)

	smtpVal, ok := resp["smtp_configured"]
	if !ok {
		t.Fatal("expected smtp_configured field in settings response")
	}
	if smtpVal != false {
		t.Fatalf("expected smtp_configured=false (nil config), got %v", smtpVal)
	}
}

func TestSettingsSetInviteOnly(t *testing.T) {
	ms := setupMockStoreWithUser(t, "owner@test.com", "owner-password-123")
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	// Login
	loginBody := `{"email":"owner@test.com","password":"owner-password-123"}`
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(loginBody))
	loginRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(loginRec, loginReq)

	var loginResp loginResponse
	json.NewDecoder(loginRec.Body).Decode(&loginResp)

	// Set invite_only
	body := `{"invite_only": true}`
	req := httptest.NewRequest(http.MethodPut, "/v1/admin/settings", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	if ms.settings[settingInviteOnly] != "true" {
		t.Fatalf("expected setting to be stored as 'true', got %q", ms.settings[settingInviteOnly])
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["invite_only"] != true {
		t.Fatalf("expected invite_only=true in response, got %v", resp["invite_only"])
	}
}

func TestOwnerVaultListShowsAllVaultsWithMembership(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := New(":0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	// Create a second vault that the owner has NO grant for.
	ms.CreateVault(context.Background(), "orphaned")

	req := httptest.NewRequest(http.MethodGet, "/v1/vaults", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Vaults []struct {
			Name       string `json:"name"`
			Role       string `json:"role"`
			Membership string `json:"membership"`
		} `json:"vaults"`
	}
	json.NewDecoder(rec.Body).Decode(&resp)

	if len(resp.Vaults) < 2 {
		t.Fatalf("expected at least 2 vaults, got %d", len(resp.Vaults))
	}

	byName := map[string]struct{ Role, Membership string }{}
	for _, v := range resp.Vaults {
		byName[v.Name] = struct{ Role, Membership string }{v.Role, v.Membership}
	}

	// default vault: owner has explicit admin grant
	if v, ok := byName["default"]; !ok || v.Membership != "explicit" || v.Role != "admin" {
		t.Errorf("default vault: expected explicit/admin, got %+v", byName["default"])
	}

	// orphaned vault: owner has no grant, should be implicit
	if v, ok := byName["orphaned"]; !ok || v.Membership != "implicit" || v.Role != "" {
		t.Errorf("orphaned vault: expected implicit/empty role, got %+v", byName["orphaned"])
	}
}

func TestMemberVaultListOnlyShowsGrantedVaults(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	memberToken := setupMemberSession(t, ms, "root-ns-id")
	srv := New(":0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	// Create a vault the member has no access to.
	ms.CreateVault(context.Background(), "secret")

	req := httptest.NewRequest(http.MethodGet, "/v1/vaults", nil)
	req.Header.Set("Authorization", "Bearer "+memberToken)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Vaults []struct {
			Name       string `json:"name"`
			Membership string `json:"membership"`
		} `json:"vaults"`
	}
	json.NewDecoder(rec.Body).Decode(&resp)

	for _, v := range resp.Vaults {
		if v.Name == "secret" {
			t.Fatalf("member should not see vault %q", v.Name)
		}
		if v.Membership != "explicit" {
			t.Errorf("member vault %q: expected explicit membership, got %q", v.Name, v.Membership)
		}
	}
}

func TestOwnerVaultJoinSuccess(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := New(":0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	// Create a vault the owner has no grant for.
	ms.CreateVault(context.Background(), "team-x")

	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/team-x/join", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify grant was created as admin.
	role, err := ms.GetVaultRole(context.Background(), "owner-user-id", "ns-team-x")
	if err != nil || role != "admin" {
		t.Fatalf("expected admin grant, got role=%q err=%v", role, err)
	}
}

func TestOwnerVaultJoinAlreadyMember(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := New(":0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	// Owner already has a grant on the default vault.
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/join", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMemberCannotJoinVault(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	memberToken := setupMemberSession(t, ms, "root-ns-id")
	srv := New(":0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	ms.CreateVault(context.Background(), "team-x")

	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/team-x/join", nil)
	req.Header.Set("Authorization", "Bearer "+memberToken)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestOwnerVaultJoinNotFound(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := New(":0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/nonexistent/join", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestVaultInviteCreateBlockedByAllowedDomains(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.settings[settingAllowedDomains] = `["acme.com"]`
	srv := New(":0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"email":"user@gmail.com","role":"member"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/invites", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for disallowed domain, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestVaultInviteCreateAllowedDomain(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.settings[settingAllowedDomains] = `["acme.com"]`
	srv := New(":0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"email":"user@acme.com","role":"member"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/invites", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 for allowed domain, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestVaultInviteCreateNoDomainRestrictions(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	// No domain restrictions set
	srv := New(":0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"email":"user@gmail.com","role":"member"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/invites", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 with no domain restrictions, got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- Direct Session Tests ---

func TestDirectSessionSuccess(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"vault":"default","vault_role":"consumer","ttl_seconds":3600}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions/direct", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp directSessionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AVSessionToken == "" {
		t.Fatal("expected non-empty session token")
	}
	if resp.AVAddr != "http://127.0.0.1:14321" {
		t.Fatalf("expected av_addr http://127.0.0.1:14321, got %q", resp.AVAddr)
	}
	if resp.AVVault != "default" {
		t.Fatalf("expected av_vault default, got %q", resp.AVVault)
	}
	if resp.VaultRole != "consumer" {
		t.Fatalf("expected vault_role consumer, got %q", resp.VaultRole)
	}
	if resp.ProxyURL != "http://127.0.0.1:14321/proxy" {
		t.Fatalf("expected proxy_url with /proxy, got %q", resp.ProxyURL)
	}
	if resp.ExpiresAt == "" {
		t.Fatal("expected non-empty expires_at")
	}
}

func TestDirectSessionDefaultsVaultAndRole(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions/direct", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp directSessionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AVVault != "default" {
		t.Fatalf("expected default vault, got %q", resp.AVVault)
	}
	if resp.VaultRole != "consumer" {
		t.Fatalf("expected consumer role, got %q", resp.VaultRole)
	}
}

func TestDirectSessionRoleCapping(t *testing.T) {
	// Create a member user (non-admin) with vault access
	ms := newMockStore()
	ms.users["member@test.com"] = &store.User{
		ID: "member-user-id", Email: "member@test.com",
		Role: "member", IsActive: true,
	}
	ms.GrantVaultRole(context.Background(), "member-user-id", "root-ns-id", "member")
	sess, err := ms.CreateSession(context.Background(), "member-user-id", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	// Request admin role — should be capped to consumer
	body := `{"vault":"default","vault_role":"admin"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions/direct", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+sess.ID)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp directSessionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.VaultRole != "consumer" {
		t.Fatalf("expected role capped to consumer, got %q", resp.VaultRole)
	}
}

func TestDirectSessionTTLBounds(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	// TTL too short
	body := `{"vault":"default","ttl_seconds":60}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions/direct", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short TTL, got %d: %s", rec.Code, rec.Body.String())
	}

	// TTL too long (8 days)
	body = `{"vault":"default","ttl_seconds":691200}`
	req = httptest.NewRequest(http.MethodPost, "/v1/sessions/direct", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for long TTL, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDirectSessionInvalidRole(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"vault":"default","vault_role":"superadmin"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions/direct", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid role, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDirectSessionUnauthenticated(t *testing.T) {
	ms := newMockStore()
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"vault":"default"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions/direct", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDirectSessionVaultNotFound(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"vault":"nonexistent"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions/direct", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDirectSessionWithLabel(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := New("127.0.0.1:0", ms, make([]byte, 32), nil, true, "http://127.0.0.1:14321", nil)

	body := `{"vault":"default","label":"testing stripe"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions/direct", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp directSessionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Verify label was stored on the session
	storedSess := ms.sessions[resp.AVSessionToken]
	if storedSess == nil {
		t.Fatal("session not found in store")
	}
	if storedSess.Label != "testing stripe" {
		t.Fatalf("expected label 'testing stripe', got %q", storedSess.Label)
	}
}
