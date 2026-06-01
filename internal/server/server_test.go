package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/infisical"
	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/store"
)

// tp is an alias for timePtr (defined in server.go, same package).
var tp = timePtr

// mockStore implements Store for testing.
type mockStore struct {
	masterKeyRecord    *store.MasterKeyRecord
	sessions           map[string]*store.Session
	vaults             map[string]*store.Vault
	credentials        map[string]*store.Credential             // keyed by "vaultID:key"
	brokerConfigs      map[string]*store.BrokerConfig       // keyed by vaultID
	proposals          map[string][]store.Proposal           // keyed by vaultID
	users              map[string]*store.User                // keyed by email
	grants             map[string]map[string]string          // keyed by userID -> vaultID -> role
	userInvites        map[string]*store.UserInvite           // keyed by token
	emailVerifications []*store.EmailVerification
	passwordResets     []*store.PasswordReset
	agents             map[string]*store.Agent               // keyed by name
	agentVaultGrants   []store.VaultGrant                    // agent vault grants
	settings           map[string]string                     // instance settings
	vaultSettings      map[string]map[string]string          // per-vault: vaultID -> key -> value
	credStores         map[string]*store.VaultCredentialStore // per-vault external credential store config
	sessionCounter     int
}

func newMockStore() *mockStore {
	ms := &mockStore{
		sessions:      make(map[string]*store.Session),
		vaults:        make(map[string]*store.Vault),
		credentials:   make(map[string]*store.Credential),
		brokerConfigs: make(map[string]*store.BrokerConfig),
		users:         make(map[string]*store.User),
		userInvites:   make(map[string]*store.UserInvite),
		agents:        make(map[string]*store.Agent),
		settings:      make(map[string]string),
		vaultSettings: make(map[string]map[string]string),
		credStores:    make(map[string]*store.VaultCredentialStore),
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

func (m *mockStore) CreateUserSession(_ context.Context, p store.CreateUserSessionParams) (*store.Session, error) {
	m.sessionCounter++
	exp := p.ExpiresAt
	now := time.Now()
	s := &store.Session{
		ID:            fmt.Sprintf("test-session-id-%d", m.sessionCounter),
		UserID:        p.UserID,
		ExpiresAt:     &exp,
		CreatedAt:     now,
		PublicID:      fmt.Sprintf("pub-%d", m.sessionCounter),
		LastUsedAt:    &now,
		IdleTTL:       p.IdleTTL,
		DeviceLabel:   p.DeviceLabel,
		LastIP:        p.LastIP,
		LastUserAgent: p.LastUserAgent,
	}
	m.sessions[s.ID] = s
	return s, nil
}

// CreateSession is a convenience for older test sites that pre-date
// CreateUserSession. New tests should call CreateUserSession directly.
func (m *mockStore) CreateSession(ctx context.Context, userID string, expiresAt time.Time) (*store.Session, error) {
	return m.CreateUserSession(ctx, store.CreateUserSessionParams{UserID: userID, ExpiresAt: expiresAt})
}

func (m *mockStore) TouchSession(_ context.Context, rawToken, ip, userAgent string) error {
	if sess, ok := m.sessions[rawToken]; ok && sess != nil {
		now := time.Now()
		sess.LastUsedAt = &now
		if ip != "" {
			sess.LastIP = ip
		}
		if userAgent != "" {
			sess.LastUserAgent = userAgent
		}
	}
	return nil
}

func (m *mockStore) ListUserSessions(_ context.Context, userID string) ([]store.Session, error) {
	var out []store.Session
	now := time.Now()
	for _, sess := range m.sessions {
		if sess.UserID != userID {
			continue
		}
		if sess.IsExpired(now) {
			continue
		}
		out = append(out, *sess)
	}
	return out, nil
}

func (m *mockStore) RevokeUserSession(_ context.Context, userID, publicID string) error {
	for id, sess := range m.sessions {
		if sess.UserID == userID && sess.PublicID == publicID {
			delete(m.sessions, id)
			return nil
		}
	}
	return sql.ErrNoRows
}

func (m *mockStore) CreateScopedSession(_ context.Context, p store.CreateScopedSessionParams) (*store.Session, error) {
	publicID := fmt.Sprintf("scoped-public-%d", len(m.sessions))
	s := &store.Session{
		ID:                 "scoped-session-id",
		VaultID:            p.VaultID,
		VaultRole:          p.VaultRole,
		ExpiresAt:          p.ExpiresAt,
		CreatedAt:          time.Now(),
		PublicID:           publicID,
		Label:              p.Label,
		CreatedByActorID:   p.CreatedByActorID,
		CreatedByActorType: p.CreatedByActorType,
	}
	m.sessions[s.ID] = s
	return s, nil
}

func (m *mockStore) ListScopedSessionsByVault(_ context.Context, vaultID string) ([]store.Session, error) {
	now := time.Now()
	var out []store.Session
	for _, sess := range m.sessions {
		if sess.VaultID != vaultID || sess.PublicID == "" || sess.UserID != "" || sess.AgentID != "" {
			continue
		}
		if sess.ExpiresAt != nil && sess.ExpiresAt.Before(now) {
			continue
		}
		out = append(out, *sess)
	}
	return out, nil
}

func (m *mockStore) RevokeScopedSession(_ context.Context, vaultID, publicID string) error {
	if vaultID == "" || publicID == "" {
		return sql.ErrNoRows
	}
	for id, sess := range m.sessions {
		if sess.VaultID == vaultID && sess.PublicID == publicID && sess.UserID == "" && sess.AgentID == "" {
			delete(m.sessions, id)
			return nil
		}
	}
	return sql.ErrNoRows
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

func (m *mockStore) CreateProposal(_ context.Context, vaultID, sessionID, servicesJSON, credentialsJSON, message, userMessage string, credentials map[string]store.EncryptedCredential) (*store.Proposal, error) {
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
		ServicesJSON:   servicesJSON,
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

func (m *mockStore) ApplyProposal(_ context.Context, vaultID string, proposalID int, mergedServicesJSON string, credentials map[string]store.EncryptedCredential, deleteCredentialKeys []string) error {
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
		ServicesJSON:   mergedServicesJSON,
	}
	return nil
}

func (m *mockStore) ExpirePendingProposals(_ context.Context, before time.Time) (int, error) {
	return 0, nil
}

func (m *mockStore) Close() error { return nil }

// --- Request log stubs (unused in server tests; storage-level tests
// live in the store package). ---

func (m *mockStore) InsertRequestLogs(_ context.Context, _ []store.RequestLog) error {
	return nil
}

func (m *mockStore) ListRequestLogs(_ context.Context, _ store.ListRequestLogsOpts) ([]store.RequestLog, error) {
	return nil, nil
}

func (m *mockStore) DeleteOldRequestLogs(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (m *mockStore) TrimRequestLogsToCap(_ context.Context, _ string, _ int64) (int64, error) {
	return 0, nil
}

func (m *mockStore) VaultIDsWithLogs(_ context.Context) ([]string, error) { return nil, nil }

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

func (m *mockStore) SetBrokerConfig(_ context.Context, vaultID, servicesJSON string) (*store.BrokerConfig, error) {
	bc := &store.BrokerConfig{
		ID:          "bc-" + vaultID,
		VaultID: vaultID,
		ServicesJSON:   servicesJSON,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	m.brokerConfigs[vaultID] = bc
	return bc, nil
}

func (m *mockStore) GrantVaultRole(_ context.Context, actorID, actorType, vaultID, role string) error {
	if actorType == "agent" {
		m.agentVaultGrants = append(m.agentVaultGrants, store.VaultGrant{
			ActorID: actorID, ActorType: "agent", VaultID: vaultID, Role: role, CreatedAt: time.Now(),
		})
		return nil
	}
	if m.grants == nil {
		m.grants = make(map[string]map[string]string)
	}
	if m.grants[actorID] == nil {
		m.grants[actorID] = make(map[string]string)
	}
	m.grants[actorID][vaultID] = role
	return nil
}

func (m *mockStore) RevokeVaultAccess(_ context.Context, userID, vaultID string) error {
	if m.grants != nil && m.grants[userID] != nil {
		delete(m.grants[userID], vaultID)
		return nil
	}
	return fmt.Errorf("grant not found")
}

func (m *mockStore) ListActorGrants(_ context.Context, actorID string) ([]store.VaultGrant, error) {
	var grants []store.VaultGrant
	// Check user grants
	if m.grants != nil && m.grants[actorID] != nil {
		for nsID, role := range m.grants[actorID] {
			grants = append(grants, store.VaultGrant{ActorID: actorID, ActorType: "user", VaultID: nsID, Role: role})
		}
	}
	// Check agent vault grants
	for _, g := range m.agentVaultGrants {
		if g.ActorID == actorID {
			grants = append(grants, g)
		}
	}
	return grants, nil
}

func (m *mockStore) HasVaultAccess(_ context.Context, actorID, vaultID string) (bool, error) {
	if m.grants != nil && m.grants[actorID] != nil {
		if _, ok := m.grants[actorID][vaultID]; ok {
			return true, nil
		}
	}
	for _, g := range m.agentVaultGrants {
		if g.ActorID == actorID && g.VaultID == vaultID {
			return true, nil
		}
	}
	return false, nil
}

func (m *mockStore) GetVaultRole(_ context.Context, actorID, vaultID string) (string, error) {
	if m.grants != nil && m.grants[actorID] != nil {
		if role, ok := m.grants[actorID][vaultID]; ok {
			return role, nil
		}
	}
	for _, g := range m.agentVaultGrants {
		if g.ActorID == actorID && g.VaultID == vaultID {
			return g.Role, nil
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

func (m *mockStore) ListVaultMembers(_ context.Context, vaultID string) ([]store.VaultGrant, error) {
	var result []store.VaultGrant
	// User grants
	for userID, userGrants := range m.grants {
		if role, ok := userGrants[vaultID]; ok {
			result = append(result, store.VaultGrant{ActorID: userID, ActorType: "user", VaultID: vaultID, Role: role})
		}
	}
	// Agent grants
	for _, g := range m.agentVaultGrants {
		if g.VaultID == vaultID {
			result = append(result, g)
		}
	}
	return result, nil
}

func (m *mockStore) ListVaultMembersByType(_ context.Context, vaultID, actorType string) ([]store.VaultGrant, error) {
	var result []store.VaultGrant
	switch actorType {
	case "user":
		for userID, userGrants := range m.grants {
			if role, ok := userGrants[vaultID]; ok {
				result = append(result, store.VaultGrant{ActorID: userID, ActorType: "user", VaultID: vaultID, Role: role})
			}
		}
	case "agent":
		for _, g := range m.agentVaultGrants {
			if g.VaultID == vaultID {
				result = append(result, g)
			}
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

// --- User Invite mock methods ---

func (m *mockStore) CreateUserInvite(_ context.Context, email, createdBy, role string, expiresAt time.Time, vaults []store.UserInviteVault) (*store.UserInvite, error) {
	if role == "" {
		role = "member"
	}
	token := "av_uinv_testtoken_" + email
	inv := &store.UserInvite{
		ID:        len(m.userInvites) + 1,
		Token:     token,
		Email:     email,
		Role:      role,
		Status:    "pending",
		CreatedBy: createdBy,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
		Vaults:    vaults,
	}
	m.userInvites[token] = inv
	return inv, nil
}

func (m *mockStore) GetUserInviteByToken(_ context.Context, token string) (*store.UserInvite, error) {
	inv, ok := m.userInvites[token]
	if !ok {
		return nil, fmt.Errorf("user invite not found")
	}
	return inv, nil
}

func (m *mockStore) GetPendingUserInviteByEmail(_ context.Context, email string) (*store.UserInvite, error) {
	for _, inv := range m.userInvites {
		if inv.Email == email && inv.Status == "pending" && time.Now().Before(inv.ExpiresAt) {
			return inv, nil
		}
	}
	return nil, nil
}

func (m *mockStore) ListUserInvites(_ context.Context, status string) ([]store.UserInvite, error) {
	var result []store.UserInvite
	for _, inv := range m.userInvites {
		if status == "" || inv.Status == status {
			result = append(result, *inv)
		}
	}
	return result, nil
}

func (m *mockStore) ListUserInvitesByVault(_ context.Context, vaultID, status string) ([]store.UserInvite, error) {
	var result []store.UserInvite
	for _, inv := range m.userInvites {
		if status != "" && inv.Status != status {
			continue
		}
		for _, v := range inv.Vaults {
			if v.VaultID == vaultID {
				result = append(result, *inv)
				break
			}
		}
	}
	return result, nil
}

func (m *mockStore) AcceptUserInvite(_ context.Context, token string) error {
	inv, ok := m.userInvites[token]
	if !ok || inv.Status != "pending" {
		return fmt.Errorf("not found or not pending")
	}
	inv.Status = "accepted"
	now := time.Now()
	inv.AcceptedAt = &now
	return nil
}

func (m *mockStore) RevokeUserInvite(_ context.Context, token string) error {
	inv, ok := m.userInvites[token]
	if !ok || inv.Status != "pending" {
		return fmt.Errorf("not found or not pending")
	}
	inv.Status = "revoked"
	return nil
}

func (m *mockStore) UpdateUserInviteVaults(_ context.Context, token string, vaults []store.UserInviteVault) error {
	inv, ok := m.userInvites[token]
	if !ok || inv.Status != "pending" {
		return fmt.Errorf("not found or not pending")
	}
	inv.Vaults = vaults
	return nil
}

func (m *mockStore) CountPendingUserInvites(_ context.Context) (int, error) {
	count := 0
	for _, inv := range m.userInvites {
		if inv.Status == "pending" {
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

func (m *mockStore) CreateAgent(_ context.Context, name, createdBy, role string) (*store.Agent, error) {
	if _, exists := m.agents[name]; exists {
		return nil, fmt.Errorf("UNIQUE constraint failed: agents.name")
	}
	ag := &store.Agent{
		ID:        "agent-" + name,
		Name:      name,
		Role:      role,
		Status:    "active",
		CreatedBy: createdBy,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	m.agents[name] = ag
	return ag, nil
}

func (m *mockStore) CreateAgentWithGrantsAndToken(ctx context.Context, name, createdBy, role string, vaultGrants []store.AgentVaultGrantSpec, expiresAt *time.Time) (*store.Agent, *store.Session, error) {
	ag, err := m.CreateAgent(ctx, name, createdBy, role)
	if err != nil {
		return nil, nil, err
	}
	for _, vg := range vaultGrants {
		if err := m.GrantVaultRole(ctx, ag.ID, "agent", vg.VaultID, vg.Role); err != nil {
			return nil, nil, err
		}
	}
	sess, err := m.CreateAgentToken(ctx, ag.ID, expiresAt)
	if err != nil {
		return nil, nil, err
	}
	return ag, sess, nil
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

func (m *mockStore) UpdateAgentRole(_ context.Context, agentID, role string) error {
	for _, ag := range m.agents {
		if ag.ID == agentID {
			ag.Role = role
			return nil
		}
	}
	return fmt.Errorf("agent not found")
}

func (m *mockStore) CountAllOwners(_ context.Context) (int, error) {
	return 1, nil
}

func (m *mockStore) ListAgents(_ context.Context, vaultID string) ([]store.Agent, error) {
	if vaultID == "" {
		return nil, fmt.Errorf("vaultID is required")
	}
	var result []store.Agent
	for _, g := range m.agentVaultGrants {
		if g.VaultID == vaultID {
			for _, ag := range m.agents {
				if ag.ID == g.ActorID {
					result = append(result, *ag)
					break
				}
			}
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

func (m *mockStore) CountAgentTokens(_ context.Context, agentID string) (int, error) {
	count := 0
	for _, sess := range m.sessions {
		if sess.AgentID == agentID && (sess.ExpiresAt == nil || time.Now().Before(*sess.ExpiresAt)) {
			count++
		}
	}
	return count, nil
}

func (m *mockStore) GetLatestAgentTokenExpiry(_ context.Context, agentID string) (*time.Time, error) {
	var latest *time.Time
	now := time.Now()
	for _, sess := range m.sessions {
		if sess.AgentID == agentID && sess.ExpiresAt != nil && sess.ExpiresAt.After(now) {
			t := *sess.ExpiresAt
			if latest == nil || t.After(*latest) {
				latest = &t
			}
		}
	}
	return latest, nil
}

func (m *mockStore) DeleteAgentTokens(_ context.Context, agentID string) error {
	for id, sess := range m.sessions {
		if sess.AgentID == agentID {
			delete(m.sessions, id)
		}
	}
	return nil
}

func (m *mockStore) RotateAgentToken(ctx context.Context, agentID string, expiresAt *time.Time) (*store.Session, error) {
	if err := m.DeleteAgentTokens(ctx, agentID); err != nil {
		return nil, err
	}
	return m.CreateAgentToken(ctx, agentID, expiresAt)
}

func (m *mockStore) CreateAgentToken(_ context.Context, agentID string, expiresAt *time.Time) (*store.Session, error) {
	m.sessionCounter++
	id := "agent-token-" + agentID + "-" + fmt.Sprintf("%d", m.sessionCounter)
	s := &store.Session{
		ID:        id,
		AgentID:   agentID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
	m.sessions[s.ID] = s
	return s, nil
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

func (m *mockStore) GetVaultSetting(_ context.Context, vaultID, key string) (string, error) {
	if vs, ok := m.vaultSettings[vaultID]; ok {
		if v, ok := vs[key]; ok {
			return v, nil
		}
	}
	return "", sql.ErrNoRows
}

func (m *mockStore) SetVaultSetting(_ context.Context, vaultID, key, value string) error {
	if m.vaultSettings[vaultID] == nil {
		m.vaultSettings[vaultID] = make(map[string]string)
	}
	m.vaultSettings[vaultID][key] = value
	return nil
}

func (m *mockStore) DeleteVaultSetting(_ context.Context, vaultID, key string) error {
	if vs, ok := m.vaultSettings[vaultID]; ok {
		delete(vs, key)
	}
	return nil
}

// External credential stores: minimal stubs so existing tests link; behavior
// covered by SQLite-backed tests in internal/store.
func (m *mockStore) CreateExternalVault(_ context.Context, _ store.CreateExternalVaultParams) (*store.Vault, error) {
	return nil, errors.New("mockStore.CreateExternalVault: not implemented in this test")
}
func (m *mockStore) GetVaultCredentialStore(_ context.Context, vaultID string) (*store.VaultCredentialStore, error) {
	if cs, ok := m.credStores[vaultID]; ok {
		return cs, nil
	}
	return nil, sql.ErrNoRows
}
func (m *mockStore) ListVaultCredentialStores(_ context.Context) ([]store.VaultCredentialStore, error) {
	out := make([]store.VaultCredentialStore, 0, len(m.credStores))
	for _, cs := range m.credStores {
		out = append(out, *cs)
	}
	return out, nil
}
func (m *mockStore) UpdateVaultCredentialStoreHealth(_ context.Context, vaultID, status, errMsg string, when time.Time) error {
	cs, ok := m.credStores[vaultID]
	if !ok {
		return sql.ErrNoRows
	}
	cs.LastSyncStatus = status
	cs.LastSyncError = errMsg
	t := when
	cs.LastSyncedAt = &t
	return nil
}
func (m *mockStore) ReplaceVaultCredentials(_ context.Context, _ string, _ []store.EncryptedKV) error {
	return nil
}

func TestHealthEndpoint(t *testing.T) {
	srv := newTestServer()

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
	srv := newTestServer()

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
	srv := newTestServer(withStore(ms))

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

func TestLoginRecordsDeviceMetadata(t *testing.T) {
	ms := setupMockStoreWithUser(t, "admin@test.com", "test-password-123")
	srv := newTestServer(withStore(ms))

	body := `{"email":"admin@test.com","password":"test-password-123","device_label":"tony-mbp"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(body))
	req.Header.Set("User-Agent", "agent-vault-cli/test")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp loginResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	sess := ms.sessions[resp.Token]
	if sess == nil {
		t.Fatal("expected session to be persisted")
	}
	if sess.DeviceLabel != "tony-mbp" {
		t.Fatalf("expected device_label 'tony-mbp', got %q", sess.DeviceLabel)
	}
	if sess.LastUserAgent != "agent-vault-cli/test" {
		t.Fatalf("expected user-agent recorded, got %q", sess.LastUserAgent)
	}
	if sess.IdleTTL != userSessionIdleTTL {
		t.Fatalf("expected idle ttl %v, got %v", userSessionIdleTTL, sess.IdleTTL)
	}
}

func TestListAndRevokeAuthSessionsRoute(t *testing.T) {
	ms := setupMockStoreWithUser(t, "admin@test.com", "test-password-123")
	srv := newTestServer(withStore(ms))

	// Two logins → two sessions for the same user.
	loginBody := `{"email":"admin@test.com","password":"test-password-123","device_label":"laptop"}`
	rec1 := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec1,
		httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(loginBody)))
	if rec1.Code != http.StatusOK {
		t.Fatalf("login 1: %d %s", rec1.Code, rec1.Body.String())
	}
	var login1 loginResponse
	_ = json.NewDecoder(rec1.Body).Decode(&login1)

	loginBody2 := `{"email":"admin@test.com","password":"test-password-123","device_label":"server"}`
	rec2 := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec2,
		httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(loginBody2)))
	var login2 loginResponse
	_ = json.NewDecoder(rec2.Body).Decode(&login2)

	// GET /v1/auth/sessions using session #1.
	listReq := httptest.NewRequest(http.MethodGet, "/v1/auth/sessions", nil)
	listReq.Header.Set("Authorization", "Bearer "+login1.Token)
	listRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list sessions: %d %s", listRec.Code, listRec.Body.String())
	}
	var listResp struct {
		Sessions []userSessionView `json:"sessions"`
	}
	if err := json.NewDecoder(listRec.Body).Decode(&listResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(listResp.Sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(listResp.Sessions))
	}
	currentCount := 0
	var currentID, otherID string
	for _, s := range listResp.Sessions {
		if s.Current {
			currentCount++
			currentID = s.ID
		} else {
			otherID = s.ID
		}
	}
	if currentCount != 1 {
		t.Fatalf("expected exactly one Current=true session, got %d", currentCount)
	}
	if want := ms.sessions[login1.Token].PublicID; currentID != want {
		t.Fatalf("Current=true row ID %q does not match login1's public_id %q", currentID, want)
	}

	// Revoke the other session via DELETE.
	delReq := httptest.NewRequest(http.MethodDelete, "/v1/auth/sessions/"+otherID, nil)
	delReq.Header.Set("Authorization", "Bearer "+login1.Token)
	delRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("revoke session: %d %s", delRec.Code, delRec.Body.String())
	}

	// Session #2's token should no longer authenticate.
	meReq := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+login2.Token)
	meRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(meRec, meReq)
	if meRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after revoke, got %d", meRec.Code)
	}

	// Revoking again returns 404.
	delAgain := httptest.NewRequest(http.MethodDelete, "/v1/auth/sessions/"+otherID, nil)
	delAgain.Header.Set("Authorization", "Bearer "+login1.Token)
	delAgainRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(delAgainRec, delAgain)
	if delAgainRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on duplicate revoke, got %d", delAgainRec.Code)
	}
}

func TestSelfRevokeClearsCookie(t *testing.T) {
	ms := setupMockStoreWithUser(t, "admin@test.com", "test-password-123")
	srv := newTestServer(withStore(ms))

	loginReq := httptest.NewRequest(http.MethodPost, "/v1/auth/login",
		strings.NewReader(`{"email":"admin@test.com","password":"test-password-123","device_label":"laptop"}`))
	loginRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", loginRec.Code, loginRec.Body.String())
	}
	var login loginResponse
	_ = json.NewDecoder(loginRec.Body).Decode(&login)
	myPub := ms.sessions[login.Token].PublicID

	delReq := httptest.NewRequest(http.MethodDelete, "/v1/auth/sessions/"+myPub, nil)
	delReq.Header.Set("Authorization", "Bearer "+login.Token)
	delRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("self-revoke: %d %s", delRec.Code, delRec.Body.String())
	}
	var cleared *http.Cookie
	for _, c := range delRec.Result().Cookies() {
		if c.Name == "av_session" {
			cleared = c
		}
	}
	if cleared == nil {
		t.Fatal("expected Set-Cookie clearing av_session on self-revoke")
	}
	if cleared.MaxAge >= 0 || cleared.Value != "" {
		t.Fatalf("expected expired empty av_session cookie, got value=%q max_age=%d", cleared.Value, cleared.MaxAge)
	}
	// Self-revoke must also surface `current: true` so non-cookie
	// clients (the CLI) know to drop their on-disk session.
	var resp struct {
		Status  string `json:"status"`
		Current bool   `json:"current"`
	}
	if err := json.Unmarshal(delRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode revoke response: %v", err)
	}
	if !resp.Current {
		t.Fatalf("self-revoke should report current=true, got %+v", resp)
	}
}

func TestRevokeOtherSessionLeavesCookieAlone(t *testing.T) {
	ms := setupMockStoreWithUser(t, "admin@test.com", "test-password-123")
	srv := newTestServer(withStore(ms))

	body := `{"email":"admin@test.com","password":"test-password-123","device_label":"laptop"}`
	rec1 := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec1, httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(body)))
	rec2 := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(body)))
	var login1, login2 loginResponse
	_ = json.NewDecoder(rec1.Body).Decode(&login1)
	_ = json.NewDecoder(rec2.Body).Decode(&login2)

	otherPub := ms.sessions[login2.Token].PublicID
	delReq := httptest.NewRequest(http.MethodDelete, "/v1/auth/sessions/"+otherPub, nil)
	delReq.Header.Set("Authorization", "Bearer "+login1.Token)
	delRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("revoke other: %d %s", delRec.Code, delRec.Body.String())
	}
	for _, c := range delRec.Result().Cookies() {
		if c.Name == "av_session" {
			t.Fatalf("revoking another session must not touch our own cookie, got %+v", c)
		}
	}
	var resp struct {
		Current bool `json:"current"`
	}
	if err := json.Unmarshal(delRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode revoke response: %v", err)
	}
	if resp.Current {
		t.Fatalf("revoking another session should report current=false, got %+v", resp)
	}
}

func TestRegisterFirstUserReturnsToken(t *testing.T) {
	ms := newMockStore()
	srv := newTestServer(withStore(ms))

	body := `{"email":"owner@test.com","password":"test-password-123","device_label":"my-laptop"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(body))
	req.Header.Set("User-Agent", "agent-vault-cli/test")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Authenticated bool   `json:"authenticated"`
		Token         string `json:"token"`
		ExpiresAt     string `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Authenticated || resp.Token == "" || resp.ExpiresAt == "" {
		t.Fatalf("first-user register should return authenticated session, got %+v", resp)
	}
	if sess := ms.sessions[resp.Token]; sess == nil || sess.DeviceLabel != "my-laptop" {
		t.Fatalf("expected stored session with device_label='my-laptop', got %+v", sess)
	}
	// Exactly one session row was created — no orphan from a duplicate auto-login.
	if len(ms.sessions) != 1 {
		t.Fatalf("expected 1 session after first-user register, got %d", len(ms.sessions))
	}
}

func TestVerifyReturnsTokenAndPersistsDeviceLabel(t *testing.T) {
	ms := newMockStore()
	// Inactive user with a pending verification code — the same shape
	// handleRegister produces on the second-user-onwards path.
	hash, salt, kdfP, err := auth.HashUserPassword([]byte("test-password-123"))
	if err != nil {
		t.Fatalf("HashUserPassword: %v", err)
	}
	ms.users["new@test.com"] = &store.User{
		ID: "u-new", Email: "new@test.com",
		PasswordHash: hash, PasswordSalt: salt,
		KDFTime: kdfP.Time, KDFMemory: kdfP.Memory, KDFThreads: kdfP.Threads,
		Role: "member", IsActive: false,
	}
	if _, err := ms.CreateEmailVerification(context.Background(), "new@test.com", "123456", time.Now().Add(15*time.Minute)); err != nil {
		t.Fatalf("CreateEmailVerification: %v", err)
	}

	srv := newTestServer(withStore(ms))
	body := `{"email":"new@test.com","code":"123456","device_label":"verify-device"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/verify", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Authenticated bool   `json:"authenticated"`
		Token         string `json:"token"`
		ExpiresAt     string `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Authenticated || resp.Token == "" || resp.ExpiresAt == "" {
		t.Fatalf("verify should return authenticated session, got %+v", resp)
	}
	sess := ms.sessions[resp.Token]
	if sess == nil {
		t.Fatal("verify should persist the session row")
	}
	if sess.DeviceLabel != "verify-device" {
		t.Fatalf("expected device_label 'verify-device', got %q", sess.DeviceLabel)
	}
	// Exactly one session row — verify must not produce an orphan that
	// a follow-up /v1/auth/login would duplicate.
	if len(ms.sessions) != 1 {
		t.Fatalf("expected 1 session after verify, got %d", len(ms.sessions))
	}
}

func TestChangePasswordPreservesDeviceLabel(t *testing.T) {
	ms := setupMockStoreWithUser(t, "admin@test.com", "old-password-123")
	srv := newTestServer(withStore(ms))

	// Login with a custom device label so we can prove it survives the
	// post-change-password DeleteUserSessions + CreateUserSession round-trip.
	body := `{"email":"admin@test.com","password":"old-password-123","device_label":"original-laptop"}`
	loginRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(loginRec,
		httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(body)))
	var login loginResponse
	_ = json.NewDecoder(loginRec.Body).Decode(&login)

	cpBody := `{"current_password":"old-password-123","new_password":"new-password-456"}`
	cpReq := httptest.NewRequest(http.MethodPost, "/v1/auth/change-password", strings.NewReader(cpBody))
	cpReq.Header.Set("Authorization", "Bearer "+login.Token)
	cpRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(cpRec, cpReq)
	if cpRec.Code != http.StatusOK {
		t.Fatalf("change-password: %d %s", cpRec.Code, cpRec.Body.String())
	}
	var cp loginResponse
	_ = json.NewDecoder(cpRec.Body).Decode(&cp)

	newSess := ms.sessions[cp.Token]
	if newSess == nil {
		t.Fatal("expected post-change session to be persisted")
	}
	if newSess.DeviceLabel != "original-laptop" {
		t.Fatalf("change-password should carry device_label across the new session, got %q", newSess.DeviceLabel)
	}
}

func TestTouchSessionRefreshesIPAndUserAgent(t *testing.T) {
	ms := setupMockStoreWithUser(t, "admin@test.com", "test-password-123")
	srv := newTestServer(withStore(ms))

	loginReq := httptest.NewRequest(http.MethodPost, "/v1/auth/login",
		strings.NewReader(`{"email":"admin@test.com","password":"test-password-123"}`))
	loginReq.Header.Set("User-Agent", "first-agent/1.0")
	loginReq.RemoteAddr = "10.0.0.1:1234"
	loginRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(loginRec, loginReq)
	var login loginResponse
	_ = json.NewDecoder(loginRec.Body).Decode(&login)

	// Force the cache miss so requireAuth's maybeTouchSession actually
	// reaches the store on the next request.
	srv.touchCache.Delete(login.Token)

	meReq := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+login.Token)
	meReq.Header.Set("User-Agent", "second-agent/2.0")
	meReq.RemoteAddr = "192.168.1.1:5678"
	meRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(meRec, meReq)
	if meRec.Code != http.StatusOK {
		t.Fatalf("/me: %d %s", meRec.Code, meRec.Body.String())
	}

	updated := ms.sessions[login.Token]
	if updated.LastUserAgent != "second-agent/2.0" {
		t.Fatalf("expected user-agent to refresh on touch, got %q", updated.LastUserAgent)
	}
	if updated.LastIP != "192.168.1.1" {
		t.Fatalf("expected last_ip to refresh on touch, got %q", updated.LastIP)
	}
}

func TestTruncateDeviceLabelKeepsValidUTF8(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"33 accents (boundary at 64 bytes)", strings.Repeat("é", 33)},
		{"17 emoji (boundary at 64 bytes)", strings.Repeat("🚀", 17)},
		{"22 cjk runes (boundary at 64 bytes)", strings.Repeat("世", 22)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := truncateDeviceLabel(tc.in)
			if !utf8.ValidString(out) {
				t.Fatalf("truncated label is not valid UTF-8: %q", out)
			}
			if utf8.RuneCountInString(out) > maxDeviceLabelRunes {
				t.Fatalf("rune count %d exceeds cap %d", utf8.RuneCountInString(out), maxDeviceLabelRunes)
			}
		})
	}
}

func TestPruneTouchCacheDropsStaleEntries(t *testing.T) {
	srv := newTestServer()
	// Cutoff is 2*TouchInterval; pick a within-window and an outside-window
	// timestamp so the bound is exercised without coupling to wall clock.
	srv.touchCache.Store("within-window", time.Now().Add(-store.TouchInterval))
	srv.touchCache.Store("past-cutoff", time.Now().Add(-3*store.TouchInterval))
	srv.pruneTouchCache()
	if _, ok := srv.touchCache.Load("within-window"); !ok {
		t.Fatal("entry inside the throttle grace window should be retained")
	}
	if _, ok := srv.touchCache.Load("past-cutoff"); ok {
		t.Fatal("entry past the cutoff should be evicted")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	ms := setupMockStoreWithUser(t, "admin@test.com", "correct-password-123")
	srv := newTestServer(withStore(ms))

	body := `{"email":"admin@test.com","password":"wrong-password-123"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(body))
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLoginEmptyFields(t *testing.T) {
	srv := newTestServer()

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
	srv := newTestServer(withStore(ms))

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
	ms.GrantVaultRole(context.Background(), "owner-user-id", "user", "root-ns-id", "admin")
	sess, err := ms.CreateSession(context.Background(), "owner-user-id", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return ms, sess.ID
}

func TestCredentialsSetSuccess(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	encKey := make([]byte, 32)
	srv := newTestServer(withStore(ms), withEncKey(encKey))

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

func TestCredentialsSetRejectedForExternalStore(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.credStores["root-ns-id"] = &store.VaultCredentialStore{
		VaultID: "root-ns-id", Kind: "infisical",
	}
	encKey := make([]byte, 32)
	srv := newTestServer(withStore(ms), withEncKey(encKey))

	body := `{"vault":"default","credentials":{"FOO":"bar"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/credentials", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp["code"] != "external_credential_store" {
		t.Fatalf("expected code=external_credential_store, got %v", resp)
	}
}

func TestCredentialsDeleteRejectedForExternalStore(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.credStores["root-ns-id"] = &store.VaultCredentialStore{
		VaultID: "root-ns-id", Kind: "infisical",
	}
	srv := newTestServer(withStore(ms))

	body := `{"vault":"default","keys":["FOO"]}`
	req := httptest.NewRequest(http.MethodDelete, "/v1/credentials", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp["code"] != "external_credential_store" {
		t.Fatalf("expected code=external_credential_store, got %v", resp)
	}
}

func TestCredentialsSetUnauthenticated(t *testing.T) {
	ms := newMockStore()
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms), withEncKey(encKey))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

	body := `{"vault":"default"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(body))
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
	// Verify the scoped session was stored with vault_id and default role "proxy".
	scopedSess := ms.sessions[resp.Token]
	if scopedSess == nil {
		t.Fatal("scoped session not found in store")
	}
	if scopedSess.VaultID != "root-ns-id" {
		t.Fatalf("expected vault_id root-ns-id, got %q", scopedSess.VaultID)
	}
	if scopedSess.VaultRole != "proxy" {
		t.Fatalf("expected vault_role proxy, got %q", scopedSess.VaultRole)
	}
}

// TestScopedSessionRoleAdminRejected covers the new restriction: even an
// owner with vault-admin can no longer request a non-proxy role through
// POST /v1/sessions. Tokens are minted with role `proxy` only.
// TestScopedSessionProxyUserRejected covers the rule that a proxy-role
// vault user cannot mint scoped tokens. Proxy is a "can only proxy
// requests" tier and explicitly excludes mint, even at proxy role.
func TestScopedSessionProxyUserRejected(t *testing.T) {
	ms := newMockStore()
	ms.users["proxy@test.com"] = &store.User{
		ID: "proxy-user-id", Email: "proxy@test.com",
		Role: "member", IsActive: true,
	}
	ms.GrantVaultRole(context.Background(), "proxy-user-id", "user", "root-ns-id", "proxy")
	sess, err := ms.CreateSession(context.Background(), "proxy-user-id", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	srv := newTestServer(withStore(ms))

	body := `{"vault":"default"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+sess.ID)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for proxy-role mint, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestScopedSessionRoleAdminRejected(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"vault":"default","vault_role":"admin"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestScopedSessionRoleMemberRejected(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"vault":"default","vault_role":"member"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestScopedSessionVaultNotFound(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"vault":"nonexistent"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestScopedSessionUnauthenticated(t *testing.T) {
	ms := newMockStore()
	srv := newTestServer(withStore(ms))

	body := `{"vault":"default"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(body))
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- Vault Enforcement ---

func setupMockStoreWithScopedSession(t *testing.T, vaultName, vaultID string) (*mockStore, string) {
	return setupMockStoreWithScopedSessionRole(t, vaultName, vaultID, "proxy")
}

func setupMockStoreWithScopedSessionRole(t *testing.T, vaultName, vaultID, role string) (*mockStore, string) {
	t.Helper()
	ms := newMockStore()
	// Add a second vault
	if vaultName != "default" {
		ms.vaults[vaultName] = &store.Vault{ID: vaultID, Name: vaultName}
	}
	// Create a scoped session locked to the given vault
	sess, err := ms.CreateScopedSession(context.Background(), store.CreateScopedSessionParams{
		VaultID:   vaultID,
		VaultRole: role,
		ExpiresAt: tp(time.Now().Add(time.Hour)),
	})
	if err != nil {
		t.Fatalf("CreateScopedSession: %v", err)
	}
	return ms, sess.ID
}

func TestScopedSessionEnforcesVaultOnSet(t *testing.T) {
	// Create a scoped session for vault "proj" (not "default")
	ms, token := setupMockStoreWithScopedSession(t, "proj", "proj-ns-id")
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms), withEncKey(encKey))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodGet, "/v1/credentials?vault=default", nil)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCredentialsListDefaultVault(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	// No vault query param — should default to "default"
	req := httptest.NewRequest(http.MethodGet, "/v1/credentials", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

// helper: pre-populate an encrypted credential in the mock store.
func seedEncryptedCredential(t *testing.T, ms *mockStore, encKey []byte, vaultID, key, plaintext string) {
	t.Helper()
	ciphertext, nonce, err := crypto.Encrypt([]byte(plaintext), encKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ms.credentials[vaultID+":"+key] = &store.Credential{
		ID: "credential-" + key, VaultID: vaultID, Key: key,
		Ciphertext: ciphertext, Nonce: nonce,
	}
}

func TestCredentialsRevealMember(t *testing.T) {
	// User session (owner) — member+ on vault, should see decrypted values.
	ms, token := setupMockStoreWithSession(t)
	encKey := make([]byte, 32)
	srv := newTestServer(withStore(ms), withEncKey(encKey))

	seedEncryptedCredential(t, ms, encKey, "root-ns-id", "SECRET", "s3cr3t")

	req := httptest.NewRequest(http.MethodGet, "/v1/credentials?vault=default&reveal=true", nil)
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
	if len(resp.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(resp.Credentials))
	}
	if resp.Credentials[0].Value != "s3cr3t" {
		t.Fatalf("expected value %q, got %q", "s3cr3t", resp.Credentials[0].Value)
	}
}

func TestCredentialsRevealSingleKey(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	encKey := make([]byte, 32)
	srv := newTestServer(withStore(ms), withEncKey(encKey))

	seedEncryptedCredential(t, ms, encKey, "root-ns-id", "A_KEY", "val-a")
	seedEncryptedCredential(t, ms, encKey, "root-ns-id", "B_KEY", "val-b")

	req := httptest.NewRequest(http.MethodGet, "/v1/credentials?vault=default&reveal=true&key=A_KEY", nil)
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
	if len(resp.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(resp.Credentials))
	}
	if resp.Credentials[0].Key != "A_KEY" || resp.Credentials[0].Value != "val-a" {
		t.Fatalf("unexpected credential: %+v", resp.Credentials[0])
	}
}

func TestCredentialsRevealNotFoundKey(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodGet, "/v1/credentials?vault=default&reveal=true&key=NOPE", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCredentialsRevealProxyBlocked(t *testing.T) {
	// Scoped session with proxy role — should be blocked from reveal.
	ms, token := setupMockStoreWithScopedSessionRole(t, "default", "root-ns-id", "proxy")
	encKey := make([]byte, 32)
	srv := newTestServer(withStore(ms), withEncKey(encKey))

	seedEncryptedCredential(t, ms, encKey, "root-ns-id", "SECRET", "s3cr3t")

	req := httptest.NewRequest(http.MethodGet, "/v1/credentials?vault=default&reveal=true", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCredentialsRevealScopedMemberAllowed(t *testing.T) {
	// Scoped session with member role — should be allowed to reveal.
	ms, token := setupMockStoreWithScopedSessionRole(t, "default", "root-ns-id", "member")
	encKey := make([]byte, 32)
	srv := newTestServer(withStore(ms), withEncKey(encKey))

	seedEncryptedCredential(t, ms, encKey, "root-ns-id", "TOKEN", "my-token")

	req := httptest.NewRequest(http.MethodGet, "/v1/credentials?vault=default&reveal=true", nil)
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
	if len(resp.Credentials) != 1 || resp.Credentials[0].Value != "my-token" {
		t.Fatalf("unexpected credentials: %+v", resp.Credentials)
	}
}

func TestCredentialsListNoRevealBackwardCompat(t *testing.T) {
	// Without reveal=true, response should have only keys, no credentials array.
	ms, token := setupMockStoreWithSession(t)
	encKey := make([]byte, 32)
	srv := newTestServer(withStore(ms), withEncKey(encKey))

	seedEncryptedCredential(t, ms, encKey, "root-ns-id", "FOO", "bar")

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
	if len(resp.Keys) != 1 || resp.Keys[0] != "FOO" {
		t.Fatalf("expected keys [FOO], got %v", resp.Keys)
	}
	if len(resp.Credentials) != 0 {
		t.Fatalf("expected no credentials in non-reveal response, got %d", len(resp.Credentials))
	}
}

func TestScopedSessionEnforcesVaultOnList(t *testing.T) {
	ms, token := setupMockStoreWithScopedSession(t, "proj", "proj-ns-id")
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

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

// --- Discovery endpoint tests ---

// setupVaultWithCredential seeds a mock store with a scoped session, broker
// config, and an encrypted STRIPE_KEY credential. Returns (store, scoped
// token, encryption key).
func setupVaultWithCredential(t *testing.T, servicesJSON string) (*mockStore, string, []byte) {
	t.Helper()
	ms := newMockStore()
	encKey := make([]byte, 32)

	sess, err := ms.CreateScopedSession(context.Background(), store.CreateScopedSessionParams{
		VaultID:   "root-ns-id",
		VaultRole: "proxy",
		ExpiresAt: tp(time.Now().Add(time.Hour)),
	})
	if err != nil {
		t.Fatalf("CreateScopedSession: %v", err)
	}

	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID:           "bc-1",
		VaultID:      "root-ns-id",
		ServicesJSON: servicesJSON,
	}

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

func TestDiscoverSuccess(t *testing.T) {
	servicesJSON := `[{"name":"github","host":"*.github.com","auth":{"type":"bearer","token":"GITHUB_TOKEN"}},{"name":"stripe","host":"api.stripe.com","auth":{"type":"bearer","token":"STRIPE_KEY"}}]`
	ms, token, _ := setupVaultWithCredential(t, servicesJSON)
	srv := newTestServer(withStore(ms))

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
	if len(resp.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(resp.Services))
	}
	if resp.Services[0].Host != "*.github.com" {
		t.Fatalf("expected host '*.github.com', got %q", resp.Services[0].Host)
	}
	if resp.Services[1].Host != "api.stripe.com" {
		t.Fatalf("expected host 'api.stripe.com', got %q", resp.Services[1].Host)
	}
	// setupVaultWithCredential seeds "STRIPE_KEY" — verify it appears in available_credentials.
	if len(resp.AvailableCredentials) != 1 || resp.AvailableCredentials[0] != "STRIPE_KEY" {
		t.Fatalf("expected available_credentials [STRIPE_KEY], got %v", resp.AvailableCredentials)
	}
}

// TestDiscoverHealsLegacyUnnamedServices pins that /discover returns
// auto-slugged Names for legacy entries persisted without `name`.
// Agents identify services by Name (per skill_cli.md); a blank Name
// here makes the service un-addressable until an unrelated write
// triggers a heal elsewhere.
func TestDiscoverHealsLegacyUnnamedServices(t *testing.T) {
	servicesJSON := `[
		{"host":"api.anthropic.com","auth":{"type":"bearer","token":"ANTHROPIC_KEY"}},
		{"host":"api.openai.com","auth":{"type":"bearer","token":"OPENAI_KEY"}}
	]`
	ms, token, _ := setupVaultWithCredential(t, servicesJSON)
	srv := newTestServer(withStore(ms))

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
	if len(resp.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(resp.Services))
	}
	if resp.Services[0].Name != "api-anthropic-com" {
		t.Fatalf("expected services[0].name=api-anthropic-com (auto-slug), got %q", resp.Services[0].Name)
	}
	if resp.Services[1].Name != "api-openai-com" {
		t.Fatalf("expected services[1].name=api-openai-com (auto-slug), got %q", resp.Services[1].Name)
	}
}

func TestDiscoverUnauthenticated(t *testing.T) {
	srv := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/discover", nil)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestDiscoverGlobalSessionForbidden(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodGet, "/discover", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDiscoverEmptyRules(t *testing.T) {
	ms, token, _ := setupVaultWithCredential(t, "[]")
	srv := newTestServer(withStore(ms))

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
	// setupVaultWithCredential seeds "STRIPE_KEY" — still available even with empty services.
	if len(resp.AvailableCredentials) != 1 || resp.AvailableCredentials[0] != "STRIPE_KEY" {
		t.Fatalf("expected available_credentials [STRIPE_KEY], got %v", resp.AvailableCredentials)
	}
}

func TestDiscoverNoCredentials(t *testing.T) {
	ms := newMockStore()
	sess, err := ms.CreateScopedSession(context.Background(), store.CreateScopedSessionParams{
		VaultID:   "root-ns-id",
		VaultRole: "proxy",
		ExpiresAt: tp(time.Now().Add(time.Hour)),
	})
	if err != nil {
		t.Fatalf("CreateScopedSession: %v", err)
	}
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id",
		ServicesJSON: `[{"name":"example","host":"example.com","auth":{"type":"custom","headers":{"X":"static"}}}]`,
	}

	srv := newTestServer(withStore(ms))
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
	srv := newTestServer(withStore(ms), withEncKey(encKey))

	// Create a scoped session for the root vault.
	sess := &store.Session{
		ID:          "scoped-cs-token",
		VaultID: "root-ns-id",
		ExpiresAt:   tp(time.Now().Add(1 * time.Hour)),
		CreatedAt:   time.Now(),
	}
	ms.sessions["scoped-cs-token"] = sess
	return srv, ms, "scoped-cs-token"
}

func TestProposalCreateSuccess(t *testing.T) {
	srv, _, token := setupProposalTest(t)

	body := `{
		"services": [{"action": "set", "name": "stripe", "host": "api.stripe.com", "auth": {"type": "bearer", "token": "STRIPE_KEY"}}],
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
	srv := newTestServer(withStore(ms))

	// Create a global (admin) session.
	sess := &store.Session{
		ID:        "admin-token",
		ExpiresAt: tp(time.Now().Add(1 * time.Hour)),
		CreatedAt: time.Now(),
	}
	ms.sessions["admin-token"] = sess

	body := `{"services": [{"action": "set", "name": "xcom", "host": "x.com", "auth": {"type": "custom", "headers": {"X": "v"}}}], "message": "test"}`
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

	// No services or credentials.
	body := `{"services": [], "message": "test"}`
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
		"services": [{"action": "set", "name": "stripe", "host": "api.stripe.com", "auth": {"type": "bearer", "token": "SK"}}],
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
			"services": [{"action": "set", "name": "%s", "host": "%s.com", "auth": {"type": "custom", "headers": {"X": "v"}}}],
			"message": "%s"
		}`, msg, msg, msg)
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
		"services": [{"action": "set", "name": "stripe", "host": "api.stripe.com", "auth": {"type": "bearer", "token": "SK"}}],
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
		"services": [{"action": "set", "name": "stripe", "host": "api.stripe.com", "auth": {"type": "bearer", "token": "MISSING_KEY"}}],
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
		"services": [{"action": "set", "name": "stripe", "host": "api.stripe.com", "auth": {"type": "bearer", "token": "STRIPE_KEY"}}],
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
	srv, ms, token := setupProposalTest(t)
	// Seed the vault with the service we're about to propose deleting,
	// so the host-only delete resolves uniquely to its canonical Name.
	// (A delete for a host with no matching service is now rejected at
	// create time with "name is required" rather than fabricating a
	// slug that could collide with an unrelated service.)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id",
		ServicesJSON: `[{"name":"slack","host":"api.slack.com","auth":{"type":"bearer","token":"SLACK_TOKEN"}}]`,
	}

	body := `{
		"services": [{"action": "delete", "host": "api.slack.com"}],
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
	srv, ms, token := setupProposalTest(t)
	// Seed the slack service so the host-only delete resolves uniquely.
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id",
		ServicesJSON: `[{"name":"slack","host":"api.slack.com","auth":{"type":"bearer","token":"SLACK_TOKEN"}}]`,
	}

	body := `{
		"services": [
			{"action": "set", "name": "stripe", "host": "api.stripe.com", "auth": {"type": "bearer", "token": "SK"}},
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

// --- Admin Proposal Tests ---

func setupAdminProposalTest(t *testing.T) (*Server, *mockStore, string) {
	t.Helper()
	ms := newMockStore()

	// Create an owner user and admin session.
	ms.users["owner@test.com"] = &store.User{
		ID: "owner-user-id", Email: "owner@test.com", Role: "owner", IsActive: true,
	}
	ms.GrantVaultRole(context.Background(), "owner-user-id", "user", "root-ns-id", "admin")
	adminSess := &store.Session{
		ID:        "admin-session",
		UserID:    "owner-user-id",
		ExpiresAt: tp(time.Now().Add(time.Hour)),
		CreatedAt: time.Now(),
	}
	ms.sessions[adminSess.ID] = adminSess

	encKey := make([]byte, 32)
	srv := newTestServer(withStore(ms), withEncKey(encKey))

	// Seed a broker config and a pending proposal.
	ms.proposals = make(map[string][]store.Proposal)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		VaultID: "root-ns-id",
		ServicesJSON:   `[]`,
	}
	ms.proposals["root-ns-id"] = []store.Proposal{
		{
			ID:          1,
			VaultID: "root-ns-id",
			Status:      "pending",
			ServicesJSON:   `[{"action":"set","name":"example","host":"api.example.com","auth":{"type":"bearer","token":"MY_KEY"}}]`,
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

// TestAdminProposalApproveRejectsStaleDeleteWithoutName pins that an
// ActionDelete proposal lacking Name whose target Host no longer
// matches any service is rejected at approve time. The delete-by-host
// resolver (kept as a UX feature for proposals) returns 0 matches →
// hostNotFoundError → 409, rather than silently dropping anything.
func TestAdminProposalApproveRejectsStaleDeleteWithoutName(t *testing.T) {
	ms := newMockStore()

	ms.users["owner@test.com"] = &store.User{
		ID: "owner-user-id", Email: "owner@test.com", Role: "owner", IsActive: true,
	}
	ms.GrantVaultRole(context.Background(), "owner-user-id", "user", "root-ns-id", "admin")
	adminSess := &store.Session{
		ID: "admin-session", UserID: "owner-user-id",
		ExpiresAt: tp(time.Now().Add(time.Hour)), CreatedAt: time.Now(),
	}
	ms.sessions[adminSess.ID] = adminSess
	srv := newTestServer(withStore(ms), withEncKey(make([]byte, 32)))

	// Vault holds an unrelated service. The stale delete proposal below
	// targets a host that no longer matches anything; the resolver must
	// surface 409 (no match) rather than touch the unrelated service.
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		VaultID: "root-ns-id",
		ServicesJSON: `[
			{"name":"unrelated","host":"unrelated.internal","auth":{"type":"bearer","token":"UNRELATED_KEEP"}}
		]`,
	}
	// Stale delete proposal: targets ghost.example.com which is no
	// longer in the vault, with no Name (delete-by-host flow).
	ms.proposals = make(map[string][]store.Proposal)
	ms.proposals["root-ns-id"] = []store.Proposal{{
		ID: 1, VaultID: "root-ns-id", Status: "pending",
		ServicesJSON:    `[{"action":"delete","host":"ghost.example.com"}]`,
		CredentialsJSON: `[]`,
		Message:         "Remove ghost service",
		CreatedAt:       time.Now(),
	}}

	body := `{"vault":"default","credentials":{}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/proposals/1/approve", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminSess.ID)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 (stale delete with no host match), got %d: %s", rec.Code, rec.Body.String())
	}
	// The unrelated service must survive untouched.
	merged := ms.brokerConfigs["root-ns-id"].ServicesJSON
	if !strings.Contains(merged, `"token":"UNRELATED_KEEP"`) {
		t.Fatalf("unrelated service was clobbered by stale delete; merged=%s", merged)
	}
}

func TestAdminProposalApproveRequiresAdminSession(t *testing.T) {
	srv, ms, _ := setupAdminProposalTest(t)

	// Create a scoped (non-admin) session.
	scopedSess := &store.Session{
		ID:          "scoped-session",
		VaultID: "root-ns-id",
		ExpiresAt:   tp(time.Now().Add(time.Hour)),
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
		ExpiresAt:   tp(time.Now().Add(time.Hour)),
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
		ExpiresAt: tp(time.Now().Add(time.Hour)),
		CreatedAt: time.Now(),
	}
	ms.sessions[memberSess.ID] = memberSess

	for _, nsID := range grantVaultIDs {
		ms.GrantVaultRole(context.Background(), "member-user-id", "user", nsID, "member")
	}
	return memberSess.ID
}

func TestMemberCanAccessGrantedVault(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	memberToken := setupMemberSession(t, ms, "root-ns-id")
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodGet, "/v1/credentials?vault=prod", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

// GET /v1/instance/credential-stores advertises only the kinds the caller
// can actually create. Two contracts are load-bearing: "infisical" requires
// a non-nil client (UI 503s otherwise), and "infisical" requires owner role
// (write path is owner-only; non-owners would see an enabled picker that
// 403s on submit).
func TestInstanceCredentialStores(t *testing.T) {
	cases := []struct {
		name            string
		asMember        bool
		attachInfisical bool
		want            []string
	}{
		{"owner sees builtin only when no infisical client", false, false, []string{store.CredentialStoreBuiltin}},
		{"owner sees both when client attached", false, true, []string{store.CredentialStoreBuiltin, store.CredentialStoreInfisical}},
		{"member sees builtin only even when client attached", true, true, []string{store.CredentialStoreBuiltin}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ms, ownerToken := setupMockStoreWithSession(t)
			token := ownerToken
			if tc.asMember {
				token = setupMemberSession(t, ms)
			}
			srv := newTestServer(withStore(ms))
			if tc.attachInfisical {
				srv.AttachInfisical(&infisical.Client{})
			}

			req := httptest.NewRequest(http.MethodGet, "/v1/instance/credential-stores", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
			}
			var resp struct {
				Available []string `json:"available"`
			}
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !slices.Equal(resp.Available, tc.want) {
				t.Fatalf("available: want %v, got %v", tc.want, resp.Available)
			}
		})
	}
}

func TestVaultCreateExternalRequiresOwner(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	memberToken := setupMemberSession(t, ms)
	srv := newTestServer(withStore(ms))

	body := `{"name":"loot","credential_store":{"kind":"infisical","config":{"project_id":"p","environment":"prod","secret_path":"/"},"poll_interval_seconds":60}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+memberToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for member, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestVaultContextRedactsConfigForNonAdmin locks in that the upstream
// topology (project_id, environment, secret_path) is only returned to vault
// admins and instance owners. Proxy/member roles must see only the kind +
// sync health, otherwise a proxy-role agent can call this endpoint and read
// the operator's Infisical layout.
func TestVaultContextRedactsConfigForNonAdmin(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	memberToken := setupMemberSession(t, ms, "root-ns-id")
	ms.credStores["root-ns-id"] = &store.VaultCredentialStore{
		VaultID:    "root-ns-id",
		Kind:       "infisical",
		ConfigJSON: `{"project_id":"secret-proj","environment":"prod","secret_path":"/svc"}`,
	}
	srv := newTestServer(withStore(ms))

	hit := func(token string) map[string]interface{} {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/v1/vaults/default/context", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			CredentialStore map[string]interface{} `json:"credential_store"`
		}
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return resp.CredentialStore
	}

	asOwner := hit(ownerToken)
	if asOwner["config"] == nil {
		t.Fatalf("owner must see config, got %+v", asOwner)
	}
	if asOwner["kind"] != "infisical" {
		t.Fatalf("owner kind: want infisical, got %v", asOwner["kind"])
	}

	asMember := hit(memberToken)
	if _, leaked := asMember["config"]; leaked {
		t.Fatalf("member must NOT see config, got %+v", asMember)
	}
	if asMember["kind"] != "infisical" {
		t.Fatalf("member must still see kind, got %v", asMember["kind"])
	}
}

// TestVaultContextRedactsLastSyncErrorForNonAdmin locks in that
// last_sync_error (may carry upstream keys via the invalid-key carve-out)
// is redacted alongside Config for non-admin/non-owner callers.
func TestVaultContextRedactsLastSyncErrorForNonAdmin(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	memberToken := setupMemberSession(t, ms, "root-ns-id")
	ms.credStores["root-ns-id"] = &store.VaultCredentialStore{
		VaultID:       "root-ns-id",
		Kind:          "infisical",
		ConfigJSON:    `{"project_id":"p","environment":"prod","secret_path":"/"}`,
		LastSyncError: `duplicate secret key "API_KEY" under both /stripe and /openai; flat key-value cannot disambiguate`,
	}
	srv := newTestServer(withStore(ms))

	hit := func(token string) map[string]interface{} {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/v1/vaults/default/context", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			CredentialStore map[string]interface{} `json:"credential_store"`
		}
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return resp.CredentialStore
	}

	asOwner := hit(ownerToken)
	if got, _ := asOwner["last_sync_error"].(string); got == "" {
		t.Fatalf("owner must see last_sync_error, got %+v", asOwner)
	}

	asMember := hit(memberToken)
	if _, leaked := asMember["last_sync_error"]; leaked {
		t.Fatalf("member must NOT see last_sync_error (may carry upstream paths/keys), got %+v", asMember)
	}
}

// stubFetcher returns canned results so each branch of
// POST /v1/vaults/{name}/sync can be exercised in isolation.
type stubFetcher struct {
	secrets []infisical.Secret
	err     error
}

func (s *stubFetcher) FetchSecrets(_ context.Context, _ infisical.VaultConfig) ([]infisical.Secret, error) {
	return s.secrets, s.err
}
func (s *stubFetcher) AuthMethod() infisical.AuthMethod { return infisical.AuthUniversal }

func TestVaultSyncNow_NotFound(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/does-not-exist/sync", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestVaultSyncNow_BuiltinVaultReturns400(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	// No credStores entry → vault is builtin.
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/sync", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for builtin vault, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestVaultSyncNow_NoSyncerReturns503(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.credStores["root-ns-id"] = &store.VaultCredentialStore{
		VaultID: "root-ns-id", Kind: "infisical",
		ConfigJSON: `{"project_id":"p","environment":"dev","secret_path":"/"}`,
	}
	srv := newTestServer(withStore(ms)) // intentionally no AttachInfisicalSyncer

	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/sync", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp["code"] != "infisical_not_configured" {
		t.Fatalf("expected code=infisical_not_configured, got %v", resp)
	}
}

// attachStubSyncer wires a Syncer driven by `fetcher` onto srv and returns
// the populated credStores row so the test can assert post-sync state.
func attachStubSyncer(t *testing.T, srv *Server, ms *mockStore, fetcher interface {
	FetchSecrets(context.Context, infisical.VaultConfig) ([]infisical.Secret, error)
	AuthMethod() infisical.AuthMethod
}) {
	t.Helper()
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}
	srv.encKey = dek
	syncer := infisical.NewSyncer(ms, fetcher, dek, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.AttachInfisicalSyncer(syncer)
	srv.AttachInfisical(&infisical.Client{}) // present so other gates relax; not used by RefreshOnce
}

func TestVaultSyncNow_Success(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.credStores["root-ns-id"] = &store.VaultCredentialStore{
		VaultID: "root-ns-id", Kind: "infisical",
		ConfigJSON:     `{"project_id":"p","environment":"dev","secret_path":"/"}`,
		LastSyncStatus: "pending",
	}
	srv := newTestServer(withStore(ms))
	attachStubSyncer(t, srv, ms, &stubFetcher{
		secrets: []infisical.Secret{{Key: "STRIPE_KEY", Value: "sk_1"}},
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/sync", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		CredentialStore map[string]interface{} `json:"credential_store"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.CredentialStore["kind"] != "infisical" {
		t.Fatalf("kind: want infisical, got %v", resp.CredentialStore["kind"])
	}
	if resp.CredentialStore["last_sync_status"] != "ok" {
		t.Fatalf("status: want ok, got %v", resp.CredentialStore["last_sync_status"])
	}
	// Owner should see the config.
	if resp.CredentialStore["config"] == nil {
		t.Fatalf("owner must see config, got %+v", resp.CredentialStore)
	}
}

func TestVaultSyncNow_InvalidKeyReturns400(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.credStores["root-ns-id"] = &store.VaultCredentialStore{
		VaultID: "root-ns-id", Kind: "infisical",
		ConfigJSON: `{"project_id":"p","environment":"dev","secret_path":"/"}`,
	}
	srv := newTestServer(withStore(ms))
	attachStubSyncer(t, srv, ms, &stubFetcher{
		// kebab-case key violates broker.CredentialKeyPattern → ErrInvalidKey.
		secrets: []infisical.Secret{{Key: "stripe-key", Value: "sk_1"}},
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/sync", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp["code"] != "external_store_invalid_key" {
		t.Fatalf("expected code=external_store_invalid_key, got %v", resp)
	}
	// The bad key must appear in the message so the operator can fix it upstream.
	if !strings.Contains(resp["error"], "stripe-key") {
		t.Fatalf("error must name the offending key; got %q", resp["error"])
	}
}

// TestVaultSyncNow_InvalidKeyRedactedForNonAdmin locks the contract that a
// non-admin/non-owner caller hitting ErrInvalidKey receives a generic message —
// the offending key name is upstream topology and is redacted on every other
// surface (last_sync_error in handleVaultContext, the post-sync summary).
func TestVaultSyncNow_InvalidKeyRedactedForNonAdmin(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	memberToken := setupMemberSession(t, ms, "root-ns-id")
	ms.credStores["root-ns-id"] = &store.VaultCredentialStore{
		VaultID: "root-ns-id", Kind: "infisical",
		ConfigJSON: `{"project_id":"p","environment":"dev","secret_path":"/"}`,
	}
	srv := newTestServer(withStore(ms))
	attachStubSyncer(t, srv, ms, &stubFetcher{
		secrets: []infisical.Secret{{Key: "stripe-key", Value: "sk_1"}},
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/sync", nil)
	req.Header.Set("Authorization", "Bearer "+memberToken)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp["code"] != "external_store_invalid_key" {
		t.Fatalf("expected code=external_store_invalid_key, got %v", resp)
	}
	if strings.Contains(resp["error"], "stripe-key") {
		t.Fatalf("non-admin response must not leak the offending key name; got %q", resp["error"])
	}
}

func TestVaultSyncNow_GenericUpstreamFailureReturns502(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.credStores["root-ns-id"] = &store.VaultCredentialStore{
		VaultID: "root-ns-id", Kind: "infisical",
		ConfigJSON: `{"project_id":"p","environment":"dev","secret_path":"/"}`,
	}
	srv := newTestServer(withStore(ms))
	// Real SDK error embeds INFISICAL_URL; the handler must scrub it from the response.
	upstreamErr := errors.New("APIError: CallListSecretsV3Raw [GET https://infisical.internal/api/v3/secrets/raw] [status-code=404]")
	attachStubSyncer(t, srv, ms, &stubFetcher{err: upstreamErr})

	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/sync", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp["code"] != "infisical_fetch_failed" {
		t.Fatalf("expected code=infisical_fetch_failed, got %v", resp)
	}
	if strings.Contains(resp["error"], "infisical.internal") {
		t.Fatalf("scrubbed response must not leak the upstream URL; got %q", resp["error"])
	}
}

func TestVaultCreateSlugValidation(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms), withEncKey(encKey))

	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{VaultID: "root-ns-id", ServicesJSON: `[]`}
	ms.proposals = map[string][]store.Proposal{
		"root-ns-id": {{
			ID: 1, VaultID: "root-ns-id", Status: "pending",
			ServicesJSON: `[]`, CredentialsJSON: `[]`,
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

// setupProxyRoleSession creates a proxy-role user with a login session and optional vault grants.
func setupProxyRoleSession(t *testing.T, ms *mockStore, grantVaultIDs ...string) string {
	t.Helper()
	ms.users["proxybot@test.com"] = &store.User{
		ID: "proxy-user-id", Email: "proxybot@test.com", Role: "member", IsActive: true,
	}
	proxySess := &store.Session{
		ID:        "proxy-session",
		UserID:    "proxy-user-id",
		ExpiresAt: tp(time.Now().Add(time.Hour)),
		CreatedAt: time.Now(),
	}
	ms.sessions[proxySess.ID] = proxySess

	for _, nsID := range grantVaultIDs {
		ms.GrantVaultRole(context.Background(), "proxy-user-id", "user", nsID, "proxy")
	}
	return proxySess.ID
}

func TestInstanceLevelProxyCannotApproveProposal(t *testing.T) {
	ms := newMockStore()
	proxyToken := setupProxyRoleSession(t, ms, "root-ns-id")

	encKey := make([]byte, 32)
	srv := newTestServer(withStore(ms), withEncKey(encKey))

	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{VaultID: "root-ns-id", ServicesJSON: `[]`}
	ms.proposals = map[string][]store.Proposal{
		"root-ns-id": {{
			ID: 1, VaultID: "root-ns-id", Status: "pending",
			ServicesJSON: `[]`, CredentialsJSON: `[]`,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}},
	}

	body := `{"vault":"default","credentials":{}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/proposals/1/approve", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+proxyToken)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	// The status check is load-bearing: it proves the apply step never ran,
	// so the proxy could not have triggered credential injection downstream.
	if got := ms.proposals["root-ns-id"][0].Status; got != "pending" {
		t.Fatalf("proposal must remain pending after rejected approve; got %s", got)
	}
}

func TestInstanceLevelProxyCannotRejectProposal(t *testing.T) {
	ms := newMockStore()
	proxyToken := setupProxyRoleSession(t, ms, "root-ns-id")

	encKey := make([]byte, 32)
	srv := newTestServer(withStore(ms), withEncKey(encKey))

	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{VaultID: "root-ns-id", ServicesJSON: `[]`}
	ms.proposals = map[string][]store.Proposal{
		"root-ns-id": {{
			ID: 1, VaultID: "root-ns-id", Status: "pending",
			ServicesJSON: `[]`, CredentialsJSON: `[]`,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}},
	}

	body := `{"vault":"default","reason":"nope"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/proposals/1/reject", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+proxyToken)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := ms.proposals["root-ns-id"][0].Status; got != "pending" {
		t.Fatalf("proposal must remain pending after rejected reject; got %s", got)
	}
}

func TestLastOwnerCannotBeDemoted(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms), withNotifier(notifier))

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
	ms.GrantVaultRole(context.Background(), "owner-user-id", "user", "root-ns-id", "admin")
	adminSess := &store.Session{
		ID: "admin-session", UserID: "owner-user-id",
		ExpiresAt: tp(time.Now().Add(time.Hour)), CreatedAt: time.Now(),
	}
	ms.sessions[adminSess.ID] = adminSess
	encKey := make([]byte, 32)
	srv := newTestServer(withStore(ms), withEncKey(encKey))
	return srv, ms, adminSess.ID
}

func TestHandleAgentCreate(t *testing.T) {
	srv, ms, sessID := setupAgentTest(t)

	body := strings.NewReader(`{"name":"newbot","role":"member","vaults":[{"vault_name":"default","vault_role":"proxy"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/agents", body)
	req.Header.Set("Authorization", "Bearer "+sessID)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["av_agent_token"] == nil || resp["av_agent_token"].(string) == "" {
		t.Fatal("expected non-empty av_agent_token")
	}
	if resp["name"] != "newbot" {
		t.Fatalf("expected name=newbot, got %v", resp["name"])
	}
	if resp["role"] != "member" {
		t.Fatalf("expected role=member, got %v", resp["role"])
	}
	if ms.agents["newbot"] == nil {
		t.Fatal("expected agent to be persisted")
	}
}

func TestHandleAgentCreate_DefaultsToNoAccess(t *testing.T) {
	srv, ms, sessID := setupAgentTest(t)

	body := strings.NewReader(`{"name":"newbot"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/agents", body)
	req.Header.Set("Authorization", "Bearer "+sessID)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["role"] != "no-access" {
		t.Fatalf("expected role=no-access (server default), got %v", resp["role"])
	}
	if ag := ms.agents["newbot"]; ag == nil || ag.Role != "no-access" {
		t.Fatalf("expected persisted agent role=no-access, got %+v", ag)
	}
}

func TestHandleAgentCreate_DuplicateName(t *testing.T) {
	srv, ms, sessID := setupAgentTest(t)

	ms.agents["existing"] = &store.Agent{ID: "a-existing", Name: "existing", Status: "active"}

	body := strings.NewReader(`{"name":"existing"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/agents", body)
	req.Header.Set("Authorization", "Bearer "+sessID)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleAgentRotate_InvalidatesOldToken(t *testing.T) {
	srv, ms, sessID := setupAgentTest(t)

	ms.agents["bot"] = &store.Agent{ID: "a1", Name: "bot", Status: "active"}
	// Seed an existing agent token so we can verify it gets invalidated.
	oldToken, _ := ms.CreateAgentToken(context.Background(), "a1", nil)
	if _, ok := ms.sessions[oldToken.ID]; !ok {
		t.Fatalf("setup: expected old token in sessions map")
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/agents/bot/rotate", nil)
	req.Header.Set("Authorization", "Bearer "+sessID)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	newToken := resp["av_agent_token"].(string)
	if newToken == "" || newToken == oldToken.ID {
		t.Fatalf("expected fresh non-empty token, got %q (old was %q)", newToken, oldToken.ID)
	}
	if _, ok := ms.sessions[oldToken.ID]; ok {
		t.Fatalf("expected old session deleted after rotate, still present")
	}
}

func TestAgentList(t *testing.T) {
	srv, ms, sessID := setupAgentTest(t)

	ms.agents["bot1"] = &store.Agent{ID: "a1", Name: "bot1", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	ms.agents["bot2"] = &store.Agent{ID: "a2", Name: "bot2", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	ms.agentVaultGrants = append(ms.agentVaultGrants, store.VaultGrant{ActorID: "a1", ActorType: "agent", VaultID: "root-ns-id", Role: "proxy"})
	ms.agentVaultGrants = append(ms.agentVaultGrants, store.VaultGrant{ActorID: "a2", ActorType: "agent", VaultID: "root-ns-id", Role: "proxy"})

	req := httptest.NewRequest(http.MethodGet, "/v1/agents", nil)
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
	for _, raw := range agents {
		row := raw.(map[string]interface{})
		if _, has := row["invite_id"]; has {
			t.Fatalf("active agent row should not include invite_id, got %v", row)
		}
	}
}

// Non-owner creators must see their own vault-less agents in /v1/agents.
// Mutation endpoints (revoke/rotate/rename) accept agent.CreatedBy == actor.ID
// regardless of vault overlap, so the list endpoint must mirror that ACL.
func TestAgentList_NonOwnerSeesOwnVaultlessAgent(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	memberToken := setupMemberSession(t, ms)
	srv := newTestServer(withStore(ms))

	ms.agents["alice-bot"] = &store.Agent{
		ID: "alice-bot-id", Name: "alice-bot", Status: "active",
		CreatedBy: "member-user-id",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	// Sibling agent owned by someone else with no shared vault; must not leak.
	ms.agents["other-bot"] = &store.Agent{
		ID: "other-bot-id", Name: "other-bot", Status: "active",
		CreatedBy: "owner-user-id",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer "+memberToken)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	agents := resp["agents"].([]interface{})
	if len(agents) != 1 {
		t.Fatalf("expected 1 visible agent (own), got %d: %s", len(agents), rec.Body.String())
	}
	if agents[0].(map[string]interface{})["name"] != "alice-bot" {
		t.Fatalf("expected alice-bot, got %v", agents[0])
	}
}

func TestAgentGet_NonOwnerOwnVaultlessAgent(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	memberToken := setupMemberSession(t, ms)
	srv := newTestServer(withStore(ms))

	ms.agents["alice-bot"] = &store.Agent{
		ID: "alice-bot-id", Name: "alice-bot", Status: "active",
		CreatedBy: "member-user-id",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/agents/alice-bot", nil)
	req.Header.Set("Authorization", "Bearer "+memberToken)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAgentGet_NonOwnerCannotViewOthersAgent(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	memberToken := setupMemberSession(t, ms)
	srv := newTestServer(withStore(ms))

	ms.agents["other-bot"] = &store.Agent{
		ID: "other-bot-id", Name: "other-bot", Status: "active",
		CreatedBy: "owner-user-id",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/agents/other-bot", nil)
	req.Header.Set("Authorization", "Bearer "+memberToken)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAgentRevoke(t *testing.T) {
	srv, ms, sessID := setupAgentTest(t)

	ms.agents["revokebot"] = &store.Agent{ID: "a1", Name: "revokebot", Status: "active"}

	req := httptest.NewRequest(http.MethodDelete, "/v1/agents/revokebot", nil)
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

	ms.agents["rotatebot"] = &store.Agent{ID: "a1", Name: "rotatebot", Status: "active"}

	req := httptest.NewRequest(http.MethodPost, "/v1/agents/rotatebot/rotate", nil)
	req.Header.Set("Authorization", "Bearer "+sessID)
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
	if resp["rotated_at"] == nil || resp["rotated_at"].(string) == "" {
		t.Fatal("expected non-empty rotated_at")
	}
}

func TestAgentRename(t *testing.T) {
	srv, ms, sessID := setupAgentTest(t)

	ms.agents["oldbot"] = &store.Agent{ID: "a1", Name: "oldbot", Status: "active"}

	body := strings.NewReader(`{"name": "newbot"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/agents/oldbot/rename", body)
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
	srv := newTestServer(withStore(ms))

	// Create a non-default vault to rename.
	ms.vaults["oldvault"] = &store.Vault{ID: "old-vault-id", Name: "oldvault"}
	ms.GrantVaultRole(context.Background(), "owner-user-id", "user", "old-vault-id", "admin")

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

func TestVaultSettingsUnmatchedHostPolicy(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	t.Run("default is passthrough", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/vaults/default/settings", nil)
		req.Header.Set("Authorization", "Bearer "+ownerToken)
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		var resp map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp["unmatched_host_policy"] != "passthrough" {
			t.Fatalf("expected passthrough default, got %q", resp["unmatched_host_policy"])
		}
	})

	t.Run("set to deny", func(t *testing.T) {
		body := strings.NewReader(`{"unmatched_host_policy": "deny"}`)
		req := httptest.NewRequest(http.MethodPatch, "/v1/vaults/default/settings", body)
		req.Header.Set("Authorization", "Bearer "+ownerToken)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		if ms.vaultSettings["root-ns-id"][settingUnmatchedHostPolicy] != "deny" {
			t.Fatalf("expected stored policy=deny, got %q",
				ms.vaultSettings["root-ns-id"][settingUnmatchedHostPolicy])
		}
		// Response must echo the validated value, not depend on a second
		// store read — otherwise a transient read failure post-write
		// would desync the UI from the persisted policy.
		var resp map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp["unmatched_host_policy"] != "deny" {
			t.Fatalf("expected response to echo deny, got %q", resp["unmatched_host_policy"])
		}
	})

	t.Run("invalid value rejected", func(t *testing.T) {
		body := strings.NewReader(`{"unmatched_host_policy": "log-and-allow"}`)
		req := httptest.NewRequest(http.MethodPatch, "/v1/vaults/default/settings", body)
		req.Header.Set("Authorization", "Bearer "+ownerToken)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("empty string reverts to default", func(t *testing.T) {
		// First set to deny so we have something to revert.
		_ = ms.SetVaultSetting(context.Background(), "root-ns-id", settingUnmatchedHostPolicy, "deny")

		body := strings.NewReader(`{"unmatched_host_policy": ""}`)
		req := httptest.NewRequest(http.MethodPatch, "/v1/vaults/default/settings", body)
		req.Header.Set("Authorization", "Bearer "+ownerToken)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		if v := ms.vaultSettings["root-ns-id"][settingUnmatchedHostPolicy]; v != "" {
			t.Fatalf("expected setting cleared, got %q", v)
		}
	})

	t.Run("non-admin member: GET reflects real policy, PATCH is forbidden", func(t *testing.T) {
		// Persist deny so we can verify the non-admin GET sees the truth
		// rather than the previous silent passthrough fallback.
		_ = ms.SetVaultSetting(context.Background(), "root-ns-id", settingUnmatchedHostPolicy, "deny")
		memberToken := setupMemberSession(t, ms, "root-ns-id")

		// GET should succeed and return the actual stored policy.
		req := httptest.NewRequest(http.MethodGet, "/v1/vaults/default/settings", nil)
		req.Header.Set("Authorization", "Bearer "+memberToken)
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected GET 200 for member, got %d: %s", rec.Code, rec.Body.String())
		}
		var resp map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp["unmatched_host_policy"] != "deny" {
			t.Fatalf("member GET should see real deny policy, got %q", resp["unmatched_host_policy"])
		}

		// PATCH must still be admin/owner-only.
		patchBody := strings.NewReader(`{"unmatched_host_policy": "passthrough"}`)
		req = httptest.NewRequest(http.MethodPatch, "/v1/vaults/default/settings", patchBody)
		req.Header.Set("Authorization", "Bearer "+memberToken)
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected PATCH 403 for member, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestUserGetMe(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

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

// --- Public User List Tests ---

func TestPublicUserListAsOwner(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodGet, "/v1/users", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	users, ok := resp["users"].([]interface{})
	if !ok {
		t.Fatalf("expected users array, got %T", resp["users"])
	}
	if len(users) == 0 {
		t.Fatal("expected at least one user")
	}
	// Owners should get vault membership data.
	first := users[0].(map[string]interface{})
	if _, hasVaults := first["vaults"]; !hasVaults {
		t.Fatal("expected vaults field for owner view")
	}
}

func TestPublicUserListAsMember(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	memberToken := setupMemberSession(t, ms, "root-ns-id")
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodGet, "/v1/users", nil)
	req.Header.Set("Authorization", "Bearer "+memberToken)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	users, ok := resp["users"].([]interface{})
	if !ok {
		t.Fatalf("expected users array, got %T", resp["users"])
	}
	if len(users) == 0 {
		t.Fatal("expected at least one user")
	}
	// Members should NOT get vault membership data.
	first := users[0].(map[string]interface{})
	if _, hasVaults := first["vaults"]; hasVaults {
		t.Fatal("expected no vaults field for member view")
	}
	// Should still have basic fields.
	if _, hasEmail := first["email"]; !hasEmail {
		t.Fatal("expected email field")
	}
	if _, hasRole := first["role"]; !hasRole {
		t.Fatal("expected role field")
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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer()

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodDelete, "/v1/auth/account", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteAccountNoAuth(t *testing.T) {
	srv := newTestServer()

	req := httptest.NewRequest(http.MethodDelete, "/v1/auth/account", nil)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestForgotPasswordSuccess(t *testing.T) {
	ms := setupMockStoreWithUser(t, "admin@test.com", "old-password-123")
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer()

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer()

	body := `{"email":"admin@test.com","code":"123456","new_password":"short"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/reset-password", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestResetPasswordMissingFields(t *testing.T) {
	srv := newTestServer()

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if _, ok := resp["invite_only"]; ok {
		t.Fatal("invite_only should not appear in status when disabled")
	}
}

func TestBaseURLInStatusWhenAddrSet(t *testing.T) {
	t.Setenv("AGENT_VAULT_ADDR", "https://vault.example.com")
	ms := setupMockStoreWithUser(t, "owner@test.com", "owner-password-123")
	srv := newTestServer(withStore(ms), withBaseURL("https://vault.example.com"))

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
	got, ok := resp["base_url"]
	if !ok {
		t.Fatal("expected base_url in status response when AGENT_VAULT_ADDR is set")
	}
	if got != "https://vault.example.com" {
		t.Fatalf("expected base_url=https://vault.example.com, got %v", got)
	}
}

func TestBaseURLAbsentFromStatusWhenAddrUnset(t *testing.T) {
	t.Setenv("AGENT_VAULT_ADDR", "")
	ms := setupMockStoreWithUser(t, "owner@test.com", "owner-password-123")
	srv := newTestServer(withStore(ms))

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
	if _, ok := resp["base_url"]; ok {
		t.Fatal("base_url should not appear in status when AGENT_VAULT_ADDR is unset")
	}
}

func TestSettingsGetIncludesInviteOnly(t *testing.T) {
	ms := setupMockStoreWithUser(t, "owner@test.com", "owner-password-123")
	ms.settings[settingInviteOnly] = "true"
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms), withNotifier(n))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

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

// TestVaultListOmitsCredentialStoreForBuiltin locks in that the credential_store
// field is absent for builtin vaults (json:"omitempty") and present for external
// ones. Scripts and UI both branch on its presence.
func TestVaultListOmitsCredentialStoreForBuiltin(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	if _, err := ms.CreateVault(context.Background(), "ext"); err != nil {
		t.Fatalf("CreateVault ext: %v", err)
	}
	extID := ms.vaults["ext"].ID
	ms.credStores[extID] = &store.VaultCredentialStore{
		VaultID: extID, Kind: store.CredentialStoreInfisical,
		ConfigJSON: `{"project_id":"p","environment":"dev","secret_path":"/"}`,
	}
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodGet, "/v1/vaults", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Vaults []map[string]interface{} `json:"vaults"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byName := map[string]map[string]interface{}{}
	for _, v := range resp.Vaults {
		byName[v["name"].(string)] = v
	}
	if _, leaked := byName["default"]["credential_store"]; leaked {
		t.Fatalf("builtin vault must omit credential_store, got %+v", byName["default"])
	}
	cs, ok := byName["ext"]["credential_store"].(map[string]interface{})
	if !ok {
		t.Fatalf("external vault must include credential_store, got %+v", byName["ext"])
	}
	if cs["kind"] != "infisical" {
		t.Fatalf("kind: want infisical, got %v", cs["kind"])
	}
}

func TestMemberVaultListOnlyShowsGrantedVaults(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	memberToken := setupMemberSession(t, ms, "root-ns-id")
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

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
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/nonexistent/join", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUserInviteCreateBlockedByAllowedDomains(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.settings[settingAllowedDomains] = `["acme.com"]`
	srv := newTestServer(withStore(ms))

	body := `{"email":"user@gmail.com"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/users/invites", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for disallowed domain, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUserInviteCreateAllowedDomain(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.settings[settingAllowedDomains] = `["acme.com"]`
	srv := newTestServer(withStore(ms))

	body := `{"email":"user@acme.com"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/users/invites", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 for allowed domain, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUserInviteCreateNoDomainRestrictions(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	// No domain restrictions set
	srv := newTestServer(withStore(ms))

	body := `{"email":"user@gmail.com"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/users/invites", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 with no domain restrictions, got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- Scoped Session TTL and Role Validation Tests ---

func TestScopedSessionWithTTL(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"vault":"default","vault_role":"proxy","ttl_seconds":3600}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(body))
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
		t.Fatal("expected non-empty token")
	}
	if resp.AVAddr != "http://127.0.0.1:14321" {
		t.Fatalf("expected av_addr http://127.0.0.1:14321, got %q", resp.AVAddr)
	}
	if resp.ExpiresAt == "" {
		t.Fatal("expected non-empty expires_at")
	}
}

func TestScopedSessionTTLBounds(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	// TTL too short
	body := `{"vault":"default","ttl_seconds":60}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short TTL, got %d: %s", rec.Code, rec.Body.String())
	}

	// TTL too long (8 days)
	body = `{"vault":"default","ttl_seconds":691200}`
	req = httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for long TTL, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestScopedSessionInvalidRole(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"vault":"default","vault_role":"superadmin"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid role, got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- Tokens UI: list + revoke + label ---

func TestScopedSessionMintWithLabel(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"vault":"default","label":"ci-bot"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(body))
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
	stored := ms.sessions[resp.Token]
	if stored == nil {
		t.Fatal("scoped session not stored")
	}
	if stored.Label != "ci-bot" {
		t.Fatalf("expected label ci-bot, got %q", stored.Label)
	}
	if stored.CreatedByActorID != "owner-user-id" || stored.CreatedByActorType != "user" {
		t.Fatalf("expected created_by user/owner-user-id, got %s/%s", stored.CreatedByActorType, stored.CreatedByActorID)
	}
	if stored.PublicID == "" {
		t.Fatal("expected public_id to be populated on scoped session")
	}
}

func TestScopedSessionLabelCJKWithinRuneLimit(t *testing.T) {
	// 50 CJK characters = 150 bytes UTF-8, well under the 100-byte len()
	// cap that previously rejected this — but within the 100-rune cap.
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	cjk := strings.Repeat("我", 50)
	body := fmt.Sprintf(`{"vault":"default","label":%q}`, cjk)
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for 50-rune CJK label, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp scopedSessionResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if got := ms.sessions[resp.Token]; got == nil || got.Label != cjk {
		t.Fatalf("expected label preserved, got %+v", got)
	}
}

func TestScopedSessionLabelStripsControlChars(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"vault":"default","label":"line1\nline2\ttab"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp scopedSessionResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	got := ms.sessions[resp.Token]
	if got == nil || got.Label != "line1line2tab" {
		t.Fatalf("expected control chars stripped, got %q", func() string {
			if got == nil {
				return "<nil>"
			}
			return got.Label
		}())
	}
}

func TestScopedSessionLabelTooLong(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	tooLong := strings.Repeat("a", maxScopedSessionLabel+1)
	body := fmt.Sprintf(`{"vault":"default","label":%q}`, tooLong)
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized label, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestScopedSessionListAndRevoke(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	mintBody := `{"vault":"default","label":"laptop"}`
	mintReq := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(mintBody))
	mintReq.Header.Set("Authorization", "Bearer "+token)
	mintRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(mintRec, mintReq)
	if mintRec.Code != http.StatusOK {
		t.Fatalf("mint: expected 200, got %d: %s", mintRec.Code, mintRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/v1/sessions?vault=default", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d: %s", listRec.Code, listRec.Body.String())
	}
	var listResp struct {
		Sessions []scopedSessionView `json:"sessions"`
	}
	if err := json.NewDecoder(listRec.Body).Decode(&listResp); err != nil {
		t.Fatalf("list decode: %v", err)
	}
	if len(listResp.Sessions) != 1 {
		t.Fatalf("expected 1 scoped session, got %d", len(listResp.Sessions))
	}
	row := listResp.Sessions[0]
	if row.Label != "laptop" {
		t.Fatalf("expected label laptop, got %q", row.Label)
	}
	if row.ID == "" {
		t.Fatal("expected non-empty public_id in list view")
	}
	if row.CreatedBy == nil || row.CreatedBy.DisplayName != "owner@test.com" {
		t.Fatalf("expected created_by display_name owner@test.com, got %+v", row.CreatedBy)
	}

	revokeReq := httptest.NewRequest(http.MethodDelete, "/v1/sessions/"+row.ID+"?vault=default", nil)
	revokeReq.Header.Set("Authorization", "Bearer "+token)
	revokeRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke: expected 200, got %d: %s", revokeRec.Code, revokeRec.Body.String())
	}

	listReq2 := httptest.NewRequest(http.MethodGet, "/v1/sessions?vault=default", nil)
	listReq2.Header.Set("Authorization", "Bearer "+token)
	listRec2 := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(listRec2, listReq2)
	var listResp2 struct {
		Sessions []scopedSessionView `json:"sessions"`
	}
	_ = json.NewDecoder(listRec2.Body).Decode(&listResp2)
	if len(listResp2.Sessions) != 0 {
		t.Fatalf("expected 0 sessions after revoke, got %d", len(listResp2.Sessions))
	}
}

func TestScopedSessionRevokeNotFound(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodDelete, "/v1/sessions/does-not-exist?vault=default", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestScopedSessionListRequiresAuth(t *testing.T) {
	ms := newMockStore()
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodGet, "/v1/sessions?vault=default", nil)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}


// setupMockStoreWithInactiveUser creates a mock store with an inactive (unverified) user.
func setupMockStoreWithInactiveUser(t *testing.T, email, password string) *mockStore {
	t.Helper()
	ms := setupMockStoreWithUser(t, email, password)
	// Demote the user to inactive member; add a separate owner so count > 1.
	ms.users[email].IsActive = false
	ms.users[email].Role = "member"
	ms.users["owner@test.com"] = &store.User{
		ID: "owner-id", Email: "owner@test.com",
		Role: "owner", IsActive: true,
	}
	return ms
}

func TestResendVerificationSuccess(t *testing.T) {
	ms := setupMockStoreWithInactiveUser(t, "test@example.com", "password123")
	srv := newTestServer(withStore(ms))

	body := `{"email":"test@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/resend-verification", strings.NewReader(body))
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

	// Verify a new verification code was created.
	if len(ms.emailVerifications) != 1 {
		t.Fatalf("expected 1 email verification, got %d", len(ms.emailVerifications))
	}
}

func TestResendVerificationUnknownEmail(t *testing.T) {
	ms := setupMockStoreWithInactiveUser(t, "test@example.com", "password123")
	srv := newTestServer(withStore(ms))

	// Unknown email — should return 200 (uniform response, no enumeration).
	body := `{"email":"unknown@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/resend-verification", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// No verification code should have been created.
	if len(ms.emailVerifications) != 0 {
		t.Fatalf("expected 0 email verifications, got %d", len(ms.emailVerifications))
	}
}

func TestResendVerificationActiveUser(t *testing.T) {
	ms := setupMockStoreWithUser(t, "admin@test.com", "password123")
	srv := newTestServer(withStore(ms))

	// Active user — should return 200 (uniform response, no enumeration).
	body := `{"email":"admin@test.com"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/resend-verification", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// No verification code should have been created.
	if len(ms.emailVerifications) != 0 {
		t.Fatalf("expected 0 email verifications, got %d", len(ms.emailVerifications))
	}
}

func TestResendVerificationEmptyEmail(t *testing.T) {
	srv := newTestServer()

	body := `{"email":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/resend-verification", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestResendVerificationTooManyPending(t *testing.T) {
	ms := setupMockStoreWithInactiveUser(t, "test@example.com", "password123")
	srv := newTestServer(withStore(ms))

	// Pre-fill 3 pending verifications to hit the limit.
	for i := 0; i < 3; i++ {
		ms.emailVerifications = append(ms.emailVerifications, &store.EmailVerification{
			ID: i + 1, Email: "test@example.com", Code: fmt.Sprintf("%06d", i),
			Status: "pending", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(15 * time.Minute),
		})
	}

	body := `{"email":"test@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/resend-verification", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	// Too many pending codes — uniform 200 (don't reveal account exists).
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// No new verification should have been created.
	if len(ms.emailVerifications) != 3 {
		t.Fatalf("expected 3 email verifications, got %d", len(ms.emailVerifications))
	}
}

// --- Services Upsert Tests ---

func TestServicesUpsertRejectsDeprecatedDescription(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"name":"stripe","host":"api.stripe.com","description":"Stripe API","auth":{"type":"bearer","token":"STRIPE_KEY"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for deprecated description, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "description is no longer supported") {
		t.Fatalf("expected deprecation error, got %s", rec.Body.String())
	}
}

func TestProposalCreateRejectsDeprecatedDescription(t *testing.T) {
	srv, _, token := setupProposalTest(t)

	body := `{
		"services": [{"action": "set", "name": "stripe", "host": "api.stripe.com", "description": "Stripe API", "auth": {"type": "bearer", "token": "STRIPE_KEY"}}],
		"credentials": [{"action": "set", "key": "STRIPE_KEY"}],
		"message": "need stripe"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proposals", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for deprecated description, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "description is no longer supported") {
		t.Fatalf("expected deprecation error, got %s", rec.Body.String())
	}
}

func TestServicesUpsertAddNew(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"name":"stripe","host":"api.stripe.com","auth":{"type":"bearer","token":"STRIPE_KEY"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["vault"] != "default" {
		t.Fatalf("expected vault=default, got %v", resp["vault"])
	}
	upserted := resp["upserted"].([]interface{})
	if len(upserted) != 1 || upserted[0] != "stripe" {
		t.Fatalf("expected upserted=[stripe], got %v", upserted)
	}
	if resp["services_count"].(float64) != 1 {
		t.Fatalf("expected services_count=1, got %v", resp["services_count"])
	}
}

// TestServicesUpsertRejectsMissingNameForNewService pins the
// "name is required for new services" contract: an empty-Name upsert
// against an empty vault has no existing entry to adopt by host, so
// it falls through to broker.Validate which rejects with 400.
func TestServicesUpsertRejectsMissingNameForNewService(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"host":"api.stripe.com","auth":{"type":"bearer","token":"STRIPE_KEY"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 (name required for new service), got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "name is required") {
		t.Fatalf("expected error to mention 'name is required', got %s", rec.Body.String())
	}
}

func TestServicesUpsertReplaceExisting(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	// Pre-seed a service.
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id",
		ServicesJSON: `[{"name":"stripe","host":"api.stripe.com","auth":{"type":"bearer","token":"OLD_KEY"}}]`,
	}
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"name":"stripe","host":"api.stripe.com","auth":{"type":"bearer","token":"NEW_KEY"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["services_count"].(float64) != 1 {
		t.Fatalf("expected services_count=1 (replaced, not appended), got %v", resp["services_count"])
	}

	// Verify the stored service has the new token key.
	bc := ms.brokerConfigs["root-ns-id"]
	if !strings.Contains(bc.ServicesJSON, "NEW_KEY") {
		t.Fatalf("expected NEW_KEY in stored services, got %s", bc.ServicesJSON)
	}
	if strings.Contains(bc.ServicesJSON, "OLD_KEY") {
		t.Fatalf("expected OLD_KEY to be replaced, got %s", bc.ServicesJSON)
	}
}

// TestServicesUpsertEmptyNameAdoptsExistingByHostPath pins the
// same-host rename heal: an empty-Name upsert against a service that
// was renamed (`stripe-prod` for `api.stripe.com`) adopts the existing
// Name and in-place replaces, instead of appending an unreachable
// `api-stripe-com` ghost that loses every MatchService tiebreak.
func TestServicesUpsertEmptyNameAdoptsExistingByHostPath(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id",
		ServicesJSON: `[{"name":"stripe-prod","host":"api.stripe.com","auth":{"type":"bearer","token":"OLD_KEY"}}]`,
	}
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"host":"api.stripe.com","auth":{"type":"bearer","token":"NEW_KEY"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["services_count"].(float64) != 1 {
		t.Fatalf("expected in-place replace (services_count=1), got %v — would be a ghost service", resp["services_count"])
	}
	upserted := resp["upserted"].([]interface{})
	if len(upserted) != 1 || upserted[0] != "stripe-prod" {
		t.Fatalf("expected upserted=[stripe-prod] (adopted), got %v", upserted)
	}
	bc := ms.brokerConfigs["root-ns-id"]
	if !strings.Contains(bc.ServicesJSON, "NEW_KEY") || strings.Contains(bc.ServicesJSON, "OLD_KEY") {
		t.Fatalf("expected token rotated to NEW_KEY, got %s", bc.ServicesJSON)
	}
	if strings.Contains(bc.ServicesJSON, "api-stripe-com") {
		t.Fatalf("expected no auto-slugged ghost entry, got %s", bc.ServicesJSON)
	}
}

// TestServicesUpsertEmptyNameDoesNotReplaceUnrelatedExisting pins
// that an empty-Name upsert whose Host does not uniquely match the
// existing wildcard service is rejected as a new-service-needs-name
// error rather than silently overwriting the wildcard. Before the
// required-name contract this case relied on a Slugify cross-host
// disambiguation; with the contract restored, the safer behavior is
// to refuse the write so the caller picks an explicit name.
func TestServicesUpsertEmptyNameDoesNotReplaceUnrelatedExisting(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id",
		ServicesJSON: `[{"name":"github-com","host":"*.github.com","auth":{"type":"bearer","token":"WILDCARD_TOKEN"}}]`,
	}
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"host":"github.com","auth":{"type":"bearer","token":"BARE_TOKEN"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 (name required, no unique host match), got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "name is required") {
		t.Fatalf("expected error to mention 'name is required', got %s", rec.Body.String())
	}
	bc := ms.brokerConfigs["root-ns-id"]
	if !strings.Contains(bc.ServicesJSON, "WILDCARD_TOKEN") {
		t.Fatalf("expected wildcard service preserved (WILDCARD_TOKEN), got %s", bc.ServicesJSON)
	}
	if strings.Contains(bc.ServicesJSON, "BARE_TOKEN") {
		t.Fatalf("expected new service NOT appended, got %s", bc.ServicesJSON)
	}
}

// Regression: GET → modify-one → PUT on legacy unnamed services must
// succeed without the caller manually slugging the siblings.
func TestLegacyUnnamedServicesGetSetRoundTrip(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id",
		ServicesJSON: `[
			{"host":"api.anthropic.com","auth":{"type":"bearer","token":"ANTHROPIC_API_KEY"}},
			{"host":"api.openai.com","auth":{"type":"bearer","token":"OPENAI_API_KEY"}}
		]`,
	}
	srv := newTestServer(withStore(ms))

	getReq := httptest.NewRequest(http.MethodGet, "/v1/vaults/default/services", nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET expected 200, got %d: %s", getRec.Code, getRec.Body.String())
	}
	var getResp struct {
		Services []map[string]interface{} `json:"services"`
	}
	if err := json.NewDecoder(getRec.Body).Decode(&getResp); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	if len(getResp.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(getResp.Services))
	}
	if getResp.Services[0]["name"] != "api-anthropic-com" {
		t.Fatalf("expected service[0].name=api-anthropic-com, got %v", getResp.Services[0]["name"])
	}
	if getResp.Services[1]["name"] != "api-openai-com" {
		t.Fatalf("expected service[1].name=api-openai-com, got %v", getResp.Services[1]["name"])
	}

	// PUT with one renamed entry — mirrors the Edit Service sidebar.
	getResp.Services[0]["name"] = "anthropic-api"
	putBody, err := json.Marshal(map[string]interface{}{"services": getResp.Services})
	if err != nil {
		t.Fatalf("marshal PUT body: %v", err)
	}
	putReq := httptest.NewRequest(http.MethodPut, "/v1/vaults/default/services", bytes.NewReader(putBody))
	putReq.Header.Set("Authorization", "Bearer "+token)
	putRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT expected 200, got %d: %s", putRec.Code, putRec.Body.String())
	}

	bc := ms.brokerConfigs["root-ns-id"]
	if !strings.Contains(bc.ServicesJSON, `"name":"anthropic-api"`) {
		t.Fatalf("expected stored services to contain anthropic-api, got %s", bc.ServicesJSON)
	}
	if !strings.Contains(bc.ServicesJSON, `"name":"api-openai-com"`) {
		t.Fatalf("expected stored services to contain auto-slugged api-openai-com, got %s", bc.ServicesJSON)
	}
}

func TestServicesUpsertBatch(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"services":[
		{"name":"stripe","host":"api.stripe.com","auth":{"type":"bearer","token":"STRIPE_KEY"}},
		{"name":"github","host":"api.github.com","auth":{"type":"bearer","token":"GITHUB_TOKEN"}}
	]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["services_count"].(float64) != 2 {
		t.Fatalf("expected services_count=2, got %v", resp["services_count"])
	}
	upserted := resp["upserted"].([]interface{})
	if len(upserted) != 2 {
		t.Fatalf("expected 2 upserted hosts, got %d", len(upserted))
	}
}

func TestServicesUpsertEmptyArray(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"services":[]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestServicesUpsertValidationError(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	// Missing auth type.
	body := `{"services":[{"name":"stripe","host":"api.stripe.com","auth":{}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestServicesUpsertUnauthenticated(t *testing.T) {
	srv := newTestServer()

	body := `{"services":[{"name":"stripe","host":"api.stripe.com","auth":{"type":"bearer","token":"KEY"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- Services Remove Tests ---

func TestServiceRemoveSuccess(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id",
		ServicesJSON: `[{"name":"stripe","host":"api.stripe.com","auth":{"type":"bearer","token":"STRIPE_KEY"}},{"name":"github","host":"api.github.com","auth":{"type":"bearer","token":"GITHUB_TOKEN"}}]`,
	}
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodDelete, "/v1/vaults/default/services/api.stripe.com", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["removed"] != "stripe" {
		t.Fatalf("expected removed=stripe (canonical name), got %v", resp["removed"])
	}
	if resp["removed_host"] != "api.stripe.com" {
		t.Fatalf("expected removed_host=api.stripe.com, got %v", resp["removed_host"])
	}
	if resp["services_count"].(float64) != 1 {
		t.Fatalf("expected services_count=1, got %v", resp["services_count"])
	}

	// Verify the remaining service.
	bc := ms.brokerConfigs["root-ns-id"]
	if strings.Contains(bc.ServicesJSON, "api.stripe.com") {
		t.Fatalf("expected api.stripe.com to be removed, got %s", bc.ServicesJSON)
	}
	if !strings.Contains(bc.ServicesJSON, "api.github.com") {
		t.Fatalf("expected api.github.com to remain, got %s", bc.ServicesJSON)
	}
}

func TestServiceRemoveNotFound(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id",
		ServicesJSON: `[{"name":"stripe","host":"api.stripe.com","auth":{"type":"bearer","token":"STRIPE_KEY"}}]`,
	}
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodDelete, "/v1/vaults/default/services/api.nonexistent.com", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestServiceRemoveNoConfig(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodDelete, "/v1/vaults/default/services/api.stripe.com", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for vault with no services, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestServiceRemoveUnauthenticated(t *testing.T) {
	srv := newTestServer()

	req := httptest.NewRequest(http.MethodDelete, "/v1/vaults/default/services/api.stripe.com", nil)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- no-access instance role tests ---

// setupNoAccessAgentSession creates a no-access agent (not a user) with an
// agent-token session and optional vault grants. Exercises the sess.AgentID
// branch of actorFromSession, which the user-based helper does not cover.
func setupNoAccessAgentSession(t *testing.T, ms *mockStore, grantVaultIDs ...string) string {
	t.Helper()
	ms.agents["scoped-bot"] = &store.Agent{
		ID: "scoped-agent-id", Name: "scoped-bot", Role: "no-access", Status: "active",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	sess := &store.Session{
		ID:        "scoped-agent-session",
		AgentID:   "scoped-agent-id",
		ExpiresAt: tp(time.Now().Add(time.Hour)),
		CreatedAt: time.Now(),
	}
	ms.sessions[sess.ID] = sess
	for _, nsID := range grantVaultIDs {
		ms.GrantVaultRole(context.Background(), "scoped-agent-id", "agent", nsID, "member")
	}
	return sess.ID
}

func setupNoAccessSession(t *testing.T, ms *mockStore, grantVaultIDs ...string) string {
	t.Helper()
	ms.users["scoped@test.com"] = &store.User{
		ID: "scoped-user-id", Email: "scoped@test.com", Role: "no-access", IsActive: true,
	}
	sess := &store.Session{
		ID:        "scoped-session",
		UserID:    "scoped-user-id",
		ExpiresAt: tp(time.Now().Add(time.Hour)),
		CreatedAt: time.Now(),
	}
	ms.sessions[sess.ID] = sess
	for _, nsID := range grantVaultIDs {
		ms.GrantVaultRole(context.Background(), "scoped-user-id", "user", nsID, "member")
	}
	return sess.ID
}

func TestNoAccessActorCannotCreateVault(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	token := setupNoAccessSession(t, ms)
	srv := newTestServer(withStore(ms))

	body := `{"name":"new-vault"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestNoAccessActorCannotCreateUserInvite(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	token := setupNoAccessSession(t, ms)
	srv := newTestServer(withStore(ms))

	body := `{"email":"new@test.com"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/users/invites", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestNoAccessActorCannotListUsers(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	token := setupNoAccessSession(t, ms)
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodGet, "/v1/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestNoAccessActorCannotListAgents(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	token := setupNoAccessSession(t, ms, "root-ns-id")
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodGet, "/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestNoAccessAgentBlockedAtInstanceScope(t *testing.T) {
	// Agents (not just users) at no-access must fail instance-scoped checks.
	// Covers the sess.AgentID path in actorFromSession.
	ms, _ := setupMockStoreWithSession(t)
	token := setupNoAccessAgentSession(t, ms, "root-ns-id")
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodGet, "/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestNoAccessAgentAllowedAtVaultScope(t *testing.T) {
	// Motivating use case: no-access agent's only authority is its vault grant.
	ms, _ := setupMockStoreWithSession(t)
	token := setupNoAccessAgentSession(t, ms, "root-ns-id")
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodGet, "/v1/credentials?vault=default", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestNoAccessActorCannotGetAgent(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	ms.agents["existing-agent"] = &store.Agent{
		ID: "existing-agent-id", Name: "existing-agent", Role: "member", Status: "active",
	}
	token := setupNoAccessSession(t, ms, "root-ns-id")
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodGet, "/v1/agents/existing-agent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestNoAccessActorWithVaultGrantCanReadCredentials(t *testing.T) {
	// The motivating use case: vault-scoped operations work via vault grant alone.
	ms, _ := setupMockStoreWithSession(t)
	token := setupNoAccessSession(t, ms, "root-ns-id")
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodGet, "/v1/credentials?vault=default", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestNoAccessActorCanReadOwnProfile(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	token := setupNoAccessSession(t, ms)
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLastOwnerCannotBeDemotedToNoAccess(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"role":"no-access"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/users/owner@test.com/role", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUserInviteWithNoAccessRoleAccepted(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"email":"new@test.com","role":"no-access"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/users/invites", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- Path-scoped service / route disambiguation tests ---

// TestServiceRemoveByHostAmbiguity exercises the 409-with-candidates
// fallback: when two services share a host, DELETE/PATCH on the host
// slot must not silently target one of them — the server returns 409
// with the candidate names so the caller can pick.
func TestServiceRemoveByHostAmbiguity(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id",
		ServicesJSON: `[
			{"name":"slack-bot","host":"slack.com","path":"/api/*","auth":{"type":"bearer","token":"SLACK_BOT_TOKEN"}},
			{"name":"slack-conn","host":"slack.com","path":"/api/apps.connections.*","auth":{"type":"bearer","token":"SLACK_CONNECTION_TOKEN"}}
		]`,
	}
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodDelete, "/v1/vaults/default/services/slack.com", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	candidates, ok := resp["candidates"].([]interface{})
	if !ok || len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %v", resp["candidates"])
	}
	names := map[string]bool{}
	for _, c := range candidates {
		entry := c.(map[string]interface{})
		names[entry["name"].(string)] = true
	}
	if !names["slack-bot"] || !names["slack-conn"] {
		t.Fatalf("expected both slack-bot and slack-conn in candidates, got %v", names)
	}

	// Ensure neither service was deleted.
	bc := ms.brokerConfigs["root-ns-id"]
	if !strings.Contains(bc.ServicesJSON, "slack-bot") || !strings.Contains(bc.ServicesJSON, "slack-conn") {
		t.Fatalf("expected both services to remain after 409, got %s", bc.ServicesJSON)
	}
}

// TestServiceRemoveByName resolves unambiguously when the slot value
// matches an existing service name. The host shim doesn't fire.
func TestServiceRemoveByName(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id",
		ServicesJSON: `[
			{"name":"slack-bot","host":"slack.com","path":"/api/*","auth":{"type":"bearer","token":"SLACK_BOT_TOKEN"}},
			{"name":"slack-conn","host":"slack.com","path":"/api/apps.connections.*","auth":{"type":"bearer","token":"SLACK_CONNECTION_TOKEN"}}
		]`,
	}
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodDelete, "/v1/vaults/default/services/slack-conn", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["removed"] != "slack-conn" {
		t.Fatalf("expected removed=slack-conn, got %v", resp["removed"])
	}

	// Verify the right service was removed and slack-bot remains.
	bc := ms.brokerConfigs["root-ns-id"]
	if strings.Contains(bc.ServicesJSON, "slack-conn") {
		t.Fatalf("expected slack-conn to be removed, got %s", bc.ServicesJSON)
	}
	if !strings.Contains(bc.ServicesJSON, "slack-bot") {
		t.Fatalf("expected slack-bot to remain, got %s", bc.ServicesJSON)
	}
}

// TestServicePatchByHostAmbiguity mirrors the DELETE 409 path for PATCH:
// the candidate list shape and the no-mutation invariant must both hold.
func TestServicePatchByHostAmbiguity(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id",
		ServicesJSON: `[
			{"name":"slack-bot","host":"slack.com","path":"/api/*","auth":{"type":"bearer","token":"SLACK_BOT_TOKEN"}},
			{"name":"slack-conn","host":"slack.com","path":"/api/apps.connections.*","auth":{"type":"bearer","token":"SLACK_CONNECTION_TOKEN"}}
		]`,
	}
	pre := ms.brokerConfigs["root-ns-id"].ServicesJSON
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodPatch, "/v1/vaults/default/services/slack.com", strings.NewReader(`{"enabled":false}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	candidates, ok := resp["candidates"].([]interface{})
	if !ok || len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %v", resp["candidates"])
	}
	names := map[string]bool{}
	for _, c := range candidates {
		entry := c.(map[string]interface{})
		names[entry["name"].(string)] = true
	}
	if !names["slack-bot"] || !names["slack-conn"] {
		t.Fatalf("expected slack-bot and slack-conn in candidates, got %v", names)
	}
	if ms.brokerConfigs["root-ns-id"].ServicesJSON != pre {
		t.Fatalf("expected services unchanged after 409, got mutation:\nbefore: %s\nafter:  %s", pre, ms.brokerConfigs["root-ns-id"].ServicesJSON)
	}
}

// TestServicePatchByName resolves unambiguously when the slot value
// matches a canonical service name. Verifies the right service is
// patched (not the other one sharing the host) and the response echoes
// the targeted service.
func TestServicePatchByName(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id",
		ServicesJSON: `[
			{"name":"slack-bot","host":"slack.com","path":"/api/*","auth":{"type":"bearer","token":"SLACK_BOT_TOKEN"}},
			{"name":"slack-conn","host":"slack.com","path":"/api/apps.connections.*","auth":{"type":"bearer","token":"SLACK_CONNECTION_TOKEN"}}
		]`,
	}
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodPatch, "/v1/vaults/default/services/slack-conn", strings.NewReader(`{"enabled":false}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["name"] != "slack-conn" {
		t.Fatalf("expected name=slack-conn in response, got %v", resp["name"])
	}
	if resp["enabled"] != false {
		t.Fatalf("expected enabled=false in response, got %v", resp["enabled"])
	}

	// Verify only slack-conn flipped; slack-bot is untouched.
	bc := ms.brokerConfigs["root-ns-id"]
	var stored []map[string]interface{}
	if err := json.Unmarshal([]byte(bc.ServicesJSON), &stored); err != nil {
		t.Fatalf("unmarshal stored: %v", err)
	}
	for _, s := range stored {
		switch s["name"] {
		case "slack-conn":
			if s["enabled"] != false {
				t.Fatalf("expected slack-conn enabled=false, got %v", s["enabled"])
			}
		case "slack-bot":
			if v, present := s["enabled"]; present && v == false {
				t.Fatalf("expected slack-bot untouched, got enabled=%v", v)
			}
		}
	}
}

// TestServicesUpsertSplitsInlineHost lets a client paste `slack.com/api/*`
// into the host field and verifies the round-trip: storage holds the
// joined form (Service.MarshalJSON re-joins Host+Path) and `path` is
// not exposed on the wire.
func TestServicesUpsertSplitsInlineHost(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"name":"slack-bot","host":"slack.com/api/*","auth":{"type":"bearer","token":"SLACK_BOT_TOKEN"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	bc := ms.brokerConfigs["root-ns-id"]
	if !strings.Contains(bc.ServicesJSON, `"host":"slack.com/api/*"`) {
		t.Fatalf("expected host stored as joined form slack.com/api/*, got %s", bc.ServicesJSON)
	}
	if strings.Contains(bc.ServicesJSON, `"path":`) {
		t.Fatalf("path field must not appear on the wire, got %s", bc.ServicesJSON)
	}
	if !strings.Contains(bc.ServicesJSON, `"name":"slack-bot"`) {
		t.Fatalf("expected explicit name slack-bot stored, got %s", bc.ServicesJSON)
	}
}

// TestServicesUpsertExplicitNameMatchingExistingReplaces confirms the
// intended upsert-by-name semantic: if the caller supplies a Name that
// matches an existing service, the upsert replaces that service.
func TestServicesUpsertExplicitNameMatchingExistingReplaces(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id",
		ServicesJSON: `[
			{"name":"slack-bot","host":"slack.com","path":"/api/*","auth":{"type":"bearer","token":"OLD_TOKEN"}}
		]`,
	}
	srv := newTestServer(withStore(ms))

	body := `{"services":[{"name":"slack-bot","host":"slack.com","path":"/api/*","auth":{"type":"bearer","token":"NEW_TOKEN"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["services_count"].(float64) != 1 {
		t.Fatalf("expected services_count=1 (replace, not bump), got %v", resp["services_count"])
	}
	bc := ms.brokerConfigs["root-ns-id"]
	if !strings.Contains(bc.ServicesJSON, `"token":"NEW_TOKEN"`) || strings.Contains(bc.ServicesJSON, `"token":"OLD_TOKEN"`) {
		t.Fatalf("expected explicit-name upsert to replace OLD_TOKEN with NEW_TOKEN, got %s", bc.ServicesJSON)
	}
}

// TestProposalCreateActionSetRejectsMissingNameForNewService pins the
// "name is required for new services" contract on the proposal path:
// an empty-Name ActionSet whose Host does not uniquely match an
// existing service falls through to proposal.Validate which rejects.
func TestProposalCreateActionSetRejectsMissingNameForNewService(t *testing.T) {
	srv, _, token := setupProposalTest(t)

	body := `{
		"services": [{"action":"set","host":"api.stripe.com","auth":{"type":"bearer","token":"STRIPE_KEY"}}],
		"credentials": [{"action":"set","key":"STRIPE_KEY"}],
		"message": "missing name"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proposals", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 (name required for new service), got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "name is required") {
		t.Fatalf("expected error to mention 'name is required', got %s", rec.Body.String())
	}
}

// TestProposalCreateActionSetEmptyNameAdoptsExistingByHostPath pins
// the proposal-flow same-host rename heal: an empty-Name ActionSet
// targeting a host already owned by a renamed service (`stripe-prod`)
// adopts the existing Name on the proposal record. Without this, the
// proposal would persist `name:"api-stripe-com"`, MergeServices would
// fail the Name-lookup, and apply would append an unreachable ghost.
func TestProposalCreateActionSetEmptyNameAdoptsExistingByHostPath(t *testing.T) {
	srv, ms, token := setupProposalTest(t)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id",
		ServicesJSON: `[{"name":"stripe-prod","host":"api.stripe.com","auth":{"type":"bearer","token":"OLD_KEY"}}]`,
	}

	body := `{
		"services": [{"action":"set","host":"api.stripe.com","auth":{"type":"bearer","token":"NEW_KEY"}}],
		"credentials": [{"action":"set","key":"NEW_KEY"}],
		"message": "rotate"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proposals", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	props := ms.proposals["root-ns-id"]
	if len(props) != 1 {
		t.Fatalf("expected 1 proposal, got %d", len(props))
	}
	if !strings.Contains(props[0].ServicesJSON, `"name":"stripe-prod"`) {
		t.Fatalf("expected proposal services_json to adopt stripe-prod, got %s", props[0].ServicesJSON)
	}
	if strings.Contains(props[0].ServicesJSON, "api-stripe-com") {
		t.Fatalf("expected no auto-slug fallback, got %s", props[0].ServicesJSON)
	}
}

// TestAdminProposalApplyRebindsStaleNameByHost pins the create→
// rename→apply rebind. A proposal whose Name was correct at create
// (adopted from the legacy heal of host api.stripe.com → api-stripe-com)
// becomes stale when the admin renames the existing service to
// stripe-prod before approving. At apply, normalize must rebind by
// (Host, Path) so MergeServices upserts stripe-prod with the new
// auth — instead of appending an unreachable ghost.
func TestAdminProposalApplyRebindsStaleNameByHost(t *testing.T) {
	ms := newMockStore()

	ms.users["owner@test.com"] = &store.User{
		ID: "owner-user-id", Email: "owner@test.com", Role: "owner", IsActive: true,
	}
	ms.GrantVaultRole(context.Background(), "owner-user-id", "user", "root-ns-id", "admin")
	adminSess := &store.Session{
		ID: "admin-session", UserID: "owner-user-id",
		ExpiresAt: tp(time.Now().Add(time.Hour)), CreatedAt: time.Now(),
	}
	ms.sessions[adminSess.ID] = adminSess
	srv := newTestServer(withStore(ms), withEncKey(make([]byte, 32)))

	// Existing service was renamed (e.g. via Edit Service sidebar) from
	// the heal-derived `api-stripe-com` to a friendlier `stripe-prod`.
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		VaultID: "root-ns-id",
		ServicesJSON: `[
			{"name":"stripe-prod","host":"api.stripe.com","auth":{"type":"bearer","token":"OLD_KEY"}}
		]`,
	}
	// Pending proposal carries the pre-rename Name (api-stripe-com)
	// because it was adopted from the legacy heal at create time.
	ms.proposals = make(map[string][]store.Proposal)
	ms.proposals["root-ns-id"] = []store.Proposal{{
		ID: 1, VaultID: "root-ns-id", Status: "pending",
		ServicesJSON:    `[{"action":"set","name":"api-stripe-com","host":"api.stripe.com","auth":{"type":"bearer","token":"NEW_KEY"}}]`,
		CredentialsJSON: `[{"action":"set","key":"NEW_KEY","description":"Stripe key"}]`,
		Message:         "Rotate Stripe key",
		CreatedAt:       time.Now(),
	}}

	body := `{"vault":"default","credentials":{"NEW_KEY":"credential_value"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/proposals/1/approve", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminSess.ID)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (rebind by host succeeds), got %d: %s", rec.Code, rec.Body.String())
	}
	merged := ms.brokerConfigs["root-ns-id"].ServicesJSON
	if !strings.Contains(merged, `"name":"stripe-prod"`) {
		t.Fatalf("expected merged config to keep stripe-prod, got %s", merged)
	}
	if !strings.Contains(merged, `"token":"NEW_KEY"`) {
		t.Fatalf("expected stripe-prod rotated to NEW_KEY, got %s", merged)
	}
	if strings.Contains(merged, `"token":"OLD_KEY"`) {
		t.Fatalf("expected OLD_KEY replaced, got %s", merged)
	}
	if strings.Contains(merged, `"name":"api-stripe-com"`) {
		t.Fatalf("expected no api-stripe-com ghost entry, got %s", merged)
	}
}

// TestProposalCreateActionSetEmptyNameUnrelatedHostRejects pins that
// an empty-Name ActionSet whose Host does not uniquely match an
// existing service (e.g. the wildcard owns `*.github.com`, incoming
// is bare `github.com`) is rejected as "name is required" instead of
// silently overwriting the wildcard via cross-host slug collision.
func TestProposalCreateActionSetEmptyNameUnrelatedHostRejects(t *testing.T) {
	srv, ms, token := setupProposalTest(t)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id",
		ServicesJSON: `[{"name":"github-com","host":"*.github.com","auth":{"type":"bearer","token":"WILDCARD_TOKEN"}}]`,
	}

	body := `{
		"services": [{"action":"set","host":"github.com","auth":{"type":"bearer","token":"BARE_TOKEN"}}],
		"credentials": [{"action":"set","key":"BARE_TOKEN"}],
		"message": "add bare github"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proposals", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 (name required, no unique host match), got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "name is required") {
		t.Fatalf("expected error to mention 'name is required', got %s", rec.Body.String())
	}
}

// TestProposalCreateActionDeleteUnknownHostReturnsNotFound pins that a
// delete-action with no Name and 0 host matches surfaces a 404 with a
// clear "no service matches host" message rather than silently
// touching an unrelated service.
func TestProposalCreateActionDeleteUnknownHostReturnsNotFound(t *testing.T) {
	srv, ms, token := setupProposalTest(t)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id",
		ServicesJSON: `[
			{"name":"unrelated","host":"unrelated.example","auth":{"type":"bearer","token":"K"}}
		]`,
	}

	body := `{
		"services": [{"action":"delete","host":"ghost.example.com"}],
		"message": "tidy"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proposals", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 (host not found), got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "no service matches host") {
		t.Fatalf("expected host-not-found error, got %s", rec.Body.String())
	}

	// Ensure the unrelated service was not touched.
	bc := ms.brokerConfigs["root-ns-id"]
	if !strings.Contains(bc.ServicesJSON, `"name":"unrelated"`) {
		t.Fatalf("expected unrelated service to remain, got %s", bc.ServicesJSON)
	}
}

// TestProposalCreateActionDeleteInlineFormNarrowsByPath pins that an
// unnamed delete with an inline-form host (`slack.com/api/*`) resolves
// to the exact (Host, Path) match instead of 409'ing against unrelated
// path siblings on the same host. Without this narrowing the user would
// be forced to fall back to the canonical Name even though the inline
// form already uniquely identifies the target.
func TestProposalCreateActionDeleteInlineFormNarrowsByPath(t *testing.T) {
	srv, ms, token := setupProposalTest(t)
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		ID: "bc-1", VaultID: "root-ns-id",
		ServicesJSON: `[
			{"name":"slack-bot","host":"slack.com","path":"/api/*","auth":{"type":"bearer","token":"SLACK_BOT_TOKEN"}},
			{"name":"slack-conn","host":"slack.com","path":"/api/apps.connections.*","auth":{"type":"bearer","token":"SLACK_CONNECTION_TOKEN"}}
		]`,
	}

	body := `{
		"services": [{"action":"delete","host":"slack.com/api/apps.connections.*"}],
		"message": "drop socket-mode token"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proposals", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 (inline form unambiguously targets slack-conn), got %d: %s", rec.Code, rec.Body.String())
	}

	// Confirm the proposal was stored with Name=slack-conn adopted from
	// the unique (Host, Path) match, not slack-bot.
	props := ms.proposals["root-ns-id"]
	if len(props) != 1 {
		t.Fatalf("expected 1 proposal, got %d", len(props))
	}
	var stored []map[string]interface{}
	if err := json.Unmarshal([]byte(props[0].ServicesJSON), &stored); err != nil {
		t.Fatalf("unmarshal stored proposal services: %v", err)
	}
	if len(stored) != 1 || stored[0]["name"] != "slack-conn" {
		t.Fatalf("expected stored proposal to adopt Name=slack-conn, got %v", stored)
	}
}

// TestServicesGetReturnsJoinedHostNoPathField pins the wire shape on
// the read surface: GET /v1/vaults/{name}/services emits Host in joined
// inline form (`slack.com/api/*`) and never includes the legacy `path`
// field, even when the persisted record uses split form (the legacy
// shape from before MarshalJSON joined them). Both the joined-form
// emission AND the defensive split-on-load are exercised.
func TestServicesGetReturnsJoinedHostNoPathField(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	// Seed storage with the legacy split form to prove loadServices's
	// defensive SplitInlineHost handles older records correctly. After
	// this PR, new writes persist the joined form via MarshalJSON; this
	// test covers the migration window.
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		VaultID: "root-ns-id",
		ServicesJSON: `[
			{"name":"slack-bot","host":"slack.com","path":"/api/*","auth":{"type":"bearer","token":"SLACK_BOT_TOKEN"}},
			{"name":"stripe","host":"api.stripe.com","auth":{"type":"bearer","token":"STRIPE_KEY"}}
		]`,
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/vaults/default/services", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"host":"slack.com/api/*"`) {
		t.Fatalf("expected joined-form host slack.com/api/*, got %s", body)
	}
	if !strings.Contains(body, `"host":"api.stripe.com"`) {
		t.Fatalf("expected bare-host stripe entry untouched, got %s", body)
	}
	if strings.Contains(body, `"path":`) {
		t.Fatalf("path field must not appear on the read surface, got %s", body)
	}
}

// TestAdminProposalApproveRejects409OnAmbiguousDelete pins the
// apply-time counterpart of normalizeProposalServices's host-ambiguity
// check: a stale ActionDelete proposal with no Name whose host matches
// 2+ existing services must surface 409 + candidates rather than
// silently picking one. The create path tests this; this is the
// apply-path twin so a pre-PR proposal stored with no Name can't slip
// through and cause arbitrary deletion at approval time.
func TestAdminProposalApproveRejects409OnAmbiguousDelete(t *testing.T) {
	ms := newMockStore()

	ms.users["owner@test.com"] = &store.User{
		ID: "owner-user-id", Email: "owner@test.com", Role: "owner", IsActive: true,
	}
	ms.GrantVaultRole(context.Background(), "owner-user-id", "user", "root-ns-id", "admin")
	adminSess := &store.Session{
		ID: "admin-session", UserID: "owner-user-id",
		ExpiresAt: tp(time.Now().Add(time.Hour)), CreatedAt: time.Now(),
	}
	ms.sessions[adminSess.ID] = adminSess
	srv := newTestServer(withStore(ms), withEncKey(make([]byte, 32)))

	// Two services share host=slack.com but scope to different paths.
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		VaultID: "root-ns-id",
		ServicesJSON: `[
			{"name":"slack-bot","host":"slack.com","path":"/api/*","auth":{"type":"bearer","token":"SLACK_BOT"}},
			{"name":"slack-conn","host":"slack.com","path":"/api/apps.connections.*","auth":{"type":"bearer","token":"SLACK_CONN"}}
		]`,
	}
	// Stale pre-PR delete proposal: targets slack.com with no Name.
	ms.proposals = make(map[string][]store.Proposal)
	ms.proposals["root-ns-id"] = []store.Proposal{{
		ID: 1, VaultID: "root-ns-id", Status: "pending",
		ServicesJSON:    `[{"action":"delete","host":"slack.com"}]`,
		CredentialsJSON: `[]`,
		Message:         "remove slack",
		CreatedAt:       time.Now(),
	}}

	body := `{"vault":"default","credentials":{}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/proposals/1/approve", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminSess.ID)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 (ambiguous delete), got %d: %s", rec.Code, rec.Body.String())
	}
	respBody := rec.Body.String()
	if !strings.Contains(respBody, "candidates") {
		t.Fatalf("expected candidates array in 409 body, got %s", respBody)
	}
	// Both services must survive untouched.
	merged := ms.brokerConfigs["root-ns-id"].ServicesJSON
	if !strings.Contains(merged, `"token":"SLACK_BOT"`) || !strings.Contains(merged, `"token":"SLACK_CONN"`) {
		t.Fatalf("expected both Slack services to survive ambiguous delete, got %s", merged)
	}
}

// TestSPACatchAllRoutes asserts every top-level frontend route serves index.html.
func TestSPACatchAllRoutes(t *testing.T) {
	srv := newTestServer()

	// /invite/{token} is omitted: Go's ServeMux prefers the API handler's
	// single-segment pattern over the SPA's {token...}, so a 404 there
	// wouldn't indicate an SPA fallback bug.
	paths := []string{
		"/",
		"/login",
		"/register",
		"/forgot-password",
		"/users",
		"/agents",
		"/change-password",
		"/account/settings",
		"/manage/settings",
		"/vaults/",
		"/vaults/default",
		"/approve/1",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, p, nil)
			rec := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(rec, req)
			if rec.Code == http.StatusNotFound {
				t.Fatalf("expected non-404 for SPA route, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}

	t.Run("unknown path stays 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/definitely-not-a-route", nil)
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for unregistered path, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}
