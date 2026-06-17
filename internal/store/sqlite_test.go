package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func tp(t time.Time) *time.Time { return &t }

func openTestDB(t *testing.T) *SQLStore {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open(:memory:): %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenAndMigrate(t *testing.T) {
	s := openTestDB(t)

	// Verify schema_migrations has migrations applied (new format uses name-based tracking).
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if err != nil {
		t.Fatalf("querying schema_migrations: %v", err)
	}
	if count < 50 {
		t.Fatalf("expected at least 50 migrations applied, got %d", count)
	}

	// Verify the new format has id, name, migration_time columns.
	var name string
	err = s.db.QueryRow("SELECT name FROM schema_migrations WHERE id = 1").Scan(&name)
	if err != nil {
		t.Fatalf("querying name column: %v", err)
	}
	if name != "001_init" {
		t.Fatalf("expected first migration name '001_init', got %q", name)
	}
}

func TestMigrationIdempotency(t *testing.T) {
	// Opening twice against the same DB should not fail.
	dbPath := filepath.Join(t.TempDir(), "idempotency.db")
	s1, err := Open(dbPath)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	_ = s1.Close()

	// Second open on the same file should succeed without re-running migrations.
	s2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	_ = s2.Close()
}

// --- Vault CRUD ---

func TestVaultCRUD(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	// Create
	ns, err := s.CreateVault(ctx, "prod")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if ns.Name != "prod" || ns.ID == "" {
		t.Fatalf("unexpected vault: %+v", ns)
	}

	// Get
	got, err := s.GetVault(ctx, "prod")
	if err != nil {
		t.Fatalf("GetVault: %v", err)
	}
	if got.ID != ns.ID {
		t.Fatalf("expected ID %s, got %s", ns.ID, got.ID)
	}

	// List (includes seeded default vault)
	list, err := s.ListVaults(ctx)
	if err != nil {
		t.Fatalf("ListVaults: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 vaults (root + prod), got %d", len(list))
	}

	// Delete
	if err := s.DeleteVault(ctx, "prod"); err != nil {
		t.Fatalf("DeleteVault: %v", err)
	}
	list, _ = s.ListVaults(ctx)
	if len(list) != 1 || list[0].Name != "default" {
		t.Fatalf("expected only default vault after delete, got %+v", list)
	}
}

func TestVaultDuplicateName(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	if _, err := s.CreateVault(ctx, "dup"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateVault(ctx, "dup"); err == nil {
		t.Fatal("expected error for duplicate vault name")
	}
}

func TestGetVaultNotFound(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	_, err := s.GetVault(ctx, "nope")
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestGetVaultByID(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, err := s.CreateVault(ctx, "byid-test")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	got, err := s.GetVaultByID(ctx, ns.ID)
	if err != nil {
		t.Fatalf("GetVaultByID: %v", err)
	}
	if got.Name != "byid-test" {
		t.Fatalf("expected name 'byid-test', got %q", got.Name)
	}
}

func TestGetVaultByIDNotFound(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	_, err := s.GetVaultByID(ctx, "nonexistent-id")
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestDeleteVaultNotFound(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	err := s.DeleteVault(ctx, "nope")
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestRenameVault(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	v, err := s.CreateVault(ctx, "oldvault")
	if err != nil {
		t.Fatal(err)
	}

	err = s.RenameVault(ctx, "oldvault", "newvault")
	if err != nil {
		t.Fatalf("RenameVault: %v", err)
	}

	renamed, err := s.GetVault(ctx, "newvault")
	if err != nil {
		t.Fatalf("expected new name to exist: %v", err)
	}
	if renamed.ID != v.ID {
		t.Fatalf("expected same ID after rename")
	}

	_, err = s.GetVault(ctx, "oldvault")
	if err != sql.ErrNoRows {
		t.Fatal("expected old name to not be found")
	}
}

func TestRenameVaultNotFound(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	err := s.RenameVault(ctx, "nonexistent", "newname")
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestRenameVaultDuplicate(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	s.CreateVault(ctx, "vault-a")
	s.CreateVault(ctx, "vault-b")

	err := s.RenameVault(ctx, "vault-a", "vault-b")
	if err == nil {
		t.Fatal("expected error when renaming to existing name")
	}
}

// --- Credential CRUD ---

func TestCredentialCRUD(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, err := s.CreateVault(ctx, "myns")
	if err != nil {
		t.Fatal(err)
	}

	ct := []byte("encrypted-value")
	nonce := []byte("random-nonce")

	// Set
	cred, err := s.SetCredential(ctx, ns.ID, "API_KEY", ct, nonce)
	if err != nil {
		t.Fatalf("SetCredential: %v", err)
	}
	if cred.Key != "API_KEY" {
		t.Fatalf("unexpected key: %s", cred.Key)
	}

	// Get
	got, err := s.GetCredential(ctx, ns.ID, "API_KEY")
	if err != nil {
		t.Fatalf("GetCredential: %v", err)
	}
	if string(got.Ciphertext) != "encrypted-value" || string(got.Nonce) != "random-nonce" {
		t.Fatalf("unexpected credential data: ct=%q nonce=%q", got.Ciphertext, got.Nonce)
	}

	// List
	list, err := s.ListCredentials(ctx, ns.ID)
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(list))
	}

	// Delete
	if err := s.DeleteCredential(ctx, ns.ID, "API_KEY"); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}
	_, err = s.GetCredential(ctx, ns.ID, "API_KEY")
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows after delete, got %v", err)
	}
}

func TestSetCredentialUpsert(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.CreateVault(ctx, "ns")

	// Set twice with same key, should upsert.
	s.SetCredential(ctx, ns.ID, "KEY", []byte("v1"), []byte("n1"))
	s.SetCredential(ctx, ns.ID, "KEY", []byte("v2"), []byte("n2"))

	got, err := s.GetCredential(ctx, ns.ID, "KEY")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Ciphertext) != "v2" {
		t.Fatalf("expected upserted value v2, got %q", got.Ciphertext)
	}
}

func TestCascadeDeleteVaultRemovesCredentials(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.CreateVault(ctx, "cascade")
	s.SetCredential(ctx, ns.ID, "S1", []byte("a"), []byte("b"))
	s.SetCredential(ctx, ns.ID, "S2", []byte("c"), []byte("d"))

	if err := s.DeleteVault(ctx, "cascade"); err != nil {
		t.Fatal(err)
	}

	list, err := s.ListCredentials(ctx, ns.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("expected 0 credentials after cascade delete, got %d", len(list))
	}
}

// --- Session CRUD ---

func TestSessionCRUD(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, _ := s.CreateUser(ctx, "session-crud@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)
	expires := time.Now().Add(1 * time.Hour).UTC().Truncate(time.Second)

	sess, err := s.CreateUserSession(ctx, CreateUserSessionParams{UserID: u.ID, ExpiresAt: expires})
	if err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}
	if sess.ID == "" {
		t.Fatal("expected non-empty session ID")
	}

	got, err := s.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(expires) {
		t.Fatalf("expected ExpiresAt %v, got %v", expires, got.ExpiresAt)
	}

	if err := s.DeleteSession(ctx, sess.ID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	_, err = s.GetSession(ctx, sess.ID)
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows after delete, got %v", err)
	}
}

func TestScopedSessionCRUD(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	// Use the seeded root vault
	ns, err := s.GetVault(ctx, "default")
	if err != nil {
		t.Fatalf("GetVault: %v", err)
	}

	expires := time.Now().Add(1 * time.Hour).UTC().Truncate(time.Second)

	sess, err := s.CreateScopedSession(ctx, CreateScopedSessionParams{
		VaultID:   ns.ID,
		VaultRole: "proxy",
		ExpiresAt: &expires,
	})
	if err != nil {
		t.Fatalf("CreateScopedSession: %v", err)
	}
	if sess.ID == "" {
		t.Fatal("expected non-empty session ID")
	}
	if sess.VaultID != ns.ID {
		t.Fatalf("expected VaultID %s, got %s", ns.ID, sess.VaultID)
	}

	got, err := s.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.VaultID != ns.ID {
		t.Fatalf("expected VaultID %s on get, got %s", ns.ID, got.VaultID)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(expires) {
		t.Fatalf("expected ExpiresAt %v, got %v", expires, got.ExpiresAt)
	}
}

func TestDeleteUserCascadesScopedTokensMintedByUser(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.GetVault(ctx, "default")
	u, err := s.CreateUser(ctx, "minter@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	keeper, err := s.CreateUser(ctx, "keeper@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)
	if err != nil {
		t.Fatalf("CreateUser keeper: %v", err)
	}

	// Token minted by `u`.
	mintedByU, err := s.CreateScopedSession(ctx, CreateScopedSessionParams{
		VaultID:            ns.ID,
		VaultRole:          "proxy",
		ExpiresAt:          tp(time.Now().Add(time.Hour)),
		CreatedByActorID:   u.ID,
		CreatedByActorType: "user",
	})
	if err != nil {
		t.Fatalf("CreateScopedSession u: %v", err)
	}
	// Token minted by `keeper` — must survive `u`'s deletion.
	mintedByKeeper, err := s.CreateScopedSession(ctx, CreateScopedSessionParams{
		VaultID:            ns.ID,
		VaultRole:          "proxy",
		ExpiresAt:          tp(time.Now().Add(time.Hour)),
		CreatedByActorID:   keeper.ID,
		CreatedByActorType: "user",
	})
	if err != nil {
		t.Fatalf("CreateScopedSession keeper: %v", err)
	}

	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	if got, _ := s.GetSession(ctx, mintedByU.ID); got != nil {
		t.Fatal("expected u's minted token to be cascaded away")
	}
	if got, err := s.GetSession(ctx, mintedByKeeper.ID); err != nil || got == nil {
		t.Fatalf("expected keeper's token to survive: got=%v err=%v", got, err)
	}
}

func TestRevokeAgentCascadesScopedTokensMintedByAgent(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.GetVault(ctx, "default")
	agent, err := s.CreateAgent(ctx, "minter-agent", "system", "member")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	// Agent's own auth token (agent_id = agent.ID).
	agentToken, err := s.CreateAgentToken(ctx, agent.ID, tp(time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatalf("CreateAgentToken: %v", err)
	}
	// Scoped token the agent minted on behalf of itself for a child process.
	mintedByAgent, err := s.CreateScopedSession(ctx, CreateScopedSessionParams{
		VaultID:            ns.ID,
		VaultRole:          "proxy",
		ExpiresAt:          tp(time.Now().Add(time.Hour)),
		CreatedByActorID:   agent.ID,
		CreatedByActorType: "agent",
	})
	if err != nil {
		t.Fatalf("CreateScopedSession: %v", err)
	}

	if err := s.RevokeAgent(ctx, agent.ID); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}

	if got, _ := s.GetSession(ctx, agentToken.ID); got != nil {
		t.Fatal("expected agent token to be cascaded away")
	}
	if got, _ := s.GetSession(ctx, mintedByAgent.ID); got != nil {
		t.Fatal("expected scoped token minted by agent to be cascaded away")
	}
}

func TestListAndRevokeScopedSessions(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, err := s.GetVault(ctx, "default")
	if err != nil {
		t.Fatalf("GetVault: %v", err)
	}

	// Mint two scoped sessions in `default` and one in a second vault to
	// confirm vault scoping in both list and revoke.
	other, err := s.CreateVault(ctx, "other")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	first, err := s.CreateScopedSession(ctx, CreateScopedSessionParams{
		VaultID:            ns.ID,
		VaultRole:          "proxy",
		ExpiresAt:          tp(time.Now().Add(time.Hour)),
		Label:              "ci-bot",
		CreatedByActorID:   "user-1",
		CreatedByActorType: "user",
	})
	if err != nil {
		t.Fatalf("CreateScopedSession default#1: %v", err)
	}
	// Sleep 1s so the second row sorts strictly after the first by created_at
	// (sqlite's datetime resolution is per-second).
	time.Sleep(1100 * time.Millisecond)
	second, err := s.CreateScopedSession(ctx, CreateScopedSessionParams{
		VaultID:   ns.ID,
		VaultRole: "member",
		ExpiresAt: tp(time.Now().Add(time.Hour)),
	})
	if err != nil {
		t.Fatalf("CreateScopedSession default#2: %v", err)
	}
	if _, err := s.CreateScopedSession(ctx, CreateScopedSessionParams{
		VaultID:   other.ID,
		VaultRole: "proxy",
		ExpiresAt: tp(time.Now().Add(time.Hour)),
	}); err != nil {
		t.Fatalf("CreateScopedSession other: %v", err)
	}

	rows, err := s.ListScopedSessionsByVault(ctx, ns.ID)
	if err != nil {
		t.Fatalf("ListScopedSessionsByVault: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows scoped to default, got %d", len(rows))
	}
	if rows[0].PublicID != second.PublicID || rows[1].PublicID != first.PublicID {
		t.Fatalf("expected newest-first ordering: %s,%s — got %s,%s",
			second.PublicID, first.PublicID, rows[0].PublicID, rows[1].PublicID)
	}
	if rows[1].Label != "ci-bot" {
		t.Fatalf("expected label 'ci-bot' on first row, got %q", rows[1].Label)
	}
	if rows[1].CreatedByActorID != "user-1" || rows[1].CreatedByActorType != "user" {
		t.Fatalf("expected created_by user/user-1, got %s/%s",
			rows[1].CreatedByActorType, rows[1].CreatedByActorID)
	}

	// Cross-vault revoke must fail (publicID belongs to default, not other).
	if err := s.RevokeScopedSession(ctx, other.ID, first.PublicID); err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows on cross-vault revoke, got %v", err)
	}

	// Same-vault revoke succeeds and removes the row from list.
	if err := s.RevokeScopedSession(ctx, ns.ID, first.PublicID); err != nil {
		t.Fatalf("RevokeScopedSession: %v", err)
	}
	rows, err = s.ListScopedSessionsByVault(ctx, ns.ID)
	if err != nil {
		t.Fatalf("ListScopedSessionsByVault after revoke: %v", err)
	}
	if len(rows) != 1 || rows[0].PublicID != second.PublicID {
		t.Fatalf("expected only second row to remain, got %+v", rows)
	}

	// Re-revoke is a no-op (sql.ErrNoRows).
	if err := s.RevokeScopedSession(ctx, ns.ID, first.PublicID); err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows on second revoke, got %v", err)
	}
}

func TestListScopedSessionsExcludesExpiredAndUserRows(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.GetVault(ctx, "default")

	// Active scoped row → included.
	active, _ := s.CreateScopedSession(ctx, CreateScopedSessionParams{
		VaultID:   ns.ID,
		VaultRole: "proxy",
		ExpiresAt: tp(time.Now().Add(time.Hour)),
	})

	// Expired scoped row → excluded by the SQL filter.
	if _, err := s.CreateScopedSession(ctx, CreateScopedSessionParams{
		VaultID:   ns.ID,
		VaultRole: "proxy",
		ExpiresAt: tp(time.Now().Add(-time.Hour)),
	}); err != nil {
		t.Fatalf("CreateScopedSession (expired): %v", err)
	}

	// User-login row that happens to carry the same vault_id (none today, but
	// the list query must defend against future cross-pollution by filtering
	// user_id IS NULL AND agent_id IS NULL).
	u, _ := s.CreateUser(ctx, "scoped-list@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)
	if _, err := s.CreateUserSession(ctx, CreateUserSessionParams{
		UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}

	rows, err := s.ListScopedSessionsByVault(ctx, ns.ID)
	if err != nil {
		t.Fatalf("ListScopedSessionsByVault: %v", err)
	}
	if len(rows) != 1 || rows[0].PublicID != active.PublicID {
		t.Fatalf("expected only the active scoped row, got %+v", rows)
	}
}

func TestGlobalSessionHasEmptyVaultID(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, _ := s.CreateUser(ctx, "global-session@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)
	expires := time.Now().Add(1 * time.Hour).UTC().Truncate(time.Second)
	sess, err := s.CreateUserSession(ctx, CreateUserSessionParams{UserID: u.ID, ExpiresAt: expires})
	if err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}

	got, err := s.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.VaultID != "" {
		t.Fatalf("expected empty VaultID for global session, got %q", got.VaultID)
	}
}

func TestDeleteSessionNotFound(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	err := s.DeleteSession(ctx, "nonexistent")
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestSessionIsExpired(t *testing.T) {
	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	cases := []struct {
		name string
		sess Session
		want bool
	}{
		{"never expires", Session{}, false},
		{"absolute future", Session{ExpiresAt: &future}, false},
		{"absolute past", Session{ExpiresAt: &past}, true},
		{"idle within window", Session{IdleTTL: time.Hour, LastUsedAt: ptrTime(now.Add(-30 * time.Minute))}, false},
		{"idle past window", Session{IdleTTL: time.Minute, LastUsedAt: ptrTime(now.Add(-time.Hour))}, true},
		{"idle ttl zero ignored", Session{IdleTTL: 0, LastUsedAt: ptrTime(now.Add(-365 * 24 * time.Hour))}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.sess.IsExpired(now); got != tc.want {
				t.Fatalf("IsExpired = %v, want %v", got, tc.want)
			}
		})
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

func TestCreateUserSessionPopulatesMetadata(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, _ := s.CreateUser(ctx, "meta@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)
	exp := time.Now().Add(365 * 24 * time.Hour).UTC().Truncate(time.Second)
	sess, err := s.CreateUserSession(ctx, CreateUserSessionParams{
		UserID:        u.ID,
		ExpiresAt:     exp,
		IdleTTL:       30 * 24 * time.Hour,
		DeviceLabel:   "tony-mbp",
		LastIP:        "127.0.0.1",
		LastUserAgent: "agent-vault-cli/0.4",
	})
	if err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}
	if sess.PublicID == "" {
		t.Fatal("expected PublicID to be populated")
	}
	got, err := s.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.DeviceLabel != "tony-mbp" || got.LastIP != "127.0.0.1" || got.LastUserAgent != "agent-vault-cli/0.4" {
		t.Fatalf("metadata round-trip mismatch: %+v", got)
	}
	if got.IdleTTL != 30*24*time.Hour {
		t.Fatalf("expected IdleTTL %v, got %v", 30*24*time.Hour, got.IdleTTL)
	}
	if got.PublicID != sess.PublicID {
		t.Fatalf("PublicID mismatch: %q vs %q", got.PublicID, sess.PublicID)
	}
	if got.LastUsedAt == nil {
		t.Fatal("expected LastUsedAt to be populated on creation")
	}
}

func TestTouchSessionThrottlesAndAdvances(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, _ := s.CreateUser(ctx, "touch@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)
	sess, _ := s.CreateUserSession(ctx, CreateUserSessionParams{
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(time.Hour),
		IdleTTL:   30 * 24 * time.Hour,
	})

	// Force last_used_at far enough in the past that a touch will succeed.
	if _, err := s.db.ExecContext(ctx,
		"UPDATE sessions SET last_used_at = ? WHERE user_id = ?",
		time.Now().Add(-2*time.Hour).UTC().Format(time.DateTime), u.ID,
	); err != nil {
		t.Fatalf("forcing last_used_at: %v", err)
	}

	if err := s.TouchSession(ctx, sess.ID, "10.0.0.1", "agent-vault-cli/test"); err != nil {
		t.Fatalf("TouchSession: %v", err)
	}

	got, err := s.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.LastUsedAt == nil {
		t.Fatal("LastUsedAt should be populated after Touch")
	}
	if time.Since(*got.LastUsedAt) > time.Minute {
		t.Fatalf("LastUsedAt should be ~now after Touch, got %v ago", time.Since(*got.LastUsedAt))
	}
	if got.LastIP != "10.0.0.1" || got.LastUserAgent != "agent-vault-cli/test" {
		t.Fatalf("touch should refresh last_ip/last_user_agent, got ip=%q ua=%q", got.LastIP, got.LastUserAgent)
	}

	// Throttle: a second touch within TouchInterval is a no-op, and
	// non-empty ip/ua args still don't bleed through the throttle.
	frozen := *got.LastUsedAt
	if err := s.TouchSession(ctx, sess.ID, "10.0.0.99", "other-agent"); err != nil {
		t.Fatalf("TouchSession (second): %v", err)
	}
	got2, _ := s.GetSession(ctx, sess.ID)
	if !got2.LastUsedAt.Equal(frozen) {
		t.Fatalf("expected throttled write to leave last_used_at = %v, got %v", frozen, got2.LastUsedAt)
	}
	if got2.LastIP != "10.0.0.1" {
		t.Fatalf("throttled touch must not overwrite last_ip, got %q", got2.LastIP)
	}

	// Empty ip/ua leaves existing values untouched even when the
	// throttle window expires.
	if _, err := s.db.ExecContext(ctx,
		"UPDATE sessions SET last_used_at = ? WHERE id = ?",
		time.Now().Add(-2*time.Hour).UTC().Format(time.DateTime), hashSessionToken(sess.ID),
	); err != nil {
		t.Fatalf("forcing last_used_at: %v", err)
	}
	if err := s.TouchSession(ctx, sess.ID, "", ""); err != nil {
		t.Fatalf("TouchSession (empty ip/ua): %v", err)
	}
	got3, _ := s.GetSession(ctx, sess.ID)
	if got3.LastIP != "10.0.0.1" || got3.LastUserAgent != "agent-vault-cli/test" {
		t.Fatalf("empty ip/ua should preserve previous values, got ip=%q ua=%q", got3.LastIP, got3.LastUserAgent)
	}
}

func TestListAndRevokeUserSessions(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, _ := s.CreateUser(ctx, "multi@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)
	a, _ := s.CreateUserSession(ctx, CreateUserSessionParams{UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour), DeviceLabel: "a"})
	b, _ := s.CreateUserSession(ctx, CreateUserSessionParams{UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour), DeviceLabel: "b"})

	rows, err := s.ListUserSessions(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListUserSessions: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(rows))
	}

	// Revoke "a" by its public id.
	if err := s.RevokeUserSession(ctx, u.ID, a.PublicID); err != nil {
		t.Fatalf("RevokeUserSession: %v", err)
	}
	if _, err := s.GetSession(ctx, a.ID); err != sql.ErrNoRows {
		t.Fatalf("expected revoked session to be gone, got %v", err)
	}
	if _, err := s.GetSession(ctx, b.ID); err != nil {
		t.Fatalf("other session should still exist: %v", err)
	}

	// Revoke twice → ErrNoRows.
	if err := s.RevokeUserSession(ctx, u.ID, a.PublicID); err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows on second revoke, got %v", err)
	}

	// Cross-account revoke is a no-op (returns ErrNoRows).
	other, _ := s.CreateUser(ctx, "other@test.com", []byte("h"), []byte("s"), "member", 3, 65536, 4)
	if err := s.RevokeUserSession(ctx, other.ID, b.PublicID); err != sql.ErrNoRows {
		t.Fatalf("cross-account revoke should be ErrNoRows, got %v", err)
	}
	if _, err := s.GetSession(ctx, b.ID); err != nil {
		t.Fatalf("session should still exist after cross-account revoke attempt: %v", err)
	}
}

// TestPreMigrationSessionStillUsable simulates a session row created before
// migration 040 — populated id/user_id/expires_at, NULL on the columns
// added by 040 except for public_id (backfilled by the migration's UPDATE).
// It must continue to authenticate, enumerate, and revoke without
// requiring the user to re-login.
func TestPreMigrationSessionStillUsable(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, _ := s.CreateUser(ctx, "legacy@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)

	// Forge a row that looks like one minted by the pre-040 server: just
	// id/user_id/expires_at/created_at, no idle_ttl, no last_used_at, but
	// with the backfilled public_id the migration would have written.
	rawToken := "av_sess_legacy_test_token_value_with_padding_to_64_chars_xxxxxxx"
	tokenHash := hashSessionToken(rawToken)
	expiresAt := time.Now().Add(time.Hour).UTC().Format(time.DateTime)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, expires_at, created_at, public_id)
		 VALUES (?, ?, ?, datetime('now'), ?)`,
		tokenHash, u.ID, expiresAt, "legacypub01",
	)
	if err != nil {
		t.Fatalf("forging legacy session row: %v", err)
	}

	got, err := s.GetSession(ctx, rawToken)
	if err != nil {
		t.Fatalf("GetSession on legacy row: %v", err)
	}
	if got.IdleTTL != 0 {
		t.Fatalf("legacy row IdleTTL should be 0 (idle disabled), got %v", got.IdleTTL)
	}
	if got.LastUsedAt != nil {
		t.Fatalf("legacy row LastUsedAt should be nil, got %v", got.LastUsedAt)
	}
	if got.IsExpired(time.Now()) {
		t.Fatal("legacy row inside its absolute TTL must not be expired")
	}

	rows, err := s.ListUserSessions(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListUserSessions: %v", err)
	}
	if len(rows) != 1 || rows[0].PublicID != "legacypub01" {
		t.Fatalf("expected legacy row in list with public_id 'legacypub01', got %+v", rows)
	}

	// Touch a legacy session: should populate last_used_at without
	// retroactively enabling the idle check.
	if err := s.TouchSession(ctx, rawToken, "127.0.0.1", "test"); err != nil {
		t.Fatalf("TouchSession: %v", err)
	}
	got, _ = s.GetSession(ctx, rawToken)
	if got.LastUsedAt == nil {
		t.Fatal("touch should populate last_used_at on legacy row")
	}
	if got.IdleTTL != 0 {
		t.Fatal("touch must not retroactively enable idle expiry on legacy row")
	}

	// Revoke by the backfilled public_id works.
	if err := s.RevokeUserSession(ctx, u.ID, "legacypub01"); err != nil {
		t.Fatalf("RevokeUserSession on legacy row: %v", err)
	}
	if _, err := s.GetSession(ctx, rawToken); err != sql.ErrNoRows {
		t.Fatalf("revoked legacy session should be gone, got %v", err)
	}
}

// --- Master Key ---

func TestGetMasterKeyRecordEmpty(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	rec, err := s.GetMasterKeyRecord(ctx)
	if err != nil {
		t.Fatalf("GetMasterKeyRecord: %v", err)
	}
	if rec != nil {
		t.Fatal("expected nil record on fresh DB")
	}
}

func TestMasterKeyRecordRoundTripWithPassword(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	kdfTime := uint32(3)
	kdfMemory := uint32(65536)
	kdfThreads := uint8(4)
	in := &MasterKeyRecord{
		Sentinel:      []byte("encrypted-sentinel"),
		SentinelNonce: []byte("sentinel-nonce"),
		DEKCiphertext: []byte("wrapped-dek-ciphertext"),
		DEKNonce:      []byte("dek-nonce-12b"),
		Salt:          []byte("test-salt-16byte"),
		KDFTime:       &kdfTime,
		KDFMemory:     &kdfMemory,
		KDFThreads:    &kdfThreads,
	}
	if err := s.SetMasterKeyRecord(ctx, in); err != nil {
		t.Fatalf("SetMasterKeyRecord: %v", err)
	}

	got, err := s.GetMasterKeyRecord(ctx)
	if err != nil {
		t.Fatalf("GetMasterKeyRecord: %v", err)
	}
	if string(got.Sentinel) != string(in.Sentinel) ||
		string(got.SentinelNonce) != string(in.SentinelNonce) ||
		string(got.DEKCiphertext) != string(in.DEKCiphertext) ||
		string(got.DEKNonce) != string(in.DEKNonce) ||
		string(got.Salt) != string(in.Salt) ||
		*got.KDFTime != *in.KDFTime ||
		*got.KDFMemory != *in.KDFMemory ||
		*got.KDFThreads != *in.KDFThreads {
		t.Fatalf("round-trip mismatch: got %+v", got)
	}
	if got.DEKPlaintext != nil {
		t.Fatal("expected DEKPlaintext to be nil for password-protected record")
	}
}

func TestMasterKeyRecordRoundTripPasswordless(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	in := &MasterKeyRecord{
		Sentinel:      []byte("encrypted-sentinel"),
		SentinelNonce: []byte("sentinel-nonce"),
		DEKPlaintext:  []byte("plaintext-dek-32-bytes-here!!!!"),
	}
	if err := s.SetMasterKeyRecord(ctx, in); err != nil {
		t.Fatalf("SetMasterKeyRecord: %v", err)
	}

	got, err := s.GetMasterKeyRecord(ctx)
	if err != nil {
		t.Fatalf("GetMasterKeyRecord: %v", err)
	}
	if string(got.Sentinel) != string(in.Sentinel) ||
		string(got.SentinelNonce) != string(in.SentinelNonce) ||
		string(got.DEKPlaintext) != string(in.DEKPlaintext) {
		t.Fatalf("round-trip mismatch: got %+v", got)
	}
	if got.DEKCiphertext != nil || got.Salt != nil || got.KDFTime != nil {
		t.Fatal("expected KEK fields to be nil for passwordless record")
	}
}

func TestMasterKeyRecordUpdate(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	// Start passwordless.
	in := &MasterKeyRecord{
		Sentinel:      []byte("sentinel"),
		SentinelNonce: []byte("nonce"),
		DEKPlaintext:  []byte("plaintext-dek"),
	}
	if err := s.SetMasterKeyRecord(ctx, in); err != nil {
		t.Fatal(err)
	}

	// Update to password-protected (simulating "set password").
	kdfTime := uint32(1)
	kdfMemory := uint32(1024)
	kdfThreads := uint8(1)
	in.DEKCiphertext = []byte("wrapped-dek")
	in.DEKNonce = []byte("dek-nonce")
	in.DEKPlaintext = nil
	in.Salt = []byte("salt")
	in.KDFTime = &kdfTime
	in.KDFMemory = &kdfMemory
	in.KDFThreads = &kdfThreads
	if err := s.UpdateMasterKeyRecord(ctx, in); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetMasterKeyRecord(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.DEKCiphertext) != "wrapped-dek" || got.DEKPlaintext != nil {
		t.Fatalf("update mismatch: got %+v", got)
	}
}

func TestMasterKeyRecordSingleton(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	rec := &MasterKeyRecord{
		Sentinel: []byte("e"), SentinelNonce: []byte("n"),
		DEKPlaintext: []byte("dek"),
	}
	if err := s.SetMasterKeyRecord(ctx, rec); err != nil {
		t.Fatal(err)
	}
	// Second insert is a no-op (ON CONFLICT DO NOTHING for HA race safety).
	rec2 := &MasterKeyRecord{
		Sentinel: []byte("different"), SentinelNonce: []byte("n2"),
		DEKPlaintext: []byte("dek2"),
	}
	if err := s.SetMasterKeyRecord(ctx, rec2); err != nil {
		t.Fatalf("second SetMasterKeyRecord should succeed (DO NOTHING): %v", err)
	}
	// The original record should be unchanged (first-writer-wins).
	got, err := s.GetMasterKeyRecord(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Sentinel) != "e" {
		t.Fatalf("expected original sentinel 'e', got %q", got.Sentinel)
	}
}

// --- Broker Config ---

func TestBrokerConfigCRUD(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	// CreateVault should auto-create an empty broker config.
	ns, err := s.CreateVault(ctx, "broker-test")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	// Get the auto-created config.
	bc, err := s.GetBrokerConfig(ctx, ns.ID)
	if err != nil {
		t.Fatalf("GetBrokerConfig: %v", err)
	}
	if bc.ServicesJSON != "[]" {
		t.Fatalf("expected empty services '[]', got %q", bc.ServicesJSON)
	}
	if bc.VaultID != ns.ID {
		t.Fatalf("expected vault ID %s, got %s", ns.ID, bc.VaultID)
	}

	// Set services.
	servicesJSON := `[{"host":"*.github.com","auth":{"type":"bearer","token":"token"}}]`
	updated, err := s.SetBrokerConfig(ctx, ns.ID, servicesJSON)
	if err != nil {
		t.Fatalf("SetBrokerConfig: %v", err)
	}
	if updated.ServicesJSON != servicesJSON {
		t.Fatalf("expected services %q, got %q", servicesJSON, updated.ServicesJSON)
	}

	// Get updated config.
	got, err := s.GetBrokerConfig(ctx, ns.ID)
	if err != nil {
		t.Fatalf("GetBrokerConfig after set: %v", err)
	}
	if got.ServicesJSON != servicesJSON {
		t.Fatalf("expected services %q, got %q", servicesJSON, got.ServicesJSON)
	}

	// Clear (set back to empty).
	cleared, err := s.SetBrokerConfig(ctx, ns.ID, "[]")
	if err != nil {
		t.Fatalf("SetBrokerConfig (clear): %v", err)
	}
	if cleared.ServicesJSON != "[]" {
		t.Fatalf("expected cleared services '[]', got %q", cleared.ServicesJSON)
	}
}

func TestBrokerConfigCascadeDelete(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.CreateVault(ctx, "cascade-broker")
	servicesJSON := `[{"host":"api.example.com","auth":{"type":"custom","headers":{"X-Key":"{{ key }}"}}}]`
	s.SetBrokerConfig(ctx, ns.ID, servicesJSON)

	// Delete the vault — broker config should be cascade-deleted.
	if err := s.DeleteVault(ctx, "cascade-broker"); err != nil {
		t.Fatal(err)
	}

	_, err := s.GetBrokerConfig(ctx, ns.ID)
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows after cascade delete, got %v", err)
	}
}

func TestRootVaultHasBrokerConfig(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	// The default vault is seeded by migration 003.
	// Migration 005 backfills broker configs for existing vaults.
	ns, err := s.GetVault(ctx, "default")
	if err != nil {
		t.Fatalf("GetVault: %v", err)
	}

	bc, err := s.GetBrokerConfig(ctx, ns.ID)
	if err != nil {
		t.Fatalf("GetBrokerConfig for root: %v", err)
	}
	if bc.ServicesJSON != "[]" {
		t.Fatalf("expected empty services for root, got %q", bc.ServicesJSON)
	}
}

// --- Proposals ---

func TestProposalCRUD(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, err := s.CreateVault(ctx, "cs-test")
	if err != nil {
		t.Fatal(err)
	}

	servicesJSON := `[{"host":"api.stripe.com","auth":{"type":"bearer","token":"STRIPE_KEY"}}]`
	credentialsJSON := `[{"key":"STRIPE_KEY","description":"Stripe credential key"}]`

	cs, err := s.CreateProposal(ctx, ns.ID, "session-1", servicesJSON, credentialsJSON, "need stripe", "", nil)
	if err != nil {
		t.Fatalf("CreateProposal: %v", err)
	}
	if cs.ID != 1 {
		t.Fatalf("expected first proposal ID 1, got %d", cs.ID)
	}
	if cs.Status != "pending" {
		t.Fatalf("expected status pending, got %s", cs.Status)
	}

	// Get
	got, err := s.GetProposal(ctx, ns.ID, 1)
	if err != nil {
		t.Fatalf("GetProposal: %v", err)
	}
	if got.Message != "need stripe" {
		t.Fatalf("expected message 'need stripe', got %q", got.Message)
	}

	// Not found
	_, err = s.GetProposal(ctx, ns.ID, 999)
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestProposalSequentialIDs(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.CreateVault(ctx, "seq-test")

	cs1, _ := s.CreateProposal(ctx, ns.ID, "s1", "[]", "[]", "first", "", nil)
	cs2, _ := s.CreateProposal(ctx, ns.ID, "s2", "[]", "[]", "second", "", nil)
	cs3, _ := s.CreateProposal(ctx, ns.ID, "s3", "[]", "[]", "third", "", nil)

	if cs1.ID != 1 || cs2.ID != 2 || cs3.ID != 3 {
		t.Fatalf("expected sequential IDs 1,2,3, got %d,%d,%d", cs1.ID, cs2.ID, cs3.ID)
	}
}

func TestProposalVaultScoping(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	nsA, _ := s.CreateVault(ctx, "ns-a")
	nsB, _ := s.CreateVault(ctx, "ns-b")

	csA, _ := s.CreateProposal(ctx, nsA.ID, "s1", "[]", "[]", "in A", "", nil)
	csB, _ := s.CreateProposal(ctx, nsB.ID, "s2", "[]", "[]", "in B", "", nil)

	// Both should have ID 1 (independent sequences).
	if csA.ID != 1 || csB.ID != 1 {
		t.Fatalf("expected both proposals to have ID 1, got %d and %d", csA.ID, csB.ID)
	}

	// Fetching ID 1 from vault B should return B's proposal (not A's).
	gotFromB, err := s.GetProposal(ctx, nsB.ID, csA.ID)
	if err != nil {
		t.Fatalf("GetProposal from B: %v", err)
	}
	if gotFromB.Message != "in B" {
		t.Fatalf("expected vault B's own proposal with message 'in B', got %q", gotFromB.Message)
	}

	// Fetching ID 1 from vault A should return A's proposal.
	gotFromA, err := s.GetProposal(ctx, nsA.ID, csA.ID)
	if err != nil {
		t.Fatalf("GetProposal from A: %v", err)
	}
	if gotFromA.Message != "in A" {
		t.Fatalf("expected vault A's own proposal with message 'in A', got %q", gotFromA.Message)
	}

	// List scoped to vault
	listA, _ := s.ListProposals(ctx, nsA.ID, "")
	listB, _ := s.ListProposals(ctx, nsB.ID, "")
	if len(listA) != 1 || len(listB) != 1 {
		t.Fatalf("expected 1 proposal per vault, got %d and %d", len(listA), len(listB))
	}
}

func TestProposalListByStatus(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.CreateVault(ctx, "list-test")

	s.CreateProposal(ctx, ns.ID, "s1", "[]", "[]", "pending one", "", nil)
	s.CreateProposal(ctx, ns.ID, "s2", "[]", "[]", "pending two", "", nil)
	s.UpdateProposalStatus(ctx, ns.ID, 1, "rejected", "not needed")

	pending, _ := s.ListProposals(ctx, ns.ID, "pending")
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}

	rejected, _ := s.ListProposals(ctx, ns.ID, "rejected")
	if len(rejected) != 1 {
		t.Fatalf("expected 1 rejected, got %d", len(rejected))
	}

	all, _ := s.ListProposals(ctx, ns.ID, "")
	if len(all) != 2 {
		t.Fatalf("expected 2 total, got %d", len(all))
	}
}

func TestProposalUpdateStatus(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.CreateVault(ctx, "status-test")
	s.CreateProposal(ctx, ns.ID, "s1", "[]", "[]", "test", "", nil)

	err := s.UpdateProposalStatus(ctx, ns.ID, 1, "rejected", "bad idea")
	if err != nil {
		t.Fatalf("UpdateProposalStatus: %v", err)
	}

	got, _ := s.GetProposal(ctx, ns.ID, 1)
	if got.Status != "rejected" {
		t.Fatalf("expected status rejected, got %s", got.Status)
	}
	if got.ReviewNote != "bad idea" {
		t.Fatalf("expected review note 'bad idea', got %q", got.ReviewNote)
	}
	if got.ReviewedAt == nil {
		t.Fatal("expected reviewed_at to be set")
	}

	// Not found
	err = s.UpdateProposalStatus(ctx, ns.ID, 999, "applied", "")
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestCountPendingProposals(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.CreateVault(ctx, "count-test")

	count, _ := s.CountPendingProposals(ctx, ns.ID)
	if count != 0 {
		t.Fatalf("expected 0, got %d", count)
	}

	s.CreateProposal(ctx, ns.ID, "s1", "[]", "[]", "a", "", nil)
	s.CreateProposal(ctx, ns.ID, "s2", "[]", "[]", "b", "", nil)
	s.UpdateProposalStatus(ctx, ns.ID, 2, "rejected", "")

	count, _ = s.CountPendingProposals(ctx, ns.ID)
	if count != 1 {
		t.Fatalf("expected 1 pending, got %d", count)
	}
}

func TestExpirePendingProposals(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.CreateVault(ctx, "expire-test")
	s.CreateProposal(ctx, ns.ID, "s1", "[]", "[]", "old", "", nil)

	// Expire proposals created before 1 hour from now — should expire the one we just created.
	n, err := s.ExpirePendingProposals(ctx, time.Now().Add(1*time.Hour))
	if err != nil {
		t.Fatalf("ExpirePendingProposals: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 expired, got %d", n)
	}

	got, _ := s.GetProposal(ctx, ns.ID, 1)
	if got.Status != "expired" {
		t.Fatalf("expected status expired, got %s", got.Status)
	}
}

func TestProposalWithCredentials(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.CreateVault(ctx, "cred-cs-test")

	creds := map[string]EncryptedCredential{
		"STRIPE_KEY": {Ciphertext: []byte("enc-val"), Nonce: []byte("nonce-12b")},
	}
	cs, err := s.CreateProposal(ctx, ns.ID, "s1", "[]", "[]", "with credential", "", creds)
	if err != nil {
		t.Fatalf("CreateProposal with credentials: %v", err)
	}

	got, err := s.GetProposalCredentials(ctx, ns.ID, cs.ID)
	if err != nil {
		t.Fatalf("GetProposalCredentials: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(got))
	}
	enc, ok := got["STRIPE_KEY"]
	if !ok {
		t.Fatal("expected STRIPE_KEY in proposal credentials")
	}
	if string(enc.Ciphertext) != "enc-val" || string(enc.Nonce) != "nonce-12b" {
		t.Fatalf("unexpected credential data: ct=%q nonce=%q", enc.Ciphertext, enc.Nonce)
	}
}

func TestApplyProposal(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.CreateVault(ctx, "apply-test")
	s.CreateProposal(ctx, ns.ID, "s1",
		`[{"host":"api.stripe.com","auth":{"type":"bearer","token":"STRIPE_KEY"}}]`,
		`[{"key":"STRIPE_KEY"}]`, "apply me", "", nil)

	mergedServices := `[{"host":"api.stripe.com","auth":{"type":"bearer","token":"STRIPE_KEY"}}]`
	creds := map[string]EncryptedCredential{
		"STRIPE_KEY": {Ciphertext: []byte("real-enc"), Nonce: []byte("real-nonce")},
	}

	err := s.ApplyProposal(ctx, ns.ID, 1, mergedServices, creds, nil, nil)
	if err != nil {
		t.Fatalf("ApplyProposal: %v", err)
	}

	// Verify proposal is applied.
	cs, _ := s.GetProposal(ctx, ns.ID, 1)
	if cs.Status != "applied" {
		t.Fatalf("expected status applied, got %s", cs.Status)
	}
	if cs.ReviewedAt == nil {
		t.Fatal("expected reviewed_at to be set")
	}

	// Verify broker config updated.
	bc, _ := s.GetBrokerConfig(ctx, ns.ID)
	if bc.ServicesJSON != mergedServices {
		t.Fatalf("expected services %q, got %q", mergedServices, bc.ServicesJSON)
	}

	// Verify credential stored.
	cred, err := s.GetCredential(ctx, ns.ID, "STRIPE_KEY")
	if err != nil {
		t.Fatalf("GetCredential after apply: %v", err)
	}
	if string(cred.Ciphertext) != "real-enc" {
		t.Fatalf("expected ciphertext 'real-enc', got %q", cred.Ciphertext)
	}
}

func TestApplyProposalWithCredentialDeletion(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.CreateVault(ctx, "apply-delete-test")

	// Pre-seed a credential that will be deleted.
	s.SetCredential(ctx, ns.ID, "old_key", []byte("old-enc"), []byte("old-nonce"))

	// Create a proposal.
	s.CreateProposal(ctx, ns.ID, "s1",
		`[{"action":"set","host":"example.com","auth":{"type":"custom","headers":{"X":"v"}}}]`,
		`[{"action":"set","key":"new_key"}]`, "add and delete", "", nil)

	mergedServices := `[{"host":"example.com","auth":{"type":"custom","headers":{"X":"v"}}}]`
	creds := map[string]EncryptedCredential{
		"new_key": {Ciphertext: []byte("new-enc"), Nonce: []byte("new-nonce")},
	}

	err := s.ApplyProposal(ctx, ns.ID, 1, mergedServices, creds, []string{"old_key"}, nil)
	if err != nil {
		t.Fatalf("ApplyProposal with delete: %v", err)
	}

	// Verify old credential deleted.
	_, err = s.GetCredential(ctx, ns.ID, "old_key")
	if err == nil {
		t.Fatal("expected old_key to be deleted")
	}

	// Verify new credential stored.
	cred, err := s.GetCredential(ctx, ns.ID, "new_key")
	if err != nil {
		t.Fatalf("GetCredential new_key: %v", err)
	}
	if string(cred.Ciphertext) != "new-enc" {
		t.Fatalf("expected ciphertext 'new-enc', got %q", cred.Ciphertext)
	}
}

func TestCascadeDeleteVaultRemovesProposals(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.CreateVault(ctx, "cascade-cs")
	creds := map[string]EncryptedCredential{
		"key1": {Ciphertext: []byte("a"), Nonce: []byte("b")},
	}
	s.CreateProposal(ctx, ns.ID, "s1", "[]", "[]", "msg", "", creds)

	if err := s.DeleteVault(ctx, "cascade-cs"); err != nil {
		t.Fatal(err)
	}

	list, _ := s.ListProposals(ctx, ns.ID, "")
	if len(list) != 0 {
		t.Fatalf("expected 0 proposals after cascade delete, got %d", len(list))
	}

	csCreds, _ := s.GetProposalCredentials(ctx, ns.ID, 1)
	if len(csCreds) != 0 {
		t.Fatalf("expected 0 proposal credentials after cascade delete, got %d", len(csCreds))
	}
}


// --- UUID ---

func TestNewUUIDUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := newUUID()
		if seen[id] {
			t.Fatalf("duplicate UUID: %s", id)
		}
		seen[id] = true
	}
}

// --- Multi-User Permission Model ---

func TestCreateMemberUser(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, err := s.CreateUser(ctx, "member@test.com", []byte("hash"), []byte("salt"), "member", 3, 65536, 4)
	if err != nil {
		t.Fatalf("CreateUser(member): %v", err)
	}
	if u.Role != "member" {
		t.Fatalf("expected role 'member', got %q", u.Role)
	}
}

func TestGetUserByID(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, err := s.CreateUser(ctx, "user@test.com", []byte("hash"), []byte("salt"), "owner", 3, 65536, 4)
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got.Email != "user@test.com" {
		t.Fatalf("expected email 'user@test.com', got %q", got.Email)
	}
}

func TestGetUserByIDNotFound(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	_, err := s.GetUserByID(ctx, "nonexistent")
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestListUsers(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	s.CreateUser(ctx, "alice@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)
	s.CreateUser(ctx, "bob@test.com", []byte("h"), []byte("s"), "member", 3, 65536, 4)

	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
	// Ordered by email
	if users[0].Email != "alice@test.com" || users[1].Email != "bob@test.com" {
		t.Fatalf("unexpected order: %s, %s", users[0].Email, users[1].Email)
	}
}

func TestUpdateUserRole(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, _ := s.CreateUser(ctx, "user@test.com", []byte("h"), []byte("s"), "member", 3, 65536, 4)

	if err := s.UpdateUserRole(ctx, u.ID, "owner"); err != nil {
		t.Fatalf("UpdateUserRole: %v", err)
	}

	got, _ := s.GetUserByID(ctx, u.ID)
	if got.Role != "owner" {
		t.Fatalf("expected role 'owner', got %q", got.Role)
	}
}

func TestUpdateUserRoleNotFound(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	err := s.UpdateUserRole(ctx, "nonexistent", "owner")
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestDeleteUser(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, _ := s.CreateUser(ctx, "del@test.com", []byte("h"), []byte("s"), "member", 3, 65536, 4)

	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	_, err := s.GetUserByID(ctx, u.ID)
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows after delete, got %v", err)
	}
}

func TestCountOwners(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	s.CreateUser(ctx, "owner1@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)
	s.CreateUser(ctx, "member1@test.com", []byte("h"), []byte("s"), "member", 3, 65536, 4)
	s.CreateUser(ctx, "owner2@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)

	count, err := s.CountOwners(ctx)
	if err != nil {
		t.Fatalf("CountOwners: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 owners, got %d", count)
	}
}

func TestVaultGrantsCRUD(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, _ := s.CreateUser(ctx, "user@test.com", []byte("h"), []byte("s"), "member", 3, 65536, 4)
	ns, _ := s.CreateVault(ctx, "dev")

	// Grant
	if err := s.GrantVaultRole(ctx, u.ID, "user", ns.ID, "member"); err != nil {
		t.Fatalf("GrantVaultRole: %v", err)
	}

	// HasAccess
	has, err := s.HasVaultAccess(ctx, u.ID, ns.ID)
	if err != nil {
		t.Fatalf("HasVaultAccess: %v", err)
	}
	if !has {
		t.Fatal("expected HasVaultAccess to be true")
	}

	// No access to other vault
	ns2, _ := s.CreateVault(ctx, "prod")
	has2, _ := s.HasVaultAccess(ctx, u.ID, ns2.ID)
	if has2 {
		t.Fatal("expected HasVaultAccess to be false for non-granted vault")
	}

	// List grants
	grants, err := s.ListActorGrants(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListUserGrants: %v", err)
	}
	if len(grants) != 1 || grants[0].VaultID != ns.ID {
		t.Fatalf("unexpected grants: %+v", grants)
	}

	// Revoke
	if err := s.RevokeVaultAccess(ctx, u.ID, ns.ID); err != nil {
		t.Fatalf("RevokeVaultAccess: %v", err)
	}

	has, _ = s.HasVaultAccess(ctx, u.ID, ns.ID)
	if has {
		t.Fatal("expected HasVaultAccess to be false after revoke")
	}
}

func TestGrantVaultAccessIdempotent(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, _ := s.CreateUser(ctx, "user@test.com", []byte("h"), []byte("s"), "member", 3, 65536, 4)
	ns, _ := s.CreateVault(ctx, "dev")

	// Granting twice should not error
	s.GrantVaultRole(ctx, u.ID, "user", ns.ID, "member")
	if err := s.GrantVaultRole(ctx, u.ID, "user", ns.ID, "member"); err != nil {
		t.Fatalf("second GrantVaultRole should not error: %v", err)
	}
}

func TestRevokeVaultAccessNotFound(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, _ := s.CreateUser(ctx, "user@test.com", []byte("h"), []byte("s"), "member", 3, 65536, 4)
	ns, _ := s.CreateVault(ctx, "dev")

	err := s.RevokeVaultAccess(ctx, u.ID, ns.ID)
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestDeleteUserSessions(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, _ := s.CreateUser(ctx, "user@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)
	sess, _ := s.CreateUserSession(ctx, CreateUserSessionParams{UserID: u.ID, ExpiresAt: time.Now().Add(24 * time.Hour)})

	if err := s.DeleteUserSessions(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUserSessions: %v", err)
	}

	_, err := s.GetSession(ctx, sess.ID)
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows after deleting user sessions, got %v", err)
	}
}


func TestDeleteUserCascadesGrants(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, _ := s.CreateUser(ctx, "user@test.com", []byte("h"), []byte("s"), "member", 3, 65536, 4)
	ns, _ := s.CreateVault(ctx, "dev")
	s.GrantVaultRole(ctx, u.ID, "user", ns.ID, "member")

	// Delete user — grants should cascade
	s.DeleteUser(ctx, u.ID)

	grants, _ := s.ListActorGrants(ctx, u.ID)
	if len(grants) != 0 {
		t.Fatalf("expected 0 grants after user deletion, got %d", len(grants))
	}
}

// --- Agent Tests ---

func TestCreateAgent(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ag, err := s.CreateAgent(ctx, "claudebot", "creator1", "member")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if ag.Name != "claudebot" {
		t.Fatalf("expected name claudebot, got %s", ag.Name)
	}
	if ag.Status != "active" {
		t.Fatalf("expected status active, got %s", ag.Status)
	}
}

func TestCreateAgentWithGrantsAndToken(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, err := s.GetVault(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}

	ag, sess, err := s.CreateAgentWithGrantsAndToken(ctx, "txbot", "creator-uid", "member",
		[]AgentVaultGrantSpec{{VaultID: ns.ID, Role: "proxy"}}, nil)
	if err != nil {
		t.Fatalf("CreateAgentWithGrantsAndToken: %v", err)
	}
	if ag.Name != "txbot" || sess.AgentID != ag.ID || sess.ID == "" {
		t.Fatalf("unexpected agent/session: ag=%+v sess=%+v", ag, sess)
	}

	got, err := s.GetAgentByName(ctx, "txbot")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Vaults) != 1 || got.Vaults[0].Role != "proxy" {
		t.Fatalf("expected one proxy grant, got %+v", got.Vaults)
	}
	if n, _ := s.CountAgentTokens(ctx, ag.ID); n != 1 {
		t.Fatalf("expected 1 token, got %d", n)
	}
}

func TestCreateAgentWithGrantsAndToken_NoVaults(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ag, sess, err := s.CreateAgentWithGrantsAndToken(ctx, "barebot", "creator-uid", "member", nil, nil)
	if err != nil {
		t.Fatalf("CreateAgentWithGrantsAndToken: %v", err)
	}
	if len(ag.Name) == 0 || sess.AgentID != ag.ID {
		t.Fatalf("unexpected agent/session: ag=%+v sess=%+v", ag, sess)
	}
	if n, _ := s.CountAgentTokens(ctx, ag.ID); n != 1 {
		t.Fatalf("expected 1 token, got %d", n)
	}
}

func TestGetAgentByName(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	s.CreateAgent(ctx, "myagent", "creator1", "member")

	ag, err := s.GetAgentByName(ctx, "myagent")
	if err != nil {
		t.Fatalf("GetAgentByName: %v", err)
	}
	if ag.Name != "myagent" {
		t.Fatalf("expected myagent, got %s", ag.Name)
	}

	_, err = s.GetAgentByName(ctx, "nonexistent")
	if err != sql.ErrNoRows {
		t.Fatalf("expected ErrNoRows for missing agent, got %v", err)
	}
}

func TestListAgents(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.GetVault(ctx, "default")
	ns2, _ := s.CreateVault(ctx, "staging")
	a1, _ := s.CreateAgent(ctx, "a1", "c", "member")
	a2, _ := s.CreateAgent(ctx, "a2", "c", "member")
	a3, _ := s.CreateAgent(ctx, "a3", "c", "member")

	// Grant vault access.
	s.GrantVaultRole(ctx, a1.ID, "agent", ns.ID, "proxy")
	s.GrantVaultRole(ctx, a2.ID, "agent", ns.ID, "proxy")
	s.GrantVaultRole(ctx, a3.ID, "agent", ns2.ID, "proxy")

	// All agents (cross-vault)
	all, err := s.ListAllAgents(ctx)
	if err != nil {
		t.Fatalf("ListAllAgents: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3, got %d", len(all))
	}

	// Filtered by vault
	filtered, err := s.ListAgents(ctx, ns.ID)
	if err != nil {
		t.Fatalf("ListAgents filtered: %v", err)
	}
	if len(filtered) != 2 {
		t.Fatalf("expected 2, got %d", len(filtered))
	}
}

func TestDuplicateAgentName(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	_, err := s.CreateAgent(ctx, "dup", "c", "member")
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err = s.CreateAgent(ctx, "dup", "c", "member")
	if err == nil {
		t.Fatal("expected error for duplicate agent name")
	}
}

func TestRevokeAgent(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ag, _ := s.CreateAgent(ctx, "torevoke", "c", "member")

	// Create a token for this agent.
	sess, err := s.CreateAgentToken(ctx, ag.ID, tp(time.Now().Add(24*time.Hour)))
	if err != nil {
		t.Fatalf("CreateAgentToken: %v", err)
	}

	// Revoke
	if err := s.RevokeAgent(ctx, ag.ID); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}

	// Agent should be revoked.
	revoked, _ := s.GetAgentByName(ctx, "torevoke")
	if revoked.Status != "revoked" {
		t.Fatalf("expected revoked, got %s", revoked.Status)
	}
	if revoked.RevokedAt == nil {
		t.Fatal("expected revoked_at to be set")
	}

	// Session should be deleted (cascade).
	_, err = s.GetSession(ctx, sess.ID)
	if err != sql.ErrNoRows {
		t.Fatalf("expected session deleted after revoke, got %v", err)
	}
}

func TestRenameAgent(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ag, _ := s.CreateAgent(ctx, "oldname", "c", "member")

	err := s.RenameAgent(ctx, ag.ID, "newname")
	if err != nil {
		t.Fatalf("RenameAgent: %v", err)
	}

	renamed, _ := s.GetAgentByName(ctx, "newname")
	if renamed.ID != ag.ID {
		t.Fatalf("expected same ID after rename")
	}

	_, err = s.GetAgentByName(ctx, "oldname")
	if err != sql.ErrNoRows {
		t.Fatal("expected old name to not be found")
	}
}

func TestCountAgentTokens(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ag, _ := s.CreateAgent(ctx, "counter", "c", "member")

	count, _ := s.CountAgentTokens(ctx, ag.ID)
	if count != 0 {
		t.Fatalf("expected 0 tokens, got %d", count)
	}

	s.CreateAgentToken(ctx, ag.ID, tp(time.Now().Add(24*time.Hour)))
	s.CreateAgentToken(ctx, ag.ID, tp(time.Now().Add(24*time.Hour)))

	count, _ = s.CountAgentTokens(ctx, ag.ID)
	if count != 2 {
		t.Fatalf("expected 2 tokens, got %d", count)
	}

	// Expired tokens should not be counted.
	s.CreateAgentToken(ctx, ag.ID, tp(time.Now().Add(-1*time.Hour)))
	count, _ = s.CountAgentTokens(ctx, ag.ID)
	if count != 2 {
		t.Fatalf("expected 2 active tokens (1 expired), got %d", count)
	}
}

func TestCreateAgentToken(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ag, _ := s.CreateAgent(ctx, "sessbot", "c", "member")

	sess, err := s.CreateAgentToken(ctx, ag.ID, tp(time.Now().Add(24*time.Hour)))
	if err != nil {
		t.Fatalf("CreateAgentToken: %v", err)
	}
	if sess.AgentID != ag.ID {
		t.Fatalf("expected agent_id %s, got %s", ag.ID, sess.AgentID)
	}
	// Instance-level agent tokens have empty VaultID.
	if sess.VaultID != "" {
		t.Fatalf("expected empty vault_id for agent token, got %s", sess.VaultID)
	}

	// Verify GetSession returns agent_id.
	fetched, _ := s.GetSession(ctx, sess.ID)
	if fetched.AgentID != ag.ID {
		t.Fatalf("GetSession: expected agent_id %s, got %s", ag.ID, fetched.AgentID)
	}
}

func TestGetSessionBackwardCompat(t *testing.T) {
	// Old sessions (pre-agent) should still work with NULL agent_id.
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.GetVault(ctx, "default")
	sess, _ := s.CreateScopedSession(ctx, CreateScopedSessionParams{
		VaultID:   ns.ID,
		VaultRole: "proxy",
		ExpiresAt: tp(time.Now().Add(24 * time.Hour)),
	})

	fetched, err := s.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if fetched.AgentID != "" {
		t.Fatalf("expected empty agent_id for old session, got %q", fetched.AgentID)
	}
}


func TestDeleteAgentTokens(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ag, _ := s.CreateAgent(ctx, "delbot", "c", "member")

	s.CreateAgentToken(ctx, ag.ID, tp(time.Now().Add(24*time.Hour)))
	s.CreateAgentToken(ctx, ag.ID, tp(time.Now().Add(24*time.Hour)))

	count, _ := s.CountAgentTokens(ctx, ag.ID)
	if count != 2 {
		t.Fatalf("expected 2 tokens before delete, got %d", count)
	}

	err := s.DeleteAgentTokens(ctx, ag.ID)
	if err != nil {
		t.Fatalf("DeleteAgentTokens: %v", err)
	}

	count, _ = s.CountAgentTokens(ctx, ag.ID)
	if count != 0 {
		t.Fatalf("expected 0 tokens after delete, got %d", count)
	}
}

func TestCreatePasswordReset(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	pr, err := s.CreatePasswordReset(ctx, "user@test.com", "123456", time.Now().Add(15*time.Minute))
	if err != nil {
		t.Fatalf("CreatePasswordReset: %v", err)
	}
	if pr.Email != "user@test.com" || pr.Status != "pending" {
		t.Fatalf("unexpected password reset: %+v", pr)
	}
}

func TestGetPendingPasswordReset(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	_, _ = s.CreatePasswordReset(ctx, "user@test.com", "123456", time.Now().Add(15*time.Minute))

	pr, err := s.GetPendingPasswordReset(ctx, "user@test.com", "123456")
	if err != nil {
		t.Fatalf("GetPendingPasswordReset: %v", err)
	}
	if pr.Email != "user@test.com" {
		t.Fatalf("unexpected email: %s", pr.Email)
	}

	// Wrong code should not match.
	pr2, err := s.GetPendingPasswordReset(ctx, "user@test.com", "999999")
	if err != sql.ErrNoRows {
		t.Fatalf("expected ErrNoRows for wrong code, got err=%v pr=%+v", err, pr2)
	}
}

func TestGetPendingPasswordReset_Expired(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	_, _ = s.CreatePasswordReset(ctx, "user@test.com", "123456", time.Now().Add(-1*time.Minute))

	pr, err := s.GetPendingPasswordReset(ctx, "user@test.com", "123456")
	if err != sql.ErrNoRows {
		t.Fatalf("expected ErrNoRows for expired code, got err=%v pr=%+v", err, pr)
	}
}

func TestMarkPasswordResetUsed(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	pr, _ := s.CreatePasswordReset(ctx, "user@test.com", "123456", time.Now().Add(15*time.Minute))

	err := s.MarkPasswordResetUsed(ctx, pr.ID)
	if err != nil {
		t.Fatalf("MarkPasswordResetUsed: %v", err)
	}

	// Should no longer be findable as pending.
	pr2, err := s.GetPendingPasswordReset(ctx, "user@test.com", "123456")
	if err != sql.ErrNoRows {
		t.Fatalf("expected ErrNoRows after marking used, got err=%v pr=%+v", err, pr2)
	}

	// Double-mark should fail.
	err = s.MarkPasswordResetUsed(ctx, pr.ID)
	if err != sql.ErrNoRows {
		t.Fatalf("expected ErrNoRows on double-mark, got %v", err)
	}
}

func TestCountPendingPasswordResets(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	count, _ := s.CountPendingPasswordResets(ctx, "user@test.com")
	if count != 0 {
		t.Fatalf("expected 0 pending, got %d", count)
	}

	s.CreatePasswordReset(ctx, "user@test.com", "111111", time.Now().Add(15*time.Minute))
	s.CreatePasswordReset(ctx, "user@test.com", "222222", time.Now().Add(15*time.Minute))

	count, _ = s.CountPendingPasswordResets(ctx, "user@test.com")
	if count != 2 {
		t.Fatalf("expected 2 pending, got %d", count)
	}

	// Other email should be 0.
	count, _ = s.CountPendingPasswordResets(ctx, "other@test.com")
	if count != 0 {
		t.Fatalf("expected 0 pending for other email, got %d", count)
	}
}

func TestExpirePendingPasswordResets(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	s.CreatePasswordReset(ctx, "user@test.com", "111111", time.Now().Add(-1*time.Minute))
	s.CreatePasswordReset(ctx, "user@test.com", "222222", time.Now().Add(15*time.Minute))

	n, err := s.ExpirePendingPasswordResets(ctx, time.Now())
	if err != nil {
		t.Fatalf("ExpirePendingPasswordResets: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 expired, got %d", n)
	}

	count, _ := s.CountPendingPasswordResets(ctx, "user@test.com")
	if count != 1 {
		t.Fatalf("expected 1 pending after expiry, got %d", count)
	}
}

// TestListRequestLogsTailOrdering is a regression test: when a burst
// larger than the page size lands between polls, the tail query must
// consume the oldest rows first so subsequent polls can advance the
// cursor through the whole burst without gaps. Before the ASC fix,
// `ORDER BY id DESC LIMIT N` returned the *newest* N rows and silently
// lost the older ones on the next poll.
func TestListRequestLogsTailOrdering(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, err := s.CreateVault(ctx, "logs")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	// Insert 10 rows so we can page through with Limit=3.
	rows := make([]RequestLog, 10)
	for i := range rows {
		rows[i] = RequestLog{
			VaultID: ns.ID,
			Ingress: "explicit",
			Method:  "GET",
			Host:    "api.example.com",
			Path:    "/",
			Status:  200,
		}
	}
	if err := s.InsertRequestLogs(ctx, rows); err != nil {
		t.Fatalf("InsertRequestLogs: %v", err)
	}

	// Historical page (no cursor) returns newest-first.
	page, err := s.ListRequestLogs(ctx, ListRequestLogsOpts{VaultID: &ns.ID, Limit: 3})
	if err != nil {
		t.Fatalf("initial list: %v", err)
	}
	if len(page) != 3 {
		t.Fatalf("initial page size = %d, want 3", len(page))
	}
	if page[0].ID <= page[1].ID || page[1].ID <= page[2].ID {
		t.Fatalf("historical page not DESC: %v", []int64{page[0].ID, page[1].ID, page[2].ID})
	}

	// Tail from an id boundary: returns rows (boundary, boundary+Limit]
	// in ASC order so a subsequent poll with after=boundary+Limit picks
	// up from there with no gap. Before the fix, the query was
	// `ORDER BY id DESC LIMIT N`, which returned the newest N rows above
	// the boundary and silently dropped the older ones.
	boundary := page[2].ID - 1
	tail, err := s.ListRequestLogs(ctx, ListRequestLogsOpts{VaultID: &ns.ID, After: boundary, Limit: 3})
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	if len(tail) != 3 {
		t.Fatalf("tail size = %d, want 3", len(tail))
	}
	if tail[0].ID >= tail[1].ID || tail[1].ID >= tail[2].ID {
		t.Fatalf("tail not ASC: %v", []int64{tail[0].ID, tail[1].ID, tail[2].ID})
	}
	if tail[0].ID != boundary+1 {
		t.Fatalf("tail should start at id %d, got %d", boundary+1, tail[0].ID)
	}
}

// TestNoAccessRoleAcceptedByMigration verifies migration 045 widened the
// instance-role CHECK constraint on agents.role. A wire value of "no-access"
// must persist; an invalid value must still be rejected.
func TestNoAccessRoleAcceptedByMigration(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	agent, err := s.CreateAgent(ctx, "scoped-agent", "system", "no-access")
	if err != nil {
		t.Fatalf("CreateAgent with no-access role: %v", err)
	}
	if agent.Role != "no-access" {
		t.Fatalf("expected role no-access, got %q", agent.Role)
	}

	if _, err := s.CreateAgent(ctx, "bad-agent", "system", "bogus-role"); err == nil {
		t.Fatalf("expected CreateAgent with bogus role to fail CHECK constraint")
	}
}

// --- External Credential Stores ---

func TestCreateExternalVault(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, err := s.CreateUser(ctx, "ext@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	params := CreateExternalVaultParams{
		Name:                "ext-vault",
		Kind:                "infisical",
		ConfigJSON:          `{"project_id":"p","environment":"dev","secret_path":"/"}`,
		PollIntervalSeconds: 60,
		Credentials: []EncryptedKV{
			{Key: "FOO", Ciphertext: []byte("c1"), Nonce: []byte("n1")},
			{Key: "BAR", Ciphertext: []byte("c2"), Nonce: []byte("n2")},
		},
		CreatorActorID:   u.ID,
		CreatorActorType: "user",
	}

	v, err := s.CreateExternalVault(ctx, params)
	if err != nil {
		t.Fatalf("CreateExternalVault: %v", err)
	}
	if v.Name != "ext-vault" || v.ID == "" {
		t.Fatalf("bad vault: %+v", v)
	}

	cs, err := s.GetVaultCredentialStore(ctx, v.ID)
	if err != nil {
		t.Fatalf("GetVaultCredentialStore: %v", err)
	}
	if cs.Kind != "infisical" || cs.PollIntervalSeconds != 60 || cs.LastSyncStatus != "ok" {
		t.Fatalf("bad credential store: %+v", cs)
	}
	if cs.LastSyncedAt == nil {
		t.Fatalf("expected last_synced_at populated")
	}

	creds, err := s.ListCredentials(ctx, v.ID)
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("expected 2 seeded credentials, got %d", len(creds))
	}

	role, err := s.GetVaultRole(ctx, u.ID, v.ID)
	if err != nil {
		t.Fatalf("GetVaultRole: %v", err)
	}
	if role != "admin" {
		t.Fatalf("expected creator admin grant, got %q", role)
	}

	bc, err := s.GetBrokerConfig(ctx, v.ID)
	if err != nil {
		t.Fatalf("GetBrokerConfig: %v", err)
	}
	if bc.ServicesJSON != "[]" {
		t.Fatalf("expected empty services_json, got %q", bc.ServicesJSON)
	}
}

func TestCreateExternalVaultRollbackOnDuplicateName(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, _ := s.CreateUser(ctx, "ext-dup@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)

	params := CreateExternalVaultParams{
		Name:                "dup-vault",
		Kind:                "infisical",
		ConfigJSON:          `{"project_id":"p","environment":"dev","secret_path":"/"}`,
		PollIntervalSeconds: 60,
		Credentials:         []EncryptedKV{{Key: "K", Ciphertext: []byte("c"), Nonce: []byte("n")}},
		CreatorActorID:      u.ID,
		CreatorActorType:    "user",
	}

	if _, err := s.CreateExternalVault(ctx, params); err != nil {
		t.Fatalf("first CreateExternalVault: %v", err)
	}
	// Second attempt with same name must fail and leave no orphan rows.
	if _, err := s.CreateExternalVault(ctx, params); err == nil {
		t.Fatalf("expected duplicate-name failure")
	}

	// Exactly one vault with this name; exactly one credential row across all
	// of the rejected attempt's keys (the K from the first vault).
	var vaultCount, credCount int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM vaults WHERE name = ?", "dup-vault").Scan(&vaultCount)
	if vaultCount != 1 {
		t.Fatalf("expected exactly 1 vault, got %d", vaultCount)
	}
	_ = s.db.QueryRow("SELECT COUNT(*) FROM credentials WHERE key = ?", "K").Scan(&credCount)
	if credCount != 1 {
		t.Fatalf("expected exactly 1 credential row after rollback, got %d", credCount)
	}
}

func TestCreateExternalVaultRejectsBelowMinPollInterval(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, "min-poll@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)
	_, err := s.CreateExternalVault(ctx, CreateExternalVaultParams{
		Name:                "spin-vault",
		Kind:                "infisical",
		ConfigJSON:          `{}`,
		PollIntervalSeconds: 5,
		CreatorActorID:      u.ID,
		CreatorActorType:    "user",
	})
	if err == nil {
		t.Fatalf("expected CHECK constraint failure for poll_interval_seconds=5, got nil")
	}
}

func TestCascadeDeleteVaultRemovesCredentialStore(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, "cascade-cs@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)
	v, err := s.CreateExternalVault(ctx, CreateExternalVaultParams{
		Name:                "cascade-cs-vault",
		Kind:                "infisical",
		ConfigJSON:          `{}`,
		PollIntervalSeconds: 60,
		CreatorActorID:      u.ID,
		CreatorActorType:    "user",
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := s.DeleteVault(ctx, v.Name); err != nil {
		t.Fatalf("DeleteVault: %v", err)
	}
	if _, err := s.GetVaultCredentialStore(ctx, v.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows after cascade delete, got %v", err)
	}
}

func TestReplaceVaultCredentialsForSyncRotates(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, _ := s.CreateUser(ctx, "replace@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)
	v, err := s.CreateExternalVault(ctx, CreateExternalVaultParams{
		Name:                "replace-vault",
		Kind:                "infisical",
		ConfigJSON:          `{}`,
		PollIntervalSeconds: 60,
		Credentials: []EncryptedKV{
			{Key: "A", Ciphertext: []byte("c1"), Nonce: []byte("n1")},
			{Key: "B", Ciphertext: []byte("c2"), Nonce: []byte("n2")},
		},
		CreatorActorID:   u.ID,
		CreatorActorType: "user",
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Replace: keep A (rotated), drop B, add C.
	applied, err := s.ReplaceVaultCredentialsForSync(ctx, v.ID, `{}`, []EncryptedKV{
		{Key: "A", Ciphertext: []byte("c1-new"), Nonce: []byte("n1-new")},
		{Key: "C", Ciphertext: []byte("c3"), Nonce: []byte("n3")},
	})
	if err != nil || !applied {
		t.Fatalf("ReplaceVaultCredentialsForSync: applied=%v err=%v", applied, err)
	}

	creds, _ := s.ListCredentials(ctx, v.ID)
	if len(creds) != 2 {
		t.Fatalf("expected 2 creds after replace, got %d", len(creds))
	}
	keys := map[string]string{}
	for _, c := range creds {
		keys[c.Key] = string(c.Ciphertext)
	}
	if keys["A"] != "c1-new" {
		t.Fatalf("A not rotated, got %q", keys["A"])
	}
	if _, ok := keys["B"]; ok {
		t.Fatalf("B should have been deleted")
	}
	if keys["C"] != "c3" {
		t.Fatalf("C not inserted, got %q", keys["C"])
	}
}

func TestReplaceVaultCredentialsForSyncEmptyWipes(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, _ := s.CreateUser(ctx, "wipe@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)
	v, _ := s.CreateExternalVault(ctx, CreateExternalVaultParams{
		Name:                "wipe-vault",
		Kind:                "infisical",
		ConfigJSON:          `{}`,
		PollIntervalSeconds: 60,
		Credentials:         []EncryptedKV{{Key: "ONLY", Ciphertext: []byte("c"), Nonce: []byte("n")}},
		CreatorActorID:      u.ID,
		CreatorActorType:    "user",
	})

	if applied, err := s.ReplaceVaultCredentialsForSync(ctx, v.ID, `{}`, nil); err != nil || !applied {
		t.Fatalf("ReplaceVaultCredentialsForSync nil: applied=%v err=%v", applied, err)
	}
	creds, _ := s.ListCredentials(ctx, v.ID)
	if len(creds) != 0 {
		t.Fatalf("expected vault wiped, got %d creds", len(creds))
	}
}

func TestUpdateVaultCredentialStoreHealth(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, _ := s.CreateUser(ctx, "health@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)
	v, _ := s.CreateExternalVault(ctx, CreateExternalVaultParams{
		Name:                "health-vault",
		Kind:                "infisical",
		ConfigJSON:          `{}`,
		PollIntervalSeconds: 60,
		Credentials:         []EncryptedKV{{Key: "K", Ciphertext: []byte("c"), Nonce: []byte("n")}},
		CreatorActorID:      u.ID,
		CreatorActorType:    "user",
	})

	when := time.Now().UTC().Add(-time.Minute)
	if err := s.UpdateVaultCredentialStoreHealth(ctx, v.ID, "error", "boom", when); err != nil {
		t.Fatalf("UpdateVaultCredentialStoreHealth: %v", err)
	}
	cs, _ := s.GetVaultCredentialStore(ctx, v.ID)
	if cs.LastSyncStatus != "error" || cs.LastSyncError != "boom" {
		t.Fatalf("health not updated: %+v", cs)
	}
	// Clear the error on a subsequent ok update.
	if err := s.UpdateVaultCredentialStoreHealth(ctx, v.ID, "ok", "", time.Now().UTC()); err != nil {
		t.Fatalf("clear error: %v", err)
	}
	cs, _ = s.GetVaultCredentialStore(ctx, v.ID)
	if cs.LastSyncStatus != "ok" || cs.LastSyncError != "" {
		t.Fatalf("expected ok with empty error, got %+v", cs)
	}
}

func TestListVaultCredentialStoresFiltersBuiltin(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, _ := s.CreateUser(ctx, "list@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)

	// A builtin vault (no row in vault_credential_stores).
	if _, err := s.CreateVault(ctx, "plain"); err != nil {
		t.Fatal(err)
	}
	// Two external vaults.
	for _, name := range []string{"ext-a", "ext-b"} {
		if _, err := s.CreateExternalVault(ctx, CreateExternalVaultParams{
			Name: name, Kind: "infisical", ConfigJSON: `{}`, PollIntervalSeconds: 60,
			Credentials:      []EncryptedKV{{Key: "K", Ciphertext: []byte("c"), Nonce: []byte("n")}},
			CreatorActorID:   u.ID,
			CreatorActorType: "user",
		}); err != nil {
			t.Fatalf("CreateExternalVault %s: %v", name, err)
		}
	}

	list, err := s.ListVaultCredentialStores(ctx)
	if err != nil {
		t.Fatalf("ListVaultCredentialStores: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 external stores, got %d (%+v)", len(list), list)
	}
}

func TestSetVaultExternalStoreOverwritesBuiltin(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	v, err := s.CreateVault(ctx, "switch-up")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	// Seed built-in credentials that the connect should overwrite.
	if _, err := s.SetCredential(ctx, v.ID, "OLD_KEY", []byte("c-old"), []byte("n-old")); err != nil {
		t.Fatalf("SetCredential: %v", err)
	}

	cs, err := s.SetVaultExternalStore(ctx, SetVaultExternalStoreParams{
		VaultID:             v.ID,
		Kind:                CredentialStoreInfisical,
		ConfigJSON:          `{"project_id":"p","environment":"dev","secret_path":"/"}`,
		PollIntervalSeconds: 30,
		Credentials: []EncryptedKV{
			{Key: "NEW_KEY", Ciphertext: []byte("c-new"), Nonce: []byte("n-new")},
		},
	})
	if err != nil {
		t.Fatalf("SetVaultExternalStore: %v", err)
	}
	// The returned row reflects the write without a follow-up read.
	if cs == nil || cs.Kind != CredentialStoreInfisical || cs.PollIntervalSeconds != 30 || cs.LastSyncStatus != SyncStatusOK {
		t.Fatalf("unexpected returned row: %+v", cs)
	}

	cs, err = s.GetVaultCredentialStore(ctx, v.ID)
	if err != nil || cs == nil {
		t.Fatalf("GetVaultCredentialStore: %v cs=%+v", err, cs)
	}
	if cs.Kind != CredentialStoreInfisical || cs.PollIntervalSeconds != 30 || cs.LastSyncStatus != SyncStatusOK {
		t.Fatalf("unexpected store row: %+v", cs)
	}

	creds, _ := s.ListCredentials(ctx, v.ID)
	if len(creds) != 1 || creds[0].Key != "NEW_KEY" {
		t.Fatalf("expected only NEW_KEY after overwrite, got %+v", creds)
	}

	// Calling again upserts the row (reconfigure) without duplicating.
	if _, err = s.SetVaultExternalStore(ctx, SetVaultExternalStoreParams{
		VaultID:             v.ID,
		Kind:                CredentialStoreInfisical,
		ConfigJSON:          `{"project_id":"p2","environment":"prod","secret_path":"/x"}`,
		PollIntervalSeconds: 60,
		Credentials:         []EncryptedKV{{Key: "K2", Ciphertext: []byte("c"), Nonce: []byte("n")}},
	}); err != nil {
		t.Fatalf("SetVaultExternalStore re-run: %v", err)
	}
	cs, _ = s.GetVaultCredentialStore(ctx, v.ID)
	if cs.PollIntervalSeconds != 60 || cs.ConfigJSON != `{"project_id":"p2","environment":"prod","secret_path":"/x"}` {
		t.Fatalf("upsert did not update row: %+v", cs)
	}
	list, _ := s.ListVaultCredentialStores(ctx)
	if len(list) != 1 {
		t.Fatalf("expected single store row after upsert, got %d", len(list))
	}
}

func TestDeleteVaultCredentialStoreKeepsCredentials(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	u, _ := s.CreateUser(ctx, "disconnect@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)
	v, err := s.CreateExternalVault(ctx, CreateExternalVaultParams{
		Name:                "switch-down",
		Kind:                CredentialStoreInfisical,
		ConfigJSON:          `{}`,
		PollIntervalSeconds: 60,
		Credentials: []EncryptedKV{
			{Key: "SYNCED_KEY", Ciphertext: []byte("c"), Nonce: []byte("n")},
		},
		CreatorActorID:   u.ID,
		CreatorActorType: "user",
	})
	if err != nil {
		t.Fatalf("CreateExternalVault: %v", err)
	}

	if err := s.DeleteVaultCredentialStore(ctx, v.ID); err != nil {
		t.Fatalf("DeleteVaultCredentialStore: %v", err)
	}

	// Row is gone (vault is now built-in).
	if _, err := s.GetVaultCredentialStore(ctx, v.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows after delete, got %v", err)
	}
	list, _ := s.ListVaultCredentialStores(ctx)
	if len(list) != 0 {
		t.Fatalf("expected no external stores, got %d", len(list))
	}

	// Credentials are kept as built-in credentials.
	creds, _ := s.ListCredentials(ctx, v.ID)
	if len(creds) != 1 || creds[0].Key != "SYNCED_KEY" {
		t.Fatalf("expected SYNCED_KEY kept, got %+v", creds)
	}

	// Deleting again is a no-op (no row to remove).
	if err := s.DeleteVaultCredentialStore(ctx, v.ID); err != nil {
		t.Fatalf("DeleteVaultCredentialStore second call: %v", err)
	}
}

// ReplaceVaultCredentialsForSync writes only while the row still matches the
// config the snapshot was fetched against. This closes two races where an
// in-flight sync would clobber credentials: a concurrent disconnect, and a
// concurrent switch to a different Infisical config.
func TestReplaceVaultCredentialsForSyncGatedOnStoreRow(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	const cfgA = `{"project_id":"a","environment":"dev","secret_path":"/"}`
	u, _ := s.CreateUser(ctx, "sync@test.com", []byte("h"), []byte("s"), "owner", 3, 65536, 4)
	v, err := s.CreateExternalVault(ctx, CreateExternalVaultParams{
		Name:                "sync-race",
		Kind:                CredentialStoreInfisical,
		ConfigJSON:          cfgA,
		PollIntervalSeconds: 60,
		Credentials:         []EncryptedKV{{Key: "KEPT", Ciphertext: []byte("c"), Nonce: []byte("n")}},
		CreatorActorID:      u.ID,
		CreatorActorType:    "user",
	})
	if err != nil {
		t.Fatalf("CreateExternalVault: %v", err)
	}

	// Same config → the sync write lands.
	applied, err := s.ReplaceVaultCredentialsForSync(ctx, v.ID, cfgA, []EncryptedKV{
		{Key: "FRESH", Ciphertext: []byte("c2"), Nonce: []byte("n2")},
	})
	if err != nil || !applied {
		t.Fatalf("expected applied write, got applied=%v err=%v", applied, err)
	}
	creds, _ := s.ListCredentials(ctx, v.ID)
	if len(creds) != 1 || creds[0].Key != "FRESH" {
		t.Fatalf("expected FRESH after applied sync, got %+v", creds)
	}

	// Reconfigure to a different config, then a still-in-flight sync against the
	// OLD config: it must be a no-op so the switched-in credentials survive.
	if _, err := s.SetVaultExternalStore(ctx, SetVaultExternalStoreParams{
		VaultID:             v.ID,
		Kind:                CredentialStoreInfisical,
		ConfigJSON:          `{"project_id":"b","environment":"prod","secret_path":"/x"}`,
		PollIntervalSeconds: 60,
		Credentials:         []EncryptedKV{{Key: "SWITCHED", Ciphertext: []byte("c4"), Nonce: []byte("n4")}},
	}); err != nil {
		t.Fatalf("SetVaultExternalStore: %v", err)
	}
	applied, err = s.ReplaceVaultCredentialsForSync(ctx, v.ID, cfgA, []EncryptedKV{
		{Key: "STALE", Ciphertext: []byte("c3"), Nonce: []byte("n3")},
	})
	if err != nil {
		t.Fatalf("ReplaceVaultCredentialsForSync after reconfigure: %v", err)
	}
	if applied {
		t.Fatalf("expected applied=false after reconfigure")
	}
	creds, _ = s.ListCredentials(ctx, v.ID)
	if len(creds) != 1 || creds[0].Key != "SWITCHED" {
		t.Fatalf("expected SWITCHED credentials preserved after reconfigure, got %+v", creds)
	}

	// Disconnect entirely, then a still-in-flight sync: also a no-op.
	if err := s.DeleteVaultCredentialStore(ctx, v.ID); err != nil {
		t.Fatalf("DeleteVaultCredentialStore: %v", err)
	}
	applied, err = s.ReplaceVaultCredentialsForSync(ctx, v.ID, cfgA, []EncryptedKV{
		{Key: "STALE2", Ciphertext: []byte("c5"), Nonce: []byte("n5")},
	})
	if err != nil {
		t.Fatalf("ReplaceVaultCredentialsForSync after disconnect: %v", err)
	}
	if applied {
		t.Fatalf("expected applied=false after disconnect")
	}
	creds, _ = s.ListCredentials(ctx, v.ID)
	if len(creds) != 1 || creds[0].Key != "SWITCHED" {
		t.Fatalf("expected SWITCHED credentials preserved after disconnect, got %+v", creds)
	}
}

func TestListUnmatchedHosts(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	vA, err := s.CreateVault(ctx, "vault-a")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	vB, err := s.CreateVault(ctx, "vault-b")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	now := time.Now().UTC()
	rows := []RequestLog{
		// Unmatched, denied by proxy (error_code=no_match) -- should appear
		{VaultID: vA.ID, Ingress: "mitm", Method: "GET", Host: "api.stripe.com:443", Path: "/", MatchedService: "", Status: 403, ErrorCode: "no_match", CreatedAt: now.Add(-1 * time.Minute)},
		{VaultID: vA.ID, Ingress: "mitm", Method: "POST", Host: "api.stripe.com:443", Path: "/v1/charges", MatchedService: "", Status: 403, ErrorCode: "no_match", CreatedAt: now},

		// Unmatched, passthrough with upstream 401 -- should appear
		{VaultID: vA.ID, Ingress: "mitm", Method: "GET", Host: "api.openai.com:443", Path: "/v1/models", MatchedService: "", Status: 401, ErrorCode: "", CreatedAt: now.Add(-30 * time.Second)},

		// Unmatched, passthrough with upstream 403 -- should appear
		{VaultID: vA.ID, Ingress: "mitm", Method: "GET", Host: "hooks.slack.com:443", Path: "/", MatchedService: "", Status: 403, ErrorCode: "", CreatedAt: now.Add(-2 * time.Minute)},

		// Matched service -- should NOT appear (matched_service != '')
		{VaultID: vA.ID, Ingress: "mitm", Method: "GET", Host: "api.github.com:443", Path: "/", MatchedService: "github", Status: 200, ErrorCode: "", CreatedAt: now},

		// Unmatched, passthrough success (200) -- should NOT appear
		{VaultID: vA.ID, Ingress: "mitm", Method: "GET", Host: "public-api.example.com:443", Path: "/", MatchedService: "", Status: 200, ErrorCode: "", CreatedAt: now},

		// Unmatched, passthrough 500 (server error, not auth) -- should NOT appear
		{VaultID: vA.ID, Ingress: "mitm", Method: "GET", Host: "buggy.example.com:443", Path: "/", MatchedService: "", Status: 500, ErrorCode: "", CreatedAt: now},

		// Vault B: unmatched denied -- should NOT appear in vault A query
		{VaultID: vB.ID, Ingress: "mitm", Method: "GET", Host: "vault-b-only.com:443", Path: "/", MatchedService: "", Status: 403, ErrorCode: "no_match", CreatedAt: now},

		// Disabled service produces matched_service='' and error_code=no_match -- should appear at store level
		{VaultID: vA.ID, Ingress: "mitm", Method: "GET", Host: "disabled.example.com:443", Path: "/", MatchedService: "", Status: 403, ErrorCode: "no_match", CreatedAt: now.Add(-5 * time.Minute)},
	}
	if err := s.InsertRequestLogs(ctx, rows); err != nil {
		t.Fatalf("InsertRequestLogs: %v", err)
	}

	hosts, err := s.ListUnmatchedHosts(ctx, vA.ID)
	if err != nil {
		t.Fatalf("ListUnmatchedHosts: %v", err)
	}

	// Expected: api.stripe.com:443 (2 requests), api.openai.com:443 (1), hooks.slack.com:443 (1), disabled.example.com:443 (1)
	if len(hosts) != 4 {
		t.Fatalf("expected 4 unmatched hosts, got %d: %+v", len(hosts), hosts)
	}

	// Sorted by last_seen DESC: stripe (now), openai (now-30s), slack (now-2m), disabled (now-5m)
	if hosts[0].Host != "api.stripe.com:443" {
		t.Errorf("expected first host to be api.stripe.com:443, got %q", hosts[0].Host)
	}
	if hosts[0].RequestCount != 2 {
		t.Errorf("expected api.stripe.com to have 2 requests, got %d", hosts[0].RequestCount)
	}
	if hosts[1].Host != "api.openai.com:443" {
		t.Errorf("expected second host to be api.openai.com:443, got %q", hosts[1].Host)
	}
	if hosts[2].Host != "hooks.slack.com:443" {
		t.Errorf("expected third host to be hooks.slack.com:443, got %q", hosts[2].Host)
	}
	if hosts[3].Host != "disabled.example.com:443" {
		t.Errorf("expected fourth host to be disabled.example.com:443, got %q", hosts[3].Host)
	}

	// Vault B query should only return its own host
	hostsB, err := s.ListUnmatchedHosts(ctx, vB.ID)
	if err != nil {
		t.Fatalf("ListUnmatchedHosts vault B: %v", err)
	}
	if len(hostsB) != 1 || hostsB[0].Host != "vault-b-only.com:443" {
		t.Fatalf("vault B expected 1 host (vault-b-only.com:443), got %+v", hostsB)
	}

	// Empty vault should return nothing
	empty, err := s.ListUnmatchedHosts(ctx, "nonexistent-vault-id")
	if err != nil {
		t.Fatalf("ListUnmatchedHosts empty: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected 0 hosts for nonexistent vault, got %d", len(empty))
	}
}
