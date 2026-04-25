package store

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func tp(t time.Time) *time.Time { return &t }

func openTestDB(t *testing.T) *SQLiteStore {
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

	// Verify schema_migrations has version 1.
	var version int
	err := s.db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version)
	if err != nil {
		t.Fatalf("querying schema_migrations: %v", err)
	}
	if version != 40 {
		t.Fatalf("expected migration version 40, got %d", version)
	}
}

func TestMigrationIdempotency(t *testing.T) {
	// Opening twice against the same DB should not fail.
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}

	// Run migrate again on the same connection.
	if err := migrate(s.db); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	s.Close()
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

	sess, err := s.CreateScopedSession(ctx, ns.ID, "proxy", &expires)
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
	// Second insert should fail (CHECK constraint: id = 1).
	if err := s.SetMasterKeyRecord(ctx, rec); err == nil {
		t.Fatal("expected error on duplicate master key insert")
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

	err := s.ApplyProposal(ctx, ns.ID, 1, mergedServices, creds, nil)
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

	err := s.ApplyProposal(ctx, ns.ID, 1, mergedServices, creds, []string{"old_key"})
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

// --- Invites ---

func TestCreateAgentInvite(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	inv, err := s.CreateAgentInvite(ctx, "testbot", "admin", time.Now().Add(15*time.Minute), 0, "member", nil)
	if err != nil {
		t.Fatalf("CreateAgentInvite: %v", err)
	}
	if inv.Status != "pending" {
		t.Fatalf("expected status pending, got %s", inv.Status)
	}
	if len(inv.Token) < 7 || inv.Token[:7] != "av_inv_" {
		t.Fatalf("unexpected token format: %s", inv.Token)
	}
	if inv.AgentName != "testbot" {
		t.Fatalf("expected agent_name testbot, got %s", inv.AgentName)
	}
}

func TestRedeemInvite(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	inv, _ := s.CreateAgentInvite(ctx, "redeembot", "admin", time.Now().Add(15*time.Minute), 0, "member", nil)

	err := s.RedeemInvite(ctx, inv.Token, "sess-123")
	if err != nil {
		t.Fatalf("RedeemInvite: %v", err)
	}

	got, err := s.GetInviteByToken(ctx, inv.Token)
	if err != nil {
		t.Fatalf("GetInviteByToken: %v", err)
	}
	if got.Status != "redeemed" {
		t.Fatalf("expected status redeemed, got %s", got.Status)
	}
	if got.SessionID != "sess-123" {
		t.Fatalf("expected session_id sess-123, got %s", got.SessionID)
	}
	if got.RedeemedAt == nil {
		t.Fatal("expected redeemed_at to be set")
	}
}

func TestRedeemInvite_Expired(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	inv, _ := s.CreateAgentInvite(ctx, "expiredbot", "admin", time.Now().Add(-1*time.Minute), 0, "member", nil)

	err := s.RedeemInvite(ctx, inv.Token, "sess-456")
	if err != sql.ErrNoRows {
		t.Fatalf("expected ErrNoRows for expired invite, got %v", err)
	}
}

func TestRedeemInvite_AlreadyRedeemed(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	inv, _ := s.CreateAgentInvite(ctx, "doublebot", "admin", time.Now().Add(15*time.Minute), 0, "member", nil)
	s.RedeemInvite(ctx, inv.Token, "sess-1")

	err := s.RedeemInvite(ctx, inv.Token, "sess-2")
	if err != sql.ErrNoRows {
		t.Fatalf("expected ErrNoRows for already-redeemed invite, got %v", err)
	}
}

func TestRevokeInvite(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	inv, _ := s.CreateAgentInvite(ctx, "revokebot", "admin", time.Now().Add(15*time.Minute), 0, "member", nil)

	if err := s.RevokeInvite(ctx, inv.Token); err != nil {
		t.Fatalf("RevokeInvite: %v", err)
	}

	got, _ := s.GetInviteByToken(ctx, inv.Token)
	if got.Status != "revoked" {
		t.Fatalf("expected status revoked, got %s", got.Status)
	}
	if got.RevokedAt == nil {
		t.Fatal("expected revoked_at to be set")
	}
}

func TestCountPendingInvites(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	inv1, _ := s.CreateAgentInvite(ctx, "countbot1", "admin", time.Now().Add(15*time.Minute), 0, "member", nil)
	s.CreateAgentInvite(ctx, "countbot2", "admin", time.Now().Add(15*time.Minute), 0, "member", nil)

	count, err := s.CountPendingInvites(ctx)
	if err != nil {
		t.Fatalf("CountPendingInvites: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 pending invites, got %d", count)
	}

	// Revoke one — count should drop.
	s.RevokeInvite(ctx, inv1.Token)

	count, _ = s.CountPendingInvites(ctx)
	if count != 1 {
		t.Fatalf("expected 1 pending invite after revoke, got %d", count)
	}
}

func TestExpirePendingInvites(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	// Create two invites: one already expired, one still valid.
	s.CreateAgentInvite(ctx, "expirebot1", "admin", time.Now().Add(-1*time.Minute), 0, "member", nil)
	s.CreateAgentInvite(ctx, "expirebot2", "admin", time.Now().Add(15*time.Minute), 0, "member", nil)

	n, err := s.ExpirePendingInvites(ctx, time.Now())
	if err != nil {
		t.Fatalf("ExpirePendingInvites: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 expired invite, got %d", n)
	}

	pending, _ := s.ListInvites(ctx, "pending")
	if len(pending) != 1 {
		t.Fatalf("expected 1 remaining pending invite, got %d", len(pending))
	}
}

func TestListInvites(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	s.CreateAgentInvite(ctx, "listbot1", "admin", time.Now().Add(15*time.Minute), 0, "member", nil)
	inv2, _ := s.CreateAgentInvite(ctx, "listbot2", "admin", time.Now().Add(15*time.Minute), 0, "member", nil)
	s.RevokeInvite(ctx, inv2.Token)

	// All invites.
	all, _ := s.ListInvites(ctx, "")
	if len(all) != 2 {
		t.Fatalf("expected 2 total invites, got %d", len(all))
	}

	// Pending only.
	pending, _ := s.ListInvites(ctx, "pending")
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending invite, got %d", len(pending))
	}

	// Revoked only.
	revoked, _ := s.ListInvites(ctx, "revoked")
	if len(revoked) != 1 {
		t.Fatalf("expected 1 revoked invite, got %d", len(revoked))
	}
}

func TestInviteWithVaultPreAssignment(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	ns, _ := s.GetVault(ctx, "default")

	inv, err := s.CreateAgentInvite(ctx, "vaultbot", "admin", time.Now().Add(15*time.Minute), 0, "member", []AgentInviteVault{
		{VaultID: ns.ID, VaultRole: "proxy"},
	})
	if err != nil {
		t.Fatalf("CreateAgentInvite with vaults: %v", err)
	}
	if len(inv.Vaults) != 1 {
		t.Fatalf("expected 1 vault pre-assignment, got %d", len(inv.Vaults))
	}
	if inv.Vaults[0].VaultRole != "proxy" {
		t.Fatalf("expected vault role proxy, got %s", inv.Vaults[0].VaultRole)
	}

	// Fetch and verify vaults are loaded.
	fetched, _ := s.GetInviteByToken(ctx, inv.Token)
	if len(fetched.Vaults) != 1 {
		t.Fatalf("fetched invite: expected 1 vault, got %d", len(fetched.Vaults))
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
	sess, _ := s.CreateScopedSession(ctx, ns.ID, "proxy", tp(time.Now().Add(24*time.Hour)))

	fetched, err := s.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if fetched.AgentID != "" {
		t.Fatalf("expected empty agent_id for old session, got %q", fetched.AgentID)
	}
}

func TestCreateAgentInviteWithVaults(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.GetVault(ctx, "default")
	inv, err := s.CreateAgentInvite(ctx, "mybot", "creator1", time.Now().Add(15*time.Minute), 0, "member", []AgentInviteVault{
		{VaultID: ns.ID, VaultRole: "proxy"},
	})
	if err != nil {
		t.Fatalf("CreateAgentInvite: %v", err)
	}
	if inv.AgentName != "mybot" {
		t.Fatalf("expected agent_name mybot, got %s", inv.AgentName)
	}
	if len(inv.Vaults) != 1 {
		t.Fatalf("expected 1 vault, got %d", len(inv.Vaults))
	}

	// Fetch and verify.
	fetched, _ := s.GetInviteByToken(ctx, inv.Token)
	if fetched.AgentName != "mybot" {
		t.Fatalf("fetched agent_name: expected mybot, got %s", fetched.AgentName)
	}
	if len(fetched.Vaults) != 1 {
		t.Fatalf("fetched: expected 1 vault, got %d", len(fetched.Vaults))
	}
}

func TestCreateRotationInvite(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ag, _ := s.CreateAgent(ctx, "rotatebot", "c", "member")

	inv, err := s.CreateRotationInvite(ctx, ag.ID, "creator1", time.Now().Add(15*time.Minute))
	if err != nil {
		t.Fatalf("CreateRotationInvite: %v", err)
	}
	if inv.AgentID != ag.ID {
		t.Fatalf("expected agent_id %s, got %s", ag.ID, inv.AgentID)
	}

	// Fetch and verify.
	fetched, _ := s.GetInviteByToken(ctx, inv.Token)
	if fetched.AgentID != ag.ID {
		t.Fatalf("fetched: expected agent_id %s, got %s", ag.ID, fetched.AgentID)
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
