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
	if version != 35 {
		t.Fatalf("expected migration version 35, got %d", version)
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

	expires := time.Now().Add(1 * time.Hour).UTC().Truncate(time.Second)

	sess, err := s.CreateSession(ctx, "", expires)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
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

	expires := time.Now().Add(1 * time.Hour).UTC().Truncate(time.Second)
	sess, err := s.CreateSession(ctx, "", expires)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
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

func TestMasterKeyRecordRoundTrip(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	in := &MasterKeyRecord{
		Salt:       []byte("test-salt-16byte"),
		Sentinel:   []byte("encrypted-sentinel"),
		Nonce:      []byte("test-nonce-12"),
		KDFTime:    3,
		KDFMemory:  65536,
		KDFThreads: 4,
	}
	if err := s.SetMasterKeyRecord(ctx, in); err != nil {
		t.Fatalf("SetMasterKeyRecord: %v", err)
	}

	got, err := s.GetMasterKeyRecord(ctx)
	if err != nil {
		t.Fatalf("GetMasterKeyRecord: %v", err)
	}
	if string(got.Salt) != string(in.Salt) ||
		string(got.Sentinel) != string(in.Sentinel) ||
		string(got.Nonce) != string(in.Nonce) ||
		got.KDFTime != in.KDFTime ||
		got.KDFMemory != in.KDFMemory ||
		got.KDFThreads != in.KDFThreads {
		t.Fatalf("round-trip mismatch: got %+v", got)
	}
}

func TestMasterKeyRecordSingleton(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	rec := &MasterKeyRecord{
		Salt: []byte("s"), Sentinel: []byte("e"), Nonce: []byte("n"),
		KDFTime: 1, KDFMemory: 1024, KDFThreads: 1,
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

	inv, err := s.CreateAgentInvite(ctx, "testbot", "admin", time.Now().Add(15*time.Minute), 0, nil)
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

	inv, _ := s.CreateAgentInvite(ctx, "redeembot", "admin", time.Now().Add(15*time.Minute), 0, nil)

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

	inv, _ := s.CreateAgentInvite(ctx, "expiredbot", "admin", time.Now().Add(-1*time.Minute), 0, nil)

	err := s.RedeemInvite(ctx, inv.Token, "sess-456")
	if err != sql.ErrNoRows {
		t.Fatalf("expected ErrNoRows for expired invite, got %v", err)
	}
}

func TestRedeemInvite_AlreadyRedeemed(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	inv, _ := s.CreateAgentInvite(ctx, "doublebot", "admin", time.Now().Add(15*time.Minute), 0, nil)
	s.RedeemInvite(ctx, inv.Token, "sess-1")

	err := s.RedeemInvite(ctx, inv.Token, "sess-2")
	if err != sql.ErrNoRows {
		t.Fatalf("expected ErrNoRows for already-redeemed invite, got %v", err)
	}
}

func TestRevokeInvite(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	inv, _ := s.CreateAgentInvite(ctx, "revokebot", "admin", time.Now().Add(15*time.Minute), 0, nil)

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

	inv1, _ := s.CreateAgentInvite(ctx, "countbot1", "admin", time.Now().Add(15*time.Minute), 0, nil)
	s.CreateAgentInvite(ctx, "countbot2", "admin", time.Now().Add(15*time.Minute), 0, nil)

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
	s.CreateAgentInvite(ctx, "expirebot1", "admin", time.Now().Add(-1*time.Minute), 0, nil)
	s.CreateAgentInvite(ctx, "expirebot2", "admin", time.Now().Add(15*time.Minute), 0, nil)

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

	s.CreateAgentInvite(ctx, "listbot1", "admin", time.Now().Add(15*time.Minute), 0, nil)
	inv2, _ := s.CreateAgentInvite(ctx, "listbot2", "admin", time.Now().Add(15*time.Minute), 0, nil)
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

	inv, err := s.CreateAgentInvite(ctx, "vaultbot", "admin", time.Now().Add(15*time.Minute), 0, []AgentInviteVault{
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
	if err := s.GrantVaultRole(ctx, u.ID, ns.ID, "member"); err != nil {
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
	grants, err := s.ListUserGrants(ctx, u.ID)
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
	s.GrantVaultRole(ctx, u.ID, ns.ID, "member")
	if err := s.GrantVaultRole(ctx, u.ID, ns.ID, "member"); err != nil {
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
	sess, _ := s.CreateSession(ctx, u.ID, time.Now().Add(24*time.Hour))

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
	s.GrantVaultRole(ctx, u.ID, ns.ID, "member")

	// Delete user — grants should cascade
	s.DeleteUser(ctx, u.ID)

	grants, _ := s.ListUserGrants(ctx, u.ID)
	if len(grants) != 0 {
		t.Fatalf("expected 0 grants after user deletion, got %d", len(grants))
	}
}

// --- Agent Tests ---

func TestCreateAgent(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ag, err := s.CreateAgent(ctx, "claudebot", "creator1")
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

	s.CreateAgent(ctx, "myagent", "creator1")

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
	a1, _ := s.CreateAgent(ctx, "a1", "c")
	a2, _ := s.CreateAgent(ctx, "a2", "c")
	a3, _ := s.CreateAgent(ctx, "a3", "c")

	// Grant vault access.
	s.GrantAgentVaultRole(ctx, a1.ID, ns.ID, "proxy")
	s.GrantAgentVaultRole(ctx, a2.ID, ns.ID, "proxy")
	s.GrantAgentVaultRole(ctx, a3.ID, ns2.ID, "proxy")

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

	_, err := s.CreateAgent(ctx, "dup", "c")
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err = s.CreateAgent(ctx, "dup", "c")
	if err == nil {
		t.Fatal("expected error for duplicate agent name")
	}
}

func TestRevokeAgent(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ag, _ := s.CreateAgent(ctx, "torevoke", "c")

	// Create a session for this agent.
	sess, err := s.CreateAgentSession(ctx, ag.ID, tp(time.Now().Add(24*time.Hour)))
	if err != nil {
		t.Fatalf("CreateAgentSession: %v", err)
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

	ag, _ := s.CreateAgent(ctx, "oldname", "c")

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

func TestCountAgentSessions(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ag, _ := s.CreateAgent(ctx, "counter", "c")

	count, _ := s.CountAgentSessions(ctx, ag.ID)
	if count != 0 {
		t.Fatalf("expected 0 sessions, got %d", count)
	}

	s.CreateAgentSession(ctx, ag.ID, tp(time.Now().Add(24*time.Hour)))
	s.CreateAgentSession(ctx, ag.ID, tp(time.Now().Add(24*time.Hour)))

	count, _ = s.CountAgentSessions(ctx, ag.ID)
	if count != 2 {
		t.Fatalf("expected 2 sessions, got %d", count)
	}

	// Expired sessions should not be counted.
	s.CreateAgentSession(ctx, ag.ID, tp(time.Now().Add(-1*time.Hour)))
	count, _ = s.CountAgentSessions(ctx, ag.ID)
	if count != 2 {
		t.Fatalf("expected 2 active sessions (1 expired), got %d", count)
	}
}

func TestCreateAgentSession(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ag, _ := s.CreateAgent(ctx, "sessbot", "c")

	sess, err := s.CreateAgentSession(ctx, ag.ID, tp(time.Now().Add(24*time.Hour)))
	if err != nil {
		t.Fatalf("CreateAgentSession: %v", err)
	}
	if sess.AgentID != ag.ID {
		t.Fatalf("expected agent_id %s, got %s", ag.ID, sess.AgentID)
	}
	// Instance-level agent sessions have empty VaultID.
	if sess.VaultID != "" {
		t.Fatalf("expected empty vault_id for agent session, got %s", sess.VaultID)
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
	inv, err := s.CreateAgentInvite(ctx, "mybot", "creator1", time.Now().Add(15*time.Minute), 0, []AgentInviteVault{
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

	ag, _ := s.CreateAgent(ctx, "rotatebot", "c")

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

func TestDeleteAgentSessions(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ag, _ := s.CreateAgent(ctx, "delbot", "c")

	s.CreateAgentSession(ctx, ag.ID, tp(time.Now().Add(24*time.Hour)))
	s.CreateAgentSession(ctx, ag.ID, tp(time.Now().Add(24*time.Hour)))

	count, _ := s.CountAgentSessions(ctx, ag.ID)
	if count != 2 {
		t.Fatalf("expected 2 sessions before delete, got %d", count)
	}

	err := s.DeleteAgentSessions(ctx, ag.ID)
	if err != nil {
		t.Fatalf("DeleteAgentSessions: %v", err)
	}

	count, _ = s.CountAgentSessions(ctx, ag.ID)
	if count != 0 {
		t.Fatalf("expected 0 sessions after delete, got %d", count)
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
