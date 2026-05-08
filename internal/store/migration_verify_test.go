package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestMigrationOnDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	rows, err := s.db.Query("PRAGMA table_info(agents)")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull int
		var dflt *string
		var pk int
		rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk)
		if name == "service_token_hash" {
			t.Fatal("agents table still has service_token_hash column after migration 035")
		}
	}
	t.Log("OK: agents table schema is correct")
}

// TestUpdateRolePromotionToOwnerClearsGrants verifies that promoting a user
// or agent to 'owner' atomically deletes their vault_grants rows so the
// invariant from migration 045 (owners auto-access every vault, never
// stored in vault_grants) is preserved across the actor's lifetime.
func TestUpdateRolePromotionToOwnerClearsGrants(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	ctx := context.Background()
	nowStr := nowUTC()
	if _, err := s.db.Exec(
		"INSERT INTO vaults (id, name, created_at, updated_at) VALUES ('v1', 'v1', ?, ?), ('v2', 'v2', ?, ?)",
		nowStr, nowStr, nowStr, nowStr,
	); err != nil {
		t.Fatalf("seeding vaults: %v", err)
	}

	// User: admin with grants on v1 and v2.
	if _, err := s.CreateUser(ctx, "admin@example.com", []byte("h"), []byte("s"), "admin", 1, 64*1024, 1); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	u, _ := s.GetUserByEmail(ctx, "admin@example.com")
	if err := s.GrantVaultAccess(ctx, u.ID, "user", "v1"); err != nil {
		t.Fatalf("grant v1: %v", err)
	}
	if err := s.GrantVaultAccess(ctx, u.ID, "user", "v2"); err != nil {
		t.Fatalf("grant v2: %v", err)
	}

	if err := s.UpdateUserRole(ctx, u.ID, "owner"); err != nil {
		t.Fatalf("UpdateUserRole: %v", err)
	}
	var n int
	if err := s.db.QueryRow(
		"SELECT COUNT(*) FROM vault_grants WHERE actor_id = ? AND actor_type = 'user'", u.ID,
	).Scan(&n); err != nil {
		t.Fatalf("counting user grants: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected owner promotion to clear user grants, got %d", n)
	}

	// Agent: admin with grants on v1.
	a, err := s.CreateAgent(ctx, "bot1", u.ID, "admin")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if err := s.GrantVaultAccess(ctx, a.ID, "agent", "v1"); err != nil {
		t.Fatalf("grant agent v1: %v", err)
	}

	if err := s.UpdateAgentRole(ctx, a.ID, "owner"); err != nil {
		t.Fatalf("UpdateAgentRole: %v", err)
	}
	if err := s.db.QueryRow(
		"SELECT COUNT(*) FROM vault_grants WHERE actor_id = ? AND actor_type = 'agent'", a.ID,
	).Scan(&n); err != nil {
		t.Fatalf("counting agent grants: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected owner promotion to clear agent grants, got %d", n)
	}
}

// TestRegisterFirstUserAfterMigrations exercises the full first-user
// onboarding path against a freshly migrated DB. Regression for the bug
// where RegisterFirstUser tried to insert into the dropped `role` column on
// vault_grants after migration 045, which would 500 every fresh install.
func TestRegisterFirstUserAfterMigrations(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	user, err := s.RegisterFirstUser(
		context.Background(),
		"first@example.com",
		[]byte("hash"),
		[]byte("salt"),
		1, 64*1024, 1,
	)
	if err != nil {
		t.Fatalf("RegisterFirstUser failed: %v", err)
	}
	if user.Role != "owner" {
		t.Fatalf("expected role=owner, got %q", user.Role)
	}

	// Owners auto-access every vault — they should have no vault_grants row.
	var grantCount int
	if err := s.db.QueryRow(
		"SELECT COUNT(*) FROM vault_grants WHERE actor_id = ?", user.ID,
	).Scan(&grantCount); err != nil {
		t.Fatalf("counting grants: %v", err)
	}
	if grantCount != 0 {
		t.Fatalf("expected owner to have no vault_grants rows, got %d", grantCount)
	}
}
