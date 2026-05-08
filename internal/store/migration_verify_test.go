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
