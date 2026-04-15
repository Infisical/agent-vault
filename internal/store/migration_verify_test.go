package store

import (
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
