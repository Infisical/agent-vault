package store

// GORM-based migrations. Each init() registers a migration that works
// on both SQLite and Postgres. GORM handles dialect differences.
//
// Migration 052 is deliberately a no-op (the name column is added by
// ensureNameColumn in the GORM runner bootstrap, before any GORM
// migrations execute). We register it here to:
// 1. Prove the GORM migration path works end-to-end
// 2. Record the version in schema_migrations with a name
// 3. Serve as the template for future migrations
//
// Future migrations go in this file (or new files in this package)
// using RegisterGORMMigration(version, name, func).

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(52, "052_schema_migrations_name_column", func(db *gorm.DB) error {
		// The name column is already added by ensureNameColumn() in the
		// GORM runner bootstrap. This migration just records the fact
		// in schema_migrations so the version advances to 52.
		return nil
	})
}
