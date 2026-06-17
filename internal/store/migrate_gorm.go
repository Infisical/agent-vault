package store

import (
	"database/sql"
	"fmt"
	"sort"
	"sync"

	"gorm.io/gorm"
	gormPG "gorm.io/driver/postgres"
	gormSQLite "gorm.io/driver/sqlite"
)

// GORMMigration is a single versioned schema change using GORM.
type GORMMigration struct {
	Version int
	Name    string
	Fn      func(db *gorm.DB) error
}

var (
	gormMigrations []GORMMigration
	gormMigMu      sync.Mutex
)

// RegisterGORMMigration adds a GORM-based migration to the global registry.
// Called from init() in each migration file.
func RegisterGORMMigration(version int, name string, fn func(db *gorm.DB) error) {
	gormMigMu.Lock()
	defer gormMigMu.Unlock()
	gormMigrations = append(gormMigrations, GORMMigration{Version: version, Name: name, Fn: fn})
}

// runGORMMigrations applies any pending GORM-based migrations.
// It wraps the existing *sql.DB in a GORM instance for DDL, then GORM
// is done. The *sql.DB continues to serve runtime queries.
//
// This runs AFTER the SQL-file migrations, so it picks up from whatever
// version the SQL runner left off at.
func runGORMMigrations(sqlDB *sql.DB, dialectName string) error {
	if len(gormMigrations) == 0 {
		return nil
	}

	var dialector gorm.Dialector
	switch dialectName {
	case "sqlite":
		dialector = gormSQLite.Dialector{Conn: sqlDB}
	case "postgres":
		dialector = gormPG.New(gormPG.Config{Conn: sqlDB})
	default:
		return fmt.Errorf("unknown dialect for GORM: %s", dialectName)
	}

	gormDB, err := gorm.Open(dialector, &gorm.Config{
		DisableAutomaticPing: true,
	})
	if err != nil {
		return fmt.Errorf("initializing gorm for migrations: %w", err)
	}

	// Ensure the name column exists on schema_migrations.
	if err := ensureNameColumn(sqlDB, dialectName); err != nil {
		return fmt.Errorf("adding name column to schema_migrations: %w", err)
	}

	// Find current version.
	var current int
	sqlDB.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&current)

	// Sort and apply pending migrations.
	sorted := make([]GORMMigration, len(gormMigrations))
	copy(sorted, gormMigrations)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Version < sorted[j].Version
	})

	for _, m := range sorted {
		if m.Version <= current {
			continue
		}

		if err := gormDB.Transaction(func(tx *gorm.DB) error {
			if err := m.Fn(tx); err != nil {
				return err
			}
			return tx.Exec(
				"INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
				m.Version, m.Name,
			).Error
		}); err != nil {
			return fmt.Errorf("gorm migration %d (%s): %w", m.Version, m.Name, err)
		}
	}

	return nil
}

// ensureNameColumn adds the "name" column to schema_migrations if it
// doesn't exist. Idempotent on both SQLite and Postgres.
func ensureNameColumn(db *sql.DB, dialect string) error {
	switch dialect {
	case "postgres":
		_, err := db.Exec("ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS name TEXT")
		return err
	case "sqlite":
		hasName := false
		rows, err := db.Query("PRAGMA table_info(schema_migrations)")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var cid int
			var colName, colType string
			var notNull int
			var dflt sql.NullString
			var pk int
			if err := rows.Scan(&cid, &colName, &colType, &notNull, &dflt, &pk); err != nil {
				return err
			}
			if colName == "name" {
				hasName = true
			}
		}
		if !hasName {
			_, err := db.Exec("ALTER TABLE schema_migrations ADD COLUMN name TEXT")
			return err
		}
		return nil
	default:
		return fmt.Errorf("unknown dialect: %s", dialect)
	}
}
