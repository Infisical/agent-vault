package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// GORMMigration is a single versioned schema change using GORM.
// Name is derived from the caller's filename (e.g., "20260617143022_add_ca_state").
type GORMMigration struct {
	Name string
	Fn   func(db *gorm.DB) error
}

var (
	gormMigrations []GORMMigration
	gormMigMu      sync.Mutex
)

// RegisterGORMMigration adds a GORM-based migration to the global registry.
// The migration name is automatically derived from the caller's filename
// (e.g., "20260617143022_add_ca_state.go" becomes "20260617143022_add_ca_state").
// Call this from init() in each migration file.
func RegisterGORMMigration(fn func(db *gorm.DB) error) {
	_, file, _, ok := runtime.Caller(1)
	if !ok {
		panic("RegisterGORMMigration: cannot determine caller filename")
	}
	name := strings.TrimSuffix(filepath.Base(file), ".go")

	gormMigMu.Lock()
	defer gormMigMu.Unlock()
	gormMigrations = append(gormMigrations, GORMMigration{Name: name, Fn: fn})
}

// runGORMMigrations applies any pending GORM-based migrations.
// On Postgres, it acquires an advisory lock on a pinned connection
// to prevent concurrent migration runs across pods.
func runGORMMigrations(sqlDB *sql.DB, dialectName string) error {
	if len(gormMigrations) == 0 {
		return nil
	}

	// For Postgres: pin a connection and acquire an advisory lock.
	if dialectName == "postgres" {
		ctx := context.Background()
		conn, err := sqlDB.Conn(ctx)
		if err != nil {
			return fmt.Errorf("acquiring connection for migration lock: %w", err)
		}
		defer func() { _ = conn.Close() }()

		if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", int64(7956324891)); err != nil {
			return fmt.Errorf("acquiring migration lock: %w", err)
		}
		defer func() { _, _ = conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", int64(7956324891)) }()
	}

	var dialector gorm.Dialector
	switch dialectName {
	case "sqlite":
		dialector = sqlite.Dialector{Conn: sqlDB}
	case "postgres":
		dialector = postgres.New(postgres.Config{Conn: sqlDB})
	default:
		return fmt.Errorf("unknown dialect for GORM: %s", dialectName)
	}

	// Upgrade schema_migrations table to the new format BEFORE opening
	// GORM, because GORM may hold the single SQLite connection.
	if err := upgradeSchemamigrationsTable(sqlDB, dialectName); err != nil {
		return fmt.Errorf("upgrading schema_migrations table: %w", err)
	}

	// Build set of already-applied migration names.
	applied, err := loadAppliedMigrations(sqlDB)
	if err != nil {
		return fmt.Errorf("loading applied migrations: %w", err)
	}

	// Sort migrations by name (timestamp prefix ensures chronological order).
	sorted := make([]GORMMigration, len(gormMigrations))
	copy(sorted, gormMigrations)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})

	// Check if any migrations are pending before opening GORM.
	hasPending := false
	for _, m := range sorted {
		if !applied[m.Name] {
			hasPending = true
			break
		}
	}
	if !hasPending {
		return nil
	}

	// Disable FK checks for SQLite migrations. Many legacy migrations
	// do DROP TABLE + RENAME which would cascade-delete FK-referenced
	// rows if FKs are enforced. PRAGMA must be set outside transactions.
	if dialectName == "sqlite" {
		if _, err := sqlDB.Exec("PRAGMA foreign_keys = OFF"); err != nil {
			return fmt.Errorf("disabling foreign keys: %w", err)
		}
		defer sqlDB.Exec("PRAGMA foreign_keys = ON") //nolint:errcheck
	}

	// Open GORM only when we have pending migrations.
	gormDB, err := gorm.Open(dialector, &gorm.Config{
		DisableAutomaticPing: true,
	})
	if err != nil {
		return fmt.Errorf("initializing gorm for migrations: %w", err)
	}

	// Apply pending migrations.
	for _, m := range sorted {
		if applied[m.Name] {
			continue
		}

		if err := gormDB.Transaction(func(tx *gorm.DB) error {
			if err := m.Fn(tx); err != nil {
				return err
			}
			// Extract integer version from name prefix for backward compat
			// with older binaries that read MAX(version). Only for small
			// sequential versions (001-999); timestamp-prefixed names
			// overflow int4 on Postgres.
			var version *int
			var v int
			if _, err := fmt.Sscanf(m.Name, "%d_", &v); err == nil && v < 1000 {
				version = &v
			}
			return tx.Exec(
				"INSERT INTO schema_migrations (name, version) VALUES (?, ?)",
				m.Name, version,
			).Error
		}); err != nil {
			return fmt.Errorf("migration %s: %w", m.Name, err)
		}
	}

	return nil
}

// upgradeSchemamigrationsTable transitions from the old format
// (version INTEGER PRIMARY KEY, applied_at) to the new format
// (id auto-increment, name TEXT UNIQUE, migration_time).
//
// For existing databases, it renames the old table, creates the new
// one, and backfills the old version-based entries with their names.
func upgradeSchemamigrationsTable(db *sql.DB, dialect string) error {
	// Check if the table exists at all.
	tableExists, err := tableExists(db, dialect, "schema_migrations")
	if err != nil {
		return err
	}

	if !tableExists {
		// Fresh install -- create the new format directly.
		// Includes version and applied_at columns for backward compat
		// with older binaries that query SELECT MAX(version).
		switch dialect {
		case "sqlite":
			_, err = db.Exec(`CREATE TABLE schema_migrations (
				id             INTEGER PRIMARY KEY AUTOINCREMENT,
				name           TEXT NOT NULL UNIQUE,
				version        INTEGER,
				migration_time TEXT NOT NULL DEFAULT (datetime('now')),
				applied_at     TEXT NOT NULL DEFAULT (datetime('now'))
			)`)
		case "postgres":
			_, err = db.Exec(`CREATE TABLE schema_migrations (
				id             SERIAL PRIMARY KEY,
				name           TEXT NOT NULL UNIQUE,
				version        INTEGER,
				migration_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				applied_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
			)`)
		}
		return err
	}

	// Check if the table already has the 'name' column (new format).
	hasName, err := columnExists(db, dialect, "schema_migrations", "name")
	if err != nil {
		return err
	}

	if hasName {
		return nil
	}

	// Old format exists -- migrate it.
	// 1. Rename old table.
	if _, err := db.Exec("ALTER TABLE schema_migrations RENAME TO schema_migrations_old"); err != nil {
		return fmt.Errorf("renaming old table: %w", err)
	}

	// 2. Create new table (with version + applied_at for backward compat).
	switch dialect {
	case "sqlite":
		_, err = db.Exec(`CREATE TABLE schema_migrations (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			name           TEXT NOT NULL UNIQUE,
			version        INTEGER,
			migration_time TEXT NOT NULL DEFAULT (datetime('now')),
			applied_at     TEXT NOT NULL DEFAULT (datetime('now'))
		)`)
	case "postgres":
		_, err = db.Exec(`CREATE TABLE schema_migrations (
			id             SERIAL PRIMARY KEY,
			name           TEXT NOT NULL UNIQUE,
			version        INTEGER,
			migration_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			applied_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`)
	}
	if err != nil {
		return fmt.Errorf("creating new table: %w", err)
	}

	// 3. Backfill old entries: version N -> name from the embedded SQL filenames.
	// Read all versions first, then close rows before inserting (SQLite
	// MaxOpenConns=1 deadlocks if rows are open during INSERT).
	rows, err := db.Query("SELECT version FROM schema_migrations_old ORDER BY version")
	if err != nil {
		return fmt.Errorf("reading old migrations: %w", err)
	}
	var oldVersions []int
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			_ = rows.Close()
			return err
		}
		oldVersions = append(oldVersions, version)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	nameMap := buildVersionToNameMap()
	for _, version := range oldVersions {
		name, ok := nameMap[version]
		if !ok {
			name = fmt.Sprintf("%03d_unknown", version)
		}
		q := "INSERT INTO schema_migrations (name, version) VALUES (?, ?)"
		if dialect == "postgres" {
			q = "INSERT INTO schema_migrations (name, version) VALUES ($1, $2)"
		}
		if _, err := db.Exec(q, name, version); err != nil {
			return fmt.Errorf("backfilling version %d: %w", version, err)
		}
	}

	// 4. Drop old table.
	if _, err := db.Exec("DROP TABLE schema_migrations_old"); err != nil {
		return fmt.Errorf("dropping old table: %w", err)
	}

	return nil
}

// loadAppliedMigrations returns a set of migration names that have been applied.
func loadAppliedMigrations(db *sql.DB) (map[string]bool, error) {
	rows, err := db.Query("SELECT name FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	applied := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		applied[name] = true
	}
	return applied, rows.Err()
}

// buildVersionToNameMap creates a version -> name mapping from the registered
// GORM migrations. Old migrations (001_init, etc.) have names that start with
// zero-padded numbers which parse to the original version integers.
func buildVersionToNameMap() map[int]string {
	m := make(map[int]string)
	for _, gm := range gormMigrations {
		var version int
		name := gm.Name
		if _, err := fmt.Sscanf(name, "%d_", &version); err == nil {
			m[version] = name
		}
	}
	return m
}

// tableExists checks if a table exists in the database.
func tableExists(db *sql.DB, dialect, table string) (bool, error) {
	switch dialect {
	case "postgres":
		var exists bool
		err := db.QueryRow(
			"SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1)",
			table,
		).Scan(&exists)
		return exists, err
	case "sqlite":
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count)
		return count > 0, err
	default:
		return false, fmt.Errorf("unknown dialect: %s", dialect)
	}
}

// columnExists checks if a column exists in a table.
func columnExists(db *sql.DB, dialect, table, column string) (bool, error) {
	switch dialect {
	case "postgres":
		var exists bool
		err := db.QueryRow(
			"SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name=$1 AND column_name=$2)",
			table, column,
		).Scan(&exists)
		return exists, err
	case "sqlite":
		rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
		if err != nil {
			return false, err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var cid int
			var colName, colType string
			var notNull int
			var dflt sql.NullString
			var pk int
			if err := rows.Scan(&cid, &colName, &colType, &notNull, &dflt, &pk); err != nil {
				return false, err
			}
			if colName == column {
				return true, nil
			}
		}
		return false, rows.Err()
	default:
		return false, fmt.Errorf("unknown dialect: %s", dialect)
	}
}
