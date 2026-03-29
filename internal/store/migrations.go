package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// migrate runs all unapplied SQL migrations against db.
// It creates the schema_migrations tracking table on first run.
func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL DEFAULT (datetime('now'))
	)`); err != nil {
		return fmt.Errorf("creating schema_migrations table: %w", err)
	}

	var current int
	if err := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&current); err != nil {
		return fmt.Errorf("querying current migration version: %w", err)
	}

	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("reading embedded migrations: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		var version int
		if _, err := fmt.Sscanf(name, "%d_", &version); err != nil {
			continue
		}
		if version <= current {
			continue
		}

		sqlBytes, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("reading migration %s: %w", name, err)
		}

		stmts := strings.Split(string(sqlBytes), ";")

		// Check if this migration needs foreign keys disabled (indicated
		// by PRAGMA foreign_keys = OFF in the file).
		var needsFKOff bool
		var cleanStmts []string
		for _, stmt := range stmts {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			// Strip leading SQL comments to find the actual statement.
			stripped := stmt
			for {
				if strings.HasPrefix(stripped, "--") {
					if idx := strings.Index(stripped, "\n"); idx >= 0 {
						stripped = strings.TrimSpace(stripped[idx+1:])
					} else {
						stripped = ""
					}
				} else {
					break
				}
			}
			if stripped == "" {
				continue
			}
			upper := strings.ToUpper(stripped)
			if strings.HasPrefix(upper, "PRAGMA FOREIGN_KEYS") {
				if strings.Contains(upper, "OFF") {
					needsFKOff = true
				}
				continue // skip all FK pragmas — handled via dedicated connection
			}
			cleanStmts = append(cleanStmts, stmt)
		}

		// If FK must be disabled, acquire a dedicated connection so the
		// PRAGMA persists across the transaction on the same connection.
		if needsFKOff {
			conn, err := db.Conn(context.Background())
			if err != nil {
				return fmt.Errorf("acquiring connection for migration %d: %w", version, err)
			}
			if _, err := conn.ExecContext(context.Background(), "PRAGMA foreign_keys = OFF"); err != nil {
				_ = conn.Close()
				return fmt.Errorf("disabling FK for migration %d: %w", version, err)
			}

			tx, err := conn.BeginTx(context.Background(), nil)
			if err != nil {
				_ = conn.Close()
				return fmt.Errorf("beginning transaction for migration %d: %w", version, err)
			}
			for _, stmt := range cleanStmts {
				if _, err := tx.Exec(stmt); err != nil {
					_ = tx.Rollback()
					_ = conn.Close()
					return fmt.Errorf("executing migration %d: %w", version, err)
				}
			}
			if _, err := tx.Exec("INSERT INTO schema_migrations (version) VALUES (?)", version); err != nil {
				_ = tx.Rollback()
				_ = conn.Close()
				return fmt.Errorf("recording migration %d: %w", version, err)
			}
			if err := tx.Commit(); err != nil {
				_ = conn.Close()
				return fmt.Errorf("committing migration %d: %w", version, err)
			}
			_, _ = conn.ExecContext(context.Background(), "PRAGMA foreign_keys = ON")
			_ = conn.Close()
			continue
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("beginning transaction for migration %d: %w", version, err)
		}

		for _, stmt := range cleanStmts {
			if _, err := tx.Exec(stmt); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("executing migration %d: %w", version, err)
			}
		}

		if _, err := tx.Exec("INSERT INTO schema_migrations (version) VALUES (?)", version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("recording migration %d: %w", version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing migration %d: %w", version, err)
		}
	}

	return nil
}
