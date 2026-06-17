package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strings"
)

//go:embed migrations/postgres/*.sql
var postgresMigrationFS embed.FS

// migratePostgres runs all unapplied SQL migrations against a PostgreSQL db.
// It uses an advisory lock on a pinned connection to prevent concurrent
// migration runs across pods.
func migratePostgres(db *sql.DB) error {
	ctx := context.Background()

	// Pin a single connection for the entire migration so the advisory
	// lock, schema queries, and DDL all run on the same session.
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquiring connection for migration: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", int64(7956324891)); err != nil {
		return fmt.Errorf("acquiring migration lock: %w", err)
	}
	defer func() { _, _ = conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", int64(7956324891)) }()

	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`); err != nil {
		return fmt.Errorf("creating schema_migrations table: %w", err)
	}

	var current int
	if err := conn.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&current); err != nil {
		return fmt.Errorf("querying current migration version: %w", err)
	}

	entries, err := postgresMigrationFS.ReadDir("migrations/postgres")
	if err != nil {
		return fmt.Errorf("reading embedded migrations: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	var maxEmbedded int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		var v int
		if _, err := fmt.Sscanf(entry.Name(), "%d_", &v); err == nil && v > maxEmbedded {
			maxEmbedded = v
		}
	}

	if current > maxEmbedded {
		return fmt.Errorf("database schema version %d is newer than the highest embedded migration %d; upgrade the binary", current, maxEmbedded)
	}

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

		sqlBytes, err := postgresMigrationFS.ReadFile("migrations/postgres/" + name)
		if err != nil {
			return fmt.Errorf("reading migration %s: %w", name, err)
		}

		stmts := strings.Split(string(sqlBytes), ";")

		var cleanStmts []string
		for _, stmt := range stmts {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
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
			cleanStmts = append(cleanStmts, stmt)
		}

		// Run each migration in a transaction on the pinned connection.
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("beginning transaction for migration %d: %w", version, err)
		}
		defer func() { _ = tx.Rollback() }()

		for _, stmt := range cleanStmts {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("executing migration %d: %w", version, err)
			}
		}

		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
			return fmt.Errorf("recording migration %d: %w", version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing migration %d: %w", version, err)
		}
	}

	return nil
}
