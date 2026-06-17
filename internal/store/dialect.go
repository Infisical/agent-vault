package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Dialect abstracts the few SQL differences between SQLite and PostgreSQL.
// The shared SQLStore implementation delegates to these methods so that
// a single codebase serves both backends.
type Dialect interface {
	// Name returns the dialect identifier ("sqlite" or "postgres").
	Name() string

	// Rebind converts '?' placeholders to the dialect's positional format.
	// SQLite uses '?' as-is; PostgreSQL uses $1, $2, etc.
	Rebind(query string) string

	// FormatTime converts a Go time.Time into the value passed to SQL
	// parameters. SQLite stores timestamps as TEXT strings; PostgreSQL
	// accepts time.Time natively for TIMESTAMPTZ columns.
	FormatTime(t time.Time) interface{}

	// ScanTime converts a value scanned from a timestamp column back into
	// a Go time.Time. SQLite returns strings; PostgreSQL returns time.Time.
	ScanTime(src interface{}) (time.Time, error)

	// FormatNullableTime is like FormatTime but handles nil (SQL NULL).
	FormatNullableTime(t *time.Time) interface{}

	// ScanNullableTime is like ScanTime but handles nil/NULL, returning
	// nil for NULL column values.
	ScanNullableTime(src interface{}) (*time.Time, error)

	// BoolVal converts a Go bool into the value passed to SQL parameters.
	// SQLite uses 0/1 integers; PostgreSQL uses native booleans.
	BoolVal(b bool) interface{}

	// ScanBool converts a value scanned from a boolean column back into
	// a Go bool. SQLite returns integers; PostgreSQL returns bool.
	ScanBool(src interface{}) (bool, error)

	// InsertReturningID executes an INSERT and returns the auto-generated
	// integer ID. SQLite uses LastInsertId(); PostgreSQL appends
	// RETURNING id and scans the result.
	InsertReturningID(ctx context.Context, execer interface{}, query string, args ...interface{}) (int64, error)

	// ForUpdateClause returns the SQL fragment appended to SELECT
	// statements for row-level locking. Returns "" for SQLite (no-op)
	// and "FOR UPDATE" for PostgreSQL.
	ForUpdateClause() string
}

// --- SQLite Dialect ---

// SQLiteDialect implements Dialect for SQLite (modernc.org/sqlite).
type SQLiteDialect struct{}

func (SQLiteDialect) Name() string { return "sqlite" }

func (SQLiteDialect) Rebind(query string) string { return query }

func (SQLiteDialect) FormatTime(t time.Time) interface{} {
	return t.UTC().Format(time.DateTime)
}

func (SQLiteDialect) ScanTime(src interface{}) (time.Time, error) {
	switch v := src.(type) {
	case string:
		return time.Parse(time.DateTime, v)
	case time.Time:
		return v.UTC(), nil
	case nil:
		return time.Time{}, fmt.Errorf("unexpected nil for non-nullable timestamp")
	default:
		return time.Time{}, fmt.Errorf("unsupported timestamp type %T", src)
	}
}

func (d SQLiteDialect) FormatNullableTime(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return d.FormatTime(*t)
}

func (d SQLiteDialect) ScanNullableTime(src interface{}) (*time.Time, error) {
	if src == nil {
		return nil, nil
	}
	t, err := d.ScanTime(src)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (SQLiteDialect) BoolVal(b bool) interface{} {
	if b {
		return 1
	}
	return 0
}

func (SQLiteDialect) ScanBool(src interface{}) (bool, error) {
	switch v := src.(type) {
	case int64:
		return v != 0, nil
	case bool:
		return v, nil
	case nil:
		return false, nil
	default:
		return false, fmt.Errorf("unsupported bool type %T", src)
	}
}

func (SQLiteDialect) InsertReturningID(ctx context.Context, execer interface{}, query string, args ...interface{}) (int64, error) {
	type dbExecer interface {
		ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	}
	e, ok := execer.(dbExecer)
	if !ok {
		return 0, fmt.Errorf("execer does not implement ExecContext")
	}
	res, err := e.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (SQLiteDialect) ForUpdateClause() string { return "" }

// --- PostgreSQL Dialect ---

// PostgresDialect implements Dialect for PostgreSQL (pgx/v5).
type PostgresDialect struct{}

func (PostgresDialect) Name() string { return "postgres" }

func (PostgresDialect) Rebind(query string) string {
	return rebindDollar(query)
}

func (PostgresDialect) FormatTime(t time.Time) interface{} {
	return t.UTC()
}

func (PostgresDialect) ScanTime(src interface{}) (time.Time, error) {
	switch v := src.(type) {
	case time.Time:
		return v.UTC(), nil
	case string:
		return time.Parse(time.DateTime, v)
	case nil:
		return time.Time{}, fmt.Errorf("unexpected nil for non-nullable timestamp")
	default:
		return time.Time{}, fmt.Errorf("unsupported timestamp type %T", src)
	}
}

func (d PostgresDialect) FormatNullableTime(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return d.FormatTime(*t)
}

func (d PostgresDialect) ScanNullableTime(src interface{}) (*time.Time, error) {
	if src == nil {
		return nil, nil
	}
	t, err := d.ScanTime(src)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (PostgresDialect) BoolVal(b bool) interface{} {
	return b
}

func (PostgresDialect) ScanBool(src interface{}) (bool, error) {
	switch v := src.(type) {
	case bool:
		return v, nil
	case int64:
		return v != 0, nil
	case nil:
		return false, nil
	default:
		return false, fmt.Errorf("unsupported bool type %T", src)
	}
}

func (PostgresDialect) InsertReturningID(ctx context.Context, execer interface{}, query string, args ...interface{}) (int64, error) {
	type dbQueryer interface {
		QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	}
	q, ok := execer.(dbQueryer)
	if !ok {
		return 0, fmt.Errorf("execer does not implement QueryRowContext")
	}
	query = rebindDollar(query) + " RETURNING id"
	var id int64
	if err := q.QueryRowContext(ctx, query, args...).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (PostgresDialect) ForUpdateClause() string { return "FOR UPDATE" }

// rebindDollar replaces '?' placeholders with $1, $2, ... for PostgreSQL.
// Only replaces '?' outside of single-quoted string literals. Handles
// escaped quotes ('') inside string literals correctly.
func rebindDollar(query string) string {
	var b strings.Builder
	b.Grow(len(query) + 16)
	n := 0
	inString := false
	for i := 0; i < len(query); i++ {
		ch := query[i]
		switch {
		case ch == '\'' && inString && i+1 < len(query) && query[i+1] == '\'':
			b.WriteByte('\'')
			b.WriteByte('\'')
			i++
		case ch == '\'':
			inString = !inString
			b.WriteByte(ch)
		case ch == '?' && !inString:
			n++
			fmt.Fprintf(&b, "$%d", n)
		default:
			b.WriteByte(ch)
		}
	}
	return b.String()
}
