package store

import (
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIsUniqueViolation(t *testing.T) {
	if !IsUniqueViolation(fmt.Errorf("creating vault: %w", &pgconn.PgError{Code: "23505"})) {
		t.Fatal("wrapped postgres unique violation not detected")
	}
	if IsUniqueViolation(&pgconn.PgError{Code: "23503"}) {
		t.Fatal("postgres foreign key violation reported as unique violation")
	}
}
