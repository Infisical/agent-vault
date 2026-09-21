package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/contextbinding"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestPostgresContextBindingRetirementWaitsForProposalLock(t *testing.T) {
	databaseURL := os.Getenv("AGENT_VAULT_TEST_POSTGRES_URL")
	if databaseURL == "" {
		t.Skip("set AGENT_VAULT_TEST_POSTGRES_URL to run PostgreSQL locking tests")
	}

	s, err := openPostgres(databaseURL)
	if err != nil {
		t.Fatalf("open Postgres: %v", err)
	}
	defer s.Close()

	ctx := context.Background()
	machineID := uuid.NewString()
	binding, err := s.CreateContextBinding(ctx, contextbinding.Tuple{
		OriginType:                          contextbinding.OriginCodex,
		OriginCodexThreadID:                 uuid.NewString(),
		OriginCodexSessionID:                uuid.NewString(),
		PerplexityProjectID:                 uuid.NewString(),
		RegisteredPersonalComputerMachineID: machineID,
		RuntimeDeviceID:                     "macos:" + machineID,
		WorkspaceRoot:                       "/tmp/agent-vault-postgres-context-test-" + uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create context binding: %v", err)
	}
	vault, err := s.CreateVault(ctx, "pg-context-"+uuid.NewString())
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.ExecContext(context.Background(), s.dialect.Rebind("DELETE FROM proposals WHERE vault_id = ?"), vault.ID)
		_, _ = s.db.ExecContext(context.Background(), s.dialect.Rebind("DELETE FROM context_bindings WHERE id = ?"), binding.ID)
		_ = s.DeleteVault(context.Background(), vault.Name)
	})

	// Hold the vault lock that CreateProposalWithContext acquires only after
	// the binding lock. This exposes the production transaction's binding lock
	// long enough for the test to probe it and race retirement against it.
	vaultBlocker, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = vaultBlocker.Rollback() }()
	var present int
	if err := vaultBlocker.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT 1 FROM vaults WHERE id = ? FOR UPDATE"), vault.ID,
	).Scan(&present); err != nil {
		t.Fatalf("lock vault: %v", err)
	}

	proposalDone := make(chan error, 1)
	go func() {
		_, err := s.CreateProposalWithContext(ctx, vault.ID, "pg-race-session", binding.ID, "[]", "[]", "race", "", nil)
		proposalDone <- err
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		probe, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		err = probe.QueryRowContext(ctx,
			s.dialect.Rebind("SELECT 1 FROM context_bindings WHERE id = ? FOR UPDATE NOWAIT"), binding.ID,
		).Scan(&present)
		_ = probe.Rollback()

		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "55P03" {
			break
		}
		if err != nil {
			t.Fatalf("probe binding lock: %v", err)
		}
		select {
		case err := <-proposalDone:
			t.Fatalf("proposal returned before reaching the blocked vault lock: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("proposal never acquired the context-binding lock")
		}
		time.Sleep(10 * time.Millisecond)
	}

	retired := make(chan error, 1)
	go func() {
		retired <- s.RetireContextBinding(ctx, binding.ID)
	}()

	select {
	case err := <-retired:
		t.Fatalf("retirement completed while proposal transaction held the binding lock: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	if err := vaultBlocker.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-proposalDone:
		if err != nil {
			t.Fatalf("CreateProposalWithContext: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proposal remained blocked after vault lock was released")
	}
	select {
	case err := <-retired:
		if err != nil {
			t.Fatalf("retirement after proposal commit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("retirement remained blocked after proposal transaction committed")
	}
}
