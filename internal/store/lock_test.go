package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// The Postgres LockVault path cannot run against a real server here (CI has
// no Postgres service), so these tests drive it through a fake driver that
// implements just the advisory-lock surface LockVault touches. That is enough
// to cover the property that matters: waiting for a contended lock must not
// hold a pooled connection, because callers borrow a second connection inside
// their critical section.

type fakePGDriver struct {
	mu   sync.Mutex
	held map[int64]bool
}

func (d *fakePGDriver) Open(string) (driver.Conn, error) { return &fakePGConn{d: d}, nil }

func (d *fakePGDriver) tryLock(key int64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.held[key] {
		return false
	}
	d.held[key] = true
	return true
}

func (d *fakePGDriver) unlock(key int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.held, key)
}

type fakePGConn struct{ d *fakePGDriver }

func (c *fakePGConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (c *fakePGConn) Close() error                        { return nil }
func (c *fakePGConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }

func (c *fakePGConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(q, "pg_try_advisory_lock") {
		return &boolRow{v: c.d.tryLock(args[0].Value.(int64))}, nil
	}
	// Stands in for the queries a caller runs inside its critical section.
	return &boolRow{v: true}, nil
}

func (c *fakePGConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if strings.Contains(q, "pg_advisory_unlock") {
		c.d.unlock(args[0].Value.(int64))
	}
	return driver.RowsAffected(0), nil
}

// boolRow is a one-column, one-row result.
type boolRow struct {
	v    bool
	done bool
}

func (r *boolRow) Columns() []string { return []string{"?column?"} }
func (r *boolRow) Close() error      { return nil }
func (r *boolRow) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.v
	return nil
}

var fakePGSeq int

// newFakePGStore returns a SQLStore on the fake Postgres driver with the
// connection pool capped at maxConns.
func newFakePGStore(t *testing.T, maxConns int) *SQLStore {
	t.Helper()
	fakePGSeq++
	name := fmt.Sprintf("fakepg-%d", fakePGSeq)
	sql.Register(name, &fakePGDriver{held: map[int64]bool{}})

	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(maxConns)
	t.Cleanup(func() { _ = db.Close() })
	return &SQLStore{db: db, dialect: PostgresDialect{}}
}

// TestLockVaultPostgresContentionDoesNotExhaustPool is the regression guard
// for the deadlock that blocking on pg_advisory_lock used to cause: waiters
// queued inside the lock statement pinned every connection in the pool, so
// the holder could never borrow the connection it needed to finish the work
// that would release the lock. Every worker here contends on one vault and
// then queries inside its critical section, with far more workers than
// connections.
func TestLockVaultPostgresContentionDoesNotExhaustPool(t *testing.T) {
	const maxConns = 4
	s := newFakePGStore(t, maxConns)

	const workers = maxConns * 4
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			unlock, err := s.LockVault(ctx, "vault-contended")
			if err != nil {
				t.Errorf("LockVault: %v", err)
				return
			}
			defer unlock()

			// Borrowing a second connection while holding the lock is the
			// shape of every real caller (handleSkillPatch, the service
			// mutators) and the half that starves under the old behavior.
			var v bool
			if err := s.db.QueryRowContext(ctx, "SELECT 1").Scan(&v); err != nil {
				t.Errorf("critical-section query: %v", err)
			}
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("LockVault deadlocked: waiters pinned the pool while the holder needed a connection")
	}
}

// TestLockVaultPostgresMutualExclusion checks the lock still excludes, since
// polling with pg_try_advisory_lock would be useless if it let two callers in.
func TestLockVaultPostgresMutualExclusion(t *testing.T) {
	s := newFakePGStore(t, 8)
	ctx := context.Background()

	var mu sync.Mutex
	inside, maxInside := 0, 0

	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock, err := s.LockVault(ctx, "vault-excl")
			if err != nil {
				t.Errorf("LockVault: %v", err)
				return
			}
			defer unlock()

			mu.Lock()
			inside++
			if inside > maxInside {
				maxInside = inside
			}
			mu.Unlock()

			time.Sleep(time.Millisecond)

			mu.Lock()
			inside--
			mu.Unlock()
		}()
	}
	wg.Wait()

	if maxInside != 1 {
		t.Fatalf("lock admitted %d concurrent holders, want 1", maxInside)
	}
}

// TestLockVaultPostgresDistinctVaultsDoNotBlock confirms the lock stays
// scoped per vault rather than serializing the whole instance.
func TestLockVaultPostgresDistinctVaultsDoNotBlock(t *testing.T) {
	s := newFakePGStore(t, 8)
	ctx := context.Background()

	first, err := s.LockVault(ctx, "vault-a")
	if err != nil {
		t.Fatalf("LockVault(vault-a): %v", err)
	}
	defer first()

	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	second, err := s.LockVault(waitCtx, "vault-b")
	if err != nil {
		t.Fatalf("LockVault(vault-b) blocked behind an unrelated vault: %v", err)
	}
	second()
}

// TestLockVaultPostgresUnlockReleases guards the release path: an advisory
// lock is session-scoped and the connection goes back to the pool, so a lock
// left behind would wedge the vault for every later caller.
func TestLockVaultPostgresUnlockReleases(t *testing.T) {
	s := newFakePGStore(t, 4)
	ctx := context.Background()

	unlock, err := s.LockVault(ctx, "vault-reuse")
	if err != nil {
		t.Fatalf("first LockVault: %v", err)
	}
	unlock()

	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	again, err := s.LockVault(waitCtx, "vault-reuse")
	if err != nil {
		t.Fatalf("re-acquire after unlock: %v", err)
	}
	again()
}

// TestLockVaultPostgresRespectsContextCancellation checks a caller waiting on
// a contended lock gives up with the context instead of hanging.
func TestLockVaultPostgresRespectsContextCancellation(t *testing.T) {
	s := newFakePGStore(t, 4)
	ctx := context.Background()

	unlock, err := s.LockVault(ctx, "vault-busy")
	if err != nil {
		t.Fatalf("LockVault: %v", err)
	}
	defer unlock()

	waitCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := s.LockVault(waitCtx, "vault-busy"); err == nil {
		t.Fatal("LockVault acquired a lock that was already held")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("LockVault ignored context cancellation for %v", elapsed)
	}
}

// TestLockVaultSQLiteMutualExclusion covers the other dialect, whose
// per-vault mutex has no pool involved and is unchanged.
func TestLockVaultSQLiteMutualExclusion(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	var mu sync.Mutex
	inside, maxInside := 0, 0

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock, err := s.LockVault(ctx, "vault-sqlite")
			if err != nil {
				t.Errorf("LockVault: %v", err)
				return
			}
			defer unlock()

			mu.Lock()
			inside++
			if inside > maxInside {
				maxInside = inside
			}
			mu.Unlock()

			time.Sleep(time.Millisecond)

			mu.Lock()
			inside--
			mu.Unlock()
		}()
	}
	wg.Wait()

	if maxInside != 1 {
		t.Fatalf("lock admitted %d concurrent holders, want 1", maxInside)
	}
}
