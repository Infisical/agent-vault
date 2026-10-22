package approval

import (
	"context"
	"errors"
	"testing"
	"time"
)

func awaitPending(t *testing.T, m *Manager, vault string) Request {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if items := m.List(vault); len(items) == 1 {
			return items[0]
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("request never entered approval queue")
	return Request{}
}

func TestDecisionIsVaultScopedAndOneTime(t *testing.T) {
	m := NewManager()
	done := make(chan error, 1)
	go func() {
		done <- m.Wait(context.Background(), Request{VaultID: "v1", Method: "POST", Host: "example.com"})
	}()
	request := awaitPending(t, m, "v1")
	if len(m.List("v2")) != 0 {
		t.Fatal("another vault can see request")
	}
	if err := m.Decide("v2", request.ID, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong-vault decision: %v", err)
	}
	if err := m.Decide("v1", request.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := m.Decide("v1", request.ID, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second decision: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("approved wait: %v", err)
	}
}

func TestDeniedAndCanceledRequestsDoNotRemainPending(t *testing.T) {
	for _, decision := range []bool{false, true} {
		m := NewManager()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- m.Wait(ctx, Request{VaultID: "v1"}) }()
		request := awaitPending(t, m, "v1")
		if decision {
			cancel()
		} else if err := m.Decide("v1", request.ID, false); err != nil {
			t.Fatal(err)
		}
		err := <-done
		if decision && !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel: %v", err)
		}
		if !decision && !errors.Is(err, ErrDenied) {
			t.Fatalf("reject: %v", err)
		}
		if len(m.List("v1")) != 0 {
			t.Fatal("finished request remains pending")
		}
		cancel()
	}
}
