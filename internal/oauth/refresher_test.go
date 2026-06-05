package oauth

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRefresher_Dedup(t *testing.T) {
	r := NewRefresher()

	var callCount atomic.Int32
	var wg sync.WaitGroup

	const goroutines = 10
	results := make([]RefreshResult, goroutines)

	// launched tracks how many goroutines have been scheduled and are
	// about to call r.Do. The leader's fn waits until all goroutines are
	// launched so they queue up inside singleflight before the fn returns.
	var launched atomic.Int32
	gate := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			launched.Add(1)
			results[idx] = r.Do("same-key", func() RefreshResult {
				callCount.Add(1)
				// Block until all goroutines have been launched and had
				// a chance to enter Do (they'll block on the singleflight
				// mutex waiting for us to return).
				for launched.Load() < goroutines {
					runtime.Gosched()
				}
				// Extra yield so stragglers enter the singleflight wait.
				time.Sleep(5 * time.Millisecond)
				<-gate
				return RefreshResult{AccessToken: "shared-token", Refreshed: true}
			})
		}(i)
	}

	// Wait for all goroutines to have launched.
	for launched.Load() < goroutines {
		runtime.Gosched()
	}
	// Let the leader finish.
	close(gate)
	wg.Wait()

	count := callCount.Load()
	if count != 1 {
		t.Errorf("fn called %d times, want exactly 1 (singleflight dedup)", count)
	}

	for i, res := range results {
		if res.AccessToken != "shared-token" {
			t.Errorf("goroutine %d: AccessToken = %q, want shared-token", i, res.AccessToken)
		}
		if !res.Refreshed {
			t.Errorf("goroutine %d: Refreshed = false, want true", i)
		}
	}
}

func TestRefresher_IndependentKeys(t *testing.T) {
	r := NewRefresher()

	var callCount atomic.Int32

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		r.Do("key-a", func() RefreshResult {
			callCount.Add(1)
			return RefreshResult{AccessToken: "token-a", Refreshed: true}
		})
	}()

	go func() {
		defer wg.Done()
		r.Do("key-b", func() RefreshResult {
			callCount.Add(1)
			return RefreshResult{AccessToken: "token-b", Refreshed: true}
		})
	}()

	wg.Wait()

	count := callCount.Load()
	if count != 2 {
		t.Errorf("fn called %d times, want 2 (independent keys)", count)
	}
}

func TestRefresher_ErrorPropagation(t *testing.T) {
	r := NewRefresher()

	errResult := RefreshResult{
		Err: &TokenError{StatusCode: 400, Body: "bad", Permanent: true},
	}

	var wg sync.WaitGroup
	const goroutines = 5
	results := make([]RefreshResult, goroutines)

	ready := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-ready
			results[idx] = r.Do("err-key", func() RefreshResult {
				return errResult
			})
		}(i)
	}

	close(ready)
	wg.Wait()

	for i, res := range results {
		if res.Err == nil {
			t.Errorf("goroutine %d: expected error, got nil", i)
			continue
		}
		te, ok := res.Err.(*TokenError)
		if !ok {
			t.Errorf("goroutine %d: expected *TokenError, got %T", i, res.Err)
			continue
		}
		if te.StatusCode != 400 {
			t.Errorf("goroutine %d: StatusCode = %d, want 400", i, te.StatusCode)
		}
	}
}
