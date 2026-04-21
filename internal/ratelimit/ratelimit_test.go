package ratelimit

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func testRegistry(t *testing.T) *Registry {
	t.Helper()
	return New(DefaultsFor(ProfileDefault))
}

func TestSlidingWindowAllowThenDeny(t *testing.T) {
	r := testRegistry(t)
	// Drive TierAuth to its ceiling (10 at default).
	var lastAllowed bool
	for i := 0; i < 10; i++ {
		d := r.Allow(TierAuth, "ip:1.2.3.4")
		lastAllowed = d.Allow
		if !d.Allow {
			t.Fatalf("attempt %d unexpectedly denied (remaining=%d)", i+1, d.Remaining)
		}
	}
	if !lastAllowed {
		t.Fatalf("final allowed attempt had Allow=false")
	}
	d := r.Allow(TierAuth, "ip:1.2.3.4")
	if d.Allow {
		t.Fatalf("11th attempt should be denied")
	}
	if d.RetryAfter <= 0 {
		t.Fatalf("retry-after should be positive on denial, got %v", d.RetryAfter)
	}
	if d.Reason != "rate" {
		t.Fatalf("reason=%q want %q", d.Reason, "rate")
	}
	// Different key is independent.
	if d := r.Allow(TierAuth, "ip:5.6.7.8"); !d.Allow {
		t.Fatalf("different key should be allowed independently")
	}
}

func TestSlidingWindowEvictionCap(t *testing.T) {
	// Tight map cap + tight window so eviction fires on an old entry.
	cfg := DefaultsFor(ProfileDefault)
	cfg.Tiers[TierAuth].MaxKeys = 4
	cfg.Tiers[TierAuth].Window = 50 * time.Millisecond
	r := New(cfg)
	// Seed 3 keys, then let them go cold.
	for i := 0; i < 3; i++ {
		r.Allow(TierAuth, string(rune('a'+i)))
	}
	time.Sleep(60 * time.Millisecond)
	// Seed 5 more (past cap); eviction should purge cold entries.
	for i := 0; i < 5; i++ {
		r.Allow(TierAuth, string(rune('A'+i)))
	}
	if sz := r.sliding[TierAuth].size(); sz > cfg.Tiers[TierAuth].MaxKeys+2 {
		t.Fatalf("map grew past eviction threshold: size=%d cap=%d", sz, cfg.Tiers[TierAuth].MaxKeys)
	}
}

func TestTokenBucketBurstAndRefill(t *testing.T) {
	cfg := DefaultsFor(ProfileDefault)
	// Force a tiny, predictable bucket.
	cfg.Tiers[TierAuthed] = TierConfig{
		Algorithm: AlgTokenBucket, Rate: 1000, Burst: 3, MaxKeys: 100,
	}
	r := New(cfg)
	for i := 0; i < 3; i++ {
		if d := r.Allow(TierAuthed, "actor:x"); !d.Allow {
			t.Fatalf("burst slot %d denied", i+1)
		}
	}
	if d := r.Allow(TierAuthed, "actor:x"); d.Allow {
		t.Fatalf("over-burst should deny")
	}
	time.Sleep(20 * time.Millisecond) // 1000/sec × 20ms = 20 tokens refilled
	if d := r.Allow(TierAuthed, "actor:x"); !d.Allow {
		t.Fatalf("refill did not restore bucket")
	}
}

func TestSemaphoreCapContextCancel(t *testing.T) {
	cfg := DefaultsFor(ProfileDefault)
	cfg.Tiers[TierProxy].Concurrency = 2
	r := New(cfg)
	rel1, d1 := r.acquireKeyed(context.Background(), TierProxy, "scope:a:b")
	rel2, d2 := r.acquireKeyed(context.Background(), TierProxy, "scope:a:b")
	if !d1.Allow || !d2.Allow {
		t.Fatalf("first two acquires should succeed")
	}
	// Third acquire on the same key blocks then denies when ctx is done.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, d3 := r.acquireKeyed(ctx, TierProxy, "scope:a:b")
	if d3.Allow {
		t.Fatalf("over-cap acquire should deny")
	}
	// Release one, a fresh acquire should now succeed.
	rel1()
	rel4, d4 := r.acquireKeyed(context.Background(), TierProxy, "scope:a:b")
	if !d4.Allow {
		t.Fatalf("acquire after release should succeed")
	}
	rel4()
	rel2()
}

func TestFailureCounterCheckRecordReset(t *testing.T) {
	cfg := DefaultsFor(ProfileDefault)
	cfg.Tiers[TierVerifyFailure].Max = 3
	r := New(cfg)
	key := "email:alice@example.com"
	for i := 0; i < 3; i++ {
		if !r.FailureCheck(TierVerifyFailure, key) {
			t.Fatalf("check should return true before exhaustion (i=%d)", i)
		}
		r.FailureRecord(TierVerifyFailure, key)
	}
	if r.FailureCheck(TierVerifyFailure, key) {
		t.Fatalf("check should return false after %d failures", 3)
	}
	r.FailureReset(TierVerifyFailure, key)
	if !r.FailureCheck(TierVerifyFailure, key) {
		t.Fatalf("check should return true after reset")
	}
}

func TestOffConfigShortCircuits(t *testing.T) {
	cfg := DefaultsFor(ProfileOff)
	if !cfg.Off {
		t.Fatalf("ProfileOff should set Off=true")
	}
	r := New(cfg)
	// 1000 calls with the same key must all be allowed.
	for i := 0; i < 1000; i++ {
		if d := r.Allow(TierAuth, "k"); !d.Allow {
			t.Fatalf("off config denied at attempt %d", i)
		}
	}
}

func TestMiddlewareEmptyKeySkips(t *testing.T) {
	r := testRegistry(t)
	logger := slog.New(slog.DiscardHandler)
	wrap := r.HandlerFunc(TierAuth, func(*http.Request) string { return "" }, logger)
	served := 0
	h := wrap(func(w http.ResponseWriter, _ *http.Request) { served++ })
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		h(w, req)
		if w.Code != 200 {
			t.Fatalf("empty key should fail open, got %d", w.Code)
		}
	}
	if served != 100 {
		t.Fatalf("expected 100 passes, got %d", served)
	}
}

func TestMiddlewareDeniesAfterCap(t *testing.T) {
	cfg := DefaultsFor(ProfileDefault)
	cfg.Tiers[TierAuth].Max = 3
	r := New(cfg)
	logger := slog.New(slog.DiscardHandler)
	wrap := r.HandlerFunc(TierAuth, func(*http.Request) string { return "ip:1" }, logger)
	h := wrap(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	var denials int
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		h(w, req)
		if w.Code == http.StatusTooManyRequests {
			denials++
			if w.Header().Get("Retry-After") == "" {
				t.Fatalf("denied response must set Retry-After")
			}
			if w.Header().Get("X-RateLimit-Limit") == "" {
				t.Fatalf("denied response must set X-RateLimit-Limit")
			}
		}
	}
	if denials < 1 {
		t.Fatalf("expected at least one 429, got 0")
	}
}

func TestReloadUpdatesInPlace(t *testing.T) {
	cfg := DefaultsFor(ProfileDefault)
	cfg.Tiers[TierAuth].Max = 2
	r := New(cfg)
	for i := 0; i < 2; i++ {
		if d := r.Allow(TierAuth, "k"); !d.Allow {
			t.Fatalf("attempt %d denied before reload", i+1)
		}
	}
	if d := r.Allow(TierAuth, "k"); d.Allow {
		t.Fatalf("over-cap attempt allowed before reload")
	}
	// Raise the cap — same key should now get more allowance after
	// the previous history ages out (we keep history, so this tests
	// that window matters more than cap raise).
	cfg2 := cfg
	cfg2.Tiers[TierAuth].Max = 10
	r.Reload(cfg2)
	// Use a fresh key to confirm the new cap applies.
	for i := 0; i < 10; i++ {
		if d := r.Allow(TierAuth, "fresh"); !d.Allow {
			t.Fatalf("post-reload attempt %d denied (new cap should allow 10)", i+1)
		}
	}
}

func TestGlobalMiddlewareShortCircuitsWhenOff(t *testing.T) {
	r := New(DefaultsFor(ProfileOff))
	logger := slog.New(slog.DiscardHandler)
	gm := r.GlobalMiddleware(logger)
	h := gm(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 204 {
			t.Fatalf("off config denied a request: %d", w.Code)
		}
	}
}

func TestValidateFloors(t *testing.T) {
	cfg := DefaultsFor(ProfileDefault)
	cfg.Tiers[TierAuth].Max = 1 // below floor 5
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for AUTH below floor")
	}
	cfg = DefaultsFor(ProfileDefault)
	cfg.Tiers[TierGlobal].Concurrency = 10 // below 32
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for global-inflight below floor")
	}
}

func TestConcurrentUsageRace(t *testing.T) {
	// Smoke test: concurrent callers shouldn't panic or corrupt the map.
	r := testRegistry(t)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_ = r.Allow(TierAuthed, "actor:x")
				_, rel := pairRelease(r.acquireKeyed(context.Background(), TierProxy, "s"))
				rel()
				_ = g
			}
		}(g)
	}
	wg.Wait()
}

func pairRelease(rel func(), d Decision) (Decision, func()) {
	if rel == nil {
		rel = func() {}
	}
	return d, rel
}
