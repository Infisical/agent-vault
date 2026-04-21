package ratelimit

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// semaphore is a counting semaphore with context-aware acquire and a
// short wait budget. Callers must invoke the returned release once when
// they no longer hold the slot, even if the decision was a denial
// (release is nil on denial — handled by the caller).
type semaphore struct {
	slots   chan struct{}
	held    atomic.Int64
	timeout time.Duration
}

func newSemaphore(capacity int, waitBudget time.Duration) *semaphore {
	if capacity < 1 {
		capacity = 1
	}
	if waitBudget <= 0 {
		waitBudget = 2 * time.Second
	}
	return &semaphore{
		slots:   make(chan struct{}, capacity),
		timeout: waitBudget,
	}
}

// acquire attempts to take a slot. It tries non-blocking first, then
// waits up to the configured budget (bounded further by ctx). Returns
// (release, Decision). release is non-nil only when Allow is true.
func (s *semaphore) acquire(ctx context.Context) (func(), Decision) {
	// Fast path: slot available immediately.
	select {
	case s.slots <- struct{}{}:
		s.held.Add(1)
		return s.releaseOnce(), AllowOK(cap(s.slots)-len(s.slots), cap(s.slots))
	default:
	}

	// Wait up to the budget or until ctx is done.
	budget := s.timeout
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case s.slots <- struct{}{}:
		s.held.Add(1)
		return s.releaseOnce(), AllowOK(cap(s.slots)-len(s.slots), cap(s.slots))
	case <-ctx.Done():
		return nil, Deny("concurrency", time.Second, cap(s.slots))
	case <-timer.C:
		return nil, Deny("concurrency", time.Second, cap(s.slots))
	}
}

func (s *semaphore) releaseOnce() func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			<-s.slots
			s.held.Add(-1)
		})
	}
}

// held returns the current number of in-flight holders (for gauges).
func (s *semaphore) holders() int64 { return s.held.Load() }

// keyedSemaphore is a map of per-key semaphores, each with the same
// capacity. Used for TierProxy per-scope concurrency caps. maxKeys evicts
// idle (fully-released) semaphores to bound memory.
type keyedSemaphore struct {
	mu         sync.Mutex
	sems       map[string]*semaphore
	capacity   int
	waitBudget time.Duration
	maxKeys    int
}

func newKeyedSemaphore(cfg TierConfig, waitBudget time.Duration) *keyedSemaphore {
	c := cfg.Concurrency
	if c < 1 {
		c = 1
	}
	mk := cfg.MaxKeys
	if mk <= 0 {
		mk = 10000
	}
	return &keyedSemaphore{
		sems:       make(map[string]*semaphore),
		capacity:   c,
		waitBudget: waitBudget,
		maxKeys:    mk,
	}
}

// reconfigure updates the per-key capacity. Existing semaphores keep
// their old capacity until the last holder releases (at which point
// they may be evicted); new keys get the new cap.
func (k *keyedSemaphore) reconfigure(cfg TierConfig) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if cfg.Concurrency > 0 {
		k.capacity = cfg.Concurrency
	}
	if cfg.MaxKeys > 0 {
		k.maxKeys = cfg.MaxKeys
	}
}

// acquire returns a release function and decision for a specific key.
func (k *keyedSemaphore) acquire(ctx context.Context, key string) (func(), Decision) {
	k.mu.Lock()
	sem, ok := k.sems[key]
	if !ok {
		sem = newSemaphore(k.capacity, k.waitBudget)
		k.sems[key] = sem
		k.evictLocked(key)
	}
	k.mu.Unlock()
	return sem.acquire(ctx)
}

// evictLocked keeps the sems map bounded. Preferred: drop entries
// with no holders (cheap, fair). If every entry has holders, abandon
// the weakest-claim semaphore — under adversarial new-key traffic
// this loses one queued slot but bounds memory. Called under k.mu.
func (k *keyedSemaphore) evictLocked(skipKey string) {
	if k.maxKeys <= 0 || len(k.sems) <= k.maxKeys {
		return
	}
	for kk, ss := range k.sems {
		if kk == skipKey {
			continue
		}
		if ss.holders() == 0 {
			delete(k.sems, kk)
			if len(k.sems) <= k.maxKeys {
				return
			}
		}
	}
	// Hard fallback: drop an arbitrary non-skip entry. New requests
	// on that key rebuild a fresh semaphore on next acquire; in-flight
	// holders still release on the (now-orphaned) sem — safe because
	// each holder captured the sem pointer at acquire time.
	for kk := range k.sems {
		if kk == skipKey {
			continue
		}
		delete(k.sems, kk)
		if len(k.sems) <= k.maxKeys {
			return
		}
	}
}
