package ratelimit

import "sync"

// failureCounter tracks failed attempts per key (typically email).
// Semantics differ from a rate limiter: the counter only increments on
// recordFailure; it does not decay with time. A successful operation
// calls reset. Callers use check() to gate retries — when a caller
// hits the cap, the underlying credential (verification code, password
// reset code) is considered burned and the caller must request a new
// one. Thread-safe.
type failureCounter struct {
	mu       sync.Mutex
	attempts map[string]int
	max      int
	maxKeys  int
}

func newFailureCounter(cfg TierConfig) *failureCounter {
	m := cfg.Max
	if m < 1 {
		m = 10
	}
	mk := cfg.MaxKeys
	if mk <= 0 {
		mk = 10000
	}
	return &failureCounter{
		attempts: make(map[string]int),
		max:      m,
		maxKeys:  mk,
	}
}

func (f *failureCounter) reconfigure(cfg TierConfig) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if cfg.Max > 0 {
		f.max = cfg.Max
	}
	if cfg.MaxKeys > 0 {
		f.maxKeys = cfg.MaxKeys
	}
}

// check returns true if key is still under the failure cap.
func (f *failureCounter) check(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempts[key] < f.max
}

// record increments the failure counter for key. On overflow, evicts
// an arbitrary other entry — Go's map iteration is randomized so the
// victim is unpredictable, but under a mass-enumeration attack the
// caller's ~10000-key cap means we're throttling anyway; losing an
// occasional legitimate counter just lets that email try again.
func (f *failureCounter) record(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts[key]++
	if f.maxKeys > 0 && len(f.attempts) > f.maxKeys {
		for k := range f.attempts {
			if k != key {
				delete(f.attempts, k)
				break
			}
		}
	}
}

// reset clears the counter for key.
func (f *failureCounter) reset(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.attempts, key)
}
