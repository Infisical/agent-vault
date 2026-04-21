package ratelimit

import (
	"math"
	"sync"
	"time"
)

// tokenBucketMap is a keyed collection of token buckets with LRU-style
// eviction when the map exceeds maxKeys. Each bucket refills at rate
// tokens/sec and can accumulate up to burst tokens. Thread-safe.
type tokenBucketMap struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64
	burst    float64
	maxKeys  int
	now      func() time.Time // injectable for tests
}

type bucket struct {
	tokens     float64
	lastRefill time.Time
}

func newTokenBucketMap(cfg TierConfig) *tokenBucketMap {
	r := cfg.Rate
	if r <= 0 {
		r = 1.0
	}
	b := float64(cfg.Burst)
	if b < 1 {
		b = 1
	}
	mk := cfg.MaxKeys
	if mk <= 0 {
		mk = 10000
	}
	return &tokenBucketMap{
		buckets: make(map[string]*bucket),
		rate:    r,
		burst:   b,
		maxKeys: mk,
		now:     time.Now,
	}
}

// reconfigure updates rate/burst/maxKeys in place. Existing buckets
// carry their current token count forward so hot keys don't get a
// surprise refill on reload.
func (m *tokenBucketMap) reconfigure(cfg TierConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cfg.Rate > 0 {
		m.rate = cfg.Rate
	}
	if cfg.Burst > 0 {
		m.burst = float64(cfg.Burst)
		// Clamp any over-full buckets to the new cap.
		for _, b := range m.buckets {
			if b.tokens > m.burst {
				b.tokens = m.burst
			}
		}
	}
	if cfg.MaxKeys > 0 {
		m.maxKeys = cfg.MaxKeys
	}
}

// allow refills before deducting so burst is honored after idle periods.
func (m *tokenBucketMap) allow(key string) Decision {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	b, ok := m.buckets[key]
	if !ok {
		b = &bucket{tokens: m.burst, lastRefill: now}
		m.buckets[key] = b
		m.evictIfNeededLocked(now)
	} else {
		elapsed := now.Sub(b.lastRefill).Seconds()
		if elapsed > 0 {
			b.tokens = math.Min(m.burst, b.tokens+elapsed*m.rate)
			b.lastRefill = now
		}
	}

	if b.tokens >= 1 {
		b.tokens--
		return AllowOK(int(b.tokens), int(m.burst))
	}

	// Wait for one token to refill.
	need := 1 - b.tokens
	wait := time.Duration(need / m.rate * float64(time.Second))
	if wait < time.Second {
		wait = time.Second
	}
	return Deny("rate", wait, int(m.burst))
}

// evictIfNeededLocked is called under m.mu. Prefers to drop buckets
// whose tokens are near full (idle keys — zero fairness impact). If
// that isn't enough (every bucket is hot), falls back to evicting the
// oldest-by-lastRefill entry so the map stays bounded even under
// adversarial distinct-key traffic.
func (m *tokenBucketMap) evictIfNeededLocked(_ time.Time) {
	if m.maxKeys <= 0 || len(m.buckets) <= m.maxKeys {
		return
	}
	for k, b := range m.buckets {
		if b.tokens >= m.burst-0.0001 {
			delete(m.buckets, k)
		}
		if len(m.buckets) <= m.maxKeys {
			return
		}
	}
	// Fallback: evict oldest by lastRefill until within cap.
	for len(m.buckets) > m.maxKeys {
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, b := range m.buckets {
			if first || b.lastRefill.Before(oldestTime) {
				oldestKey = k
				oldestTime = b.lastRefill
				first = false
			}
		}
		if oldestKey == "" {
			return
		}
		delete(m.buckets, oldestKey)
	}
}
