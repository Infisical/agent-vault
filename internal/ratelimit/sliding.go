package ratelimit

import (
	"sync"
	"time"
)

// slidingWindow is a generic sliding-window limiter keyed by string.
// It tracks timestamps of recent events per key, drops entries older
// than window on every check, and evicts cold keys when the map grows
// past maxKeys. Thread-safe.
//
// The struct fields are mutable at runtime so Registry.Reload can
// change window/max without rebuilding the bucket map; in-flight keys
// pick up the new limits on their next call.
type slidingWindow struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	window   time.Duration
	max      int
	maxKeys  int
	now      func() time.Time // injectable for tests
}

func newSlidingWindow(cfg TierConfig) *slidingWindow {
	w := cfg.Window
	if w <= 0 {
		w = 5 * time.Minute
	}
	m := cfg.Max
	if m < 1 {
		m = 1
	}
	mk := cfg.MaxKeys
	if mk <= 0 {
		mk = 10000
	}
	return &slidingWindow{
		attempts: make(map[string][]time.Time),
		window:   w,
		max:      m,
		maxKeys:  mk,
		now:      time.Now,
	}
}

// reconfigure updates the window/max/maxKeys in place. Existing per-key
// history is preserved; future checks use the new parameters.
func (l *slidingWindow) reconfigure(cfg TierConfig) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if cfg.Window > 0 {
		l.window = cfg.Window
	}
	if cfg.Max > 0 {
		l.max = cfg.Max
	}
	if cfg.MaxKeys > 0 {
		l.maxKeys = cfg.MaxKeys
	}
}

// allow records an attempt for key and returns a Decision. The earliest
// event in the window is used to compute RetryAfter on denial so the
// response's Retry-After header is accurate.
func (l *slidingWindow) allow(key string) Decision {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	cutoff := now.Add(-l.window)

	recent := l.attempts[key][:0]
	for _, t := range l.attempts[key] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	l.attempts[key] = recent

	if len(recent) >= l.max {
		// retry-after = time until earliest event falls out of the window.
		var wait time.Duration
		if len(recent) > 0 {
			wait = recent[0].Add(l.window).Sub(now)
		}
		if wait < time.Second {
			wait = time.Second
		}
		return Deny("rate", wait, l.max)
	}

	l.attempts[key] = append(l.attempts[key], now)

	// Evict cold keys to prevent unbounded growth. Walk once looking
	// for entries whose most-recent attempt is already outside the
	// window — cheap and correct, matches the legacy limiter.
	if l.maxKeys > 0 && len(l.attempts) > l.maxKeys {
		for k, v := range l.attempts {
			if len(v) == 0 || v[len(v)-1].Before(cutoff) {
				delete(l.attempts, k)
			}
		}
	}

	return AllowOK(l.max-len(recent)-1, l.max)
}

// size returns the number of tracked keys (for gauges/tests).
func (l *slidingWindow) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.attempts)
}
