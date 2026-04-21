package ratelimit

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Registry owns all per-tier limiters in a single process. It is safe
// for concurrent use. Call New() once at server construction; callers
// hold on to it and pass it into middleware and handlers that need to
// perform explicit allow/acquire calls (like login's email bucket).
type Registry struct {
	cfg atomic.Pointer[Config]

	mu sync.RWMutex
	// Per-tier state. Only the field matching the tier's algorithm is
	// non-nil. Reload swaps fields atomically by taking the write lock.
	sliding     [tierCount]*slidingWindow
	buckets     [tierCount]*tokenBucketMap
	kSemaphores [tierCount]*keyedSemaphore
	failures    [tierCount]*failureCounter
	globalSem   *semaphore
	globalRate  *tokenBucketMap
}

// New constructs a Registry from cfg. Call Reload later to pick up
// updated settings without rebuilding the registry.
func New(cfg Config) *Registry {
	r := &Registry{}
	r.cfg.Store(&cfg)
	r.build(cfg)
	return r
}

// Config returns a copy of the current effective config.
func (r *Registry) Config() Config { return *r.cfg.Load() }

// Reload replaces the registry's config. Existing per-key state is
// preserved where possible (sliding histories, bucket token counts);
// tier capacities and rates update in place. The global semaphore is
// rebuilt if the capacity changes — in-flight holders will release to
// the old semaphore and new requests acquire on the new one.
func (r *Registry) Reload(newCfg Config) {
	old := r.cfg.Load()
	r.cfg.Store(&newCfg)
	r.mu.Lock()
	defer r.mu.Unlock()
	for t := Tier(0); t < tierCount; t++ {
		if r.sliding[t] != nil {
			r.sliding[t].reconfigure(newCfg.Tiers[t])
		}
		if r.buckets[t] != nil {
			r.buckets[t].reconfigure(newCfg.Tiers[t])
		}
		if r.kSemaphores[t] != nil {
			r.kSemaphores[t].reconfigure(newCfg.Tiers[t])
		} else if t == TierProxy && newCfg.Tiers[t].Concurrency > 0 {
			// Boot config had Concurrency=0 so no sem was allocated;
			// a UI / env change re-enabled it — build it now.
			r.kSemaphores[t] = newKeyedSemaphore(newCfg.Tiers[t], 2*time.Second)
		}
		if r.failures[t] != nil {
			r.failures[t].reconfigure(newCfg.Tiers[t])
		}
	}
	// Rebuild global sem if capacity changed.
	if old == nil || newCfg.Tiers[TierGlobal].Concurrency != old.Tiers[TierGlobal].Concurrency {
		r.globalSem = newSemaphore(newCfg.Tiers[TierGlobal].Concurrency, 500*time.Millisecond)
	}
	if r.globalRate != nil {
		r.globalRate.reconfigure(TierConfig{
			Rate:  newCfg.Tiers[TierGlobal].Rate,
			Burst: newCfg.Tiers[TierGlobal].Burst,
		})
	}
}

// build initializes the per-tier structures for cfg. Called once from
// New; Reload updates in place.
func (r *Registry) build(cfg Config) {
	if cfg.Off {
		return
	}
	for t := Tier(0); t < tierCount; t++ {
		// TierGlobal is handled below — it carries both a bucket and
		// a semaphore, neither of which matches a single Algorithm.
		if t == TierGlobal {
			continue
		}
		tc := cfg.Tiers[t]
		switch tc.Algorithm {
		case AlgSliding:
			r.sliding[t] = newSlidingWindow(tc)
		case AlgTokenBucket:
			r.buckets[t] = newTokenBucketMap(tc)
		case AlgFailureCounter:
			r.failures[t] = newFailureCounter(tc)
		}
	}
	// TierProxy layers a per-key concurrency semaphore on top of its
	// token bucket; the bucket smooths sustained traffic, the sem
	// bounds in-flight slow upstream calls.
	if cfg.Tiers[TierProxy].Concurrency > 0 {
		r.kSemaphores[TierProxy] = newKeyedSemaphore(cfg.Tiers[TierProxy], 2*time.Second)
	}
	// TierGlobal is two primitives in one tier: an RPS token bucket
	// keyed on a constant, and an in-flight semaphore.
	r.globalSem = newSemaphore(cfg.Tiers[TierGlobal].Concurrency, 500*time.Millisecond)
	r.globalRate = newTokenBucketMap(TierConfig{
		Rate:    cfg.Tiers[TierGlobal].Rate,
		Burst:   cfg.Tiers[TierGlobal].Burst,
		MaxKeys: 1,
	})
}

// Allow records one event against tier for key and returns a Decision.
// Off configs return AllowOK. Unknown/unset tiers fail open (AllowOK).
// Empty key fails open too (the middleware treats "" as "skip").
func (r *Registry) Allow(tier Tier, key string) Decision {
	if r.cfg.Load().Off || key == "" {
		return AllowOK(0, 0)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if sw := r.sliding[tier]; sw != nil {
		return sw.allow(key)
	}
	if tb := r.buckets[tier]; tb != nil {
		return tb.allow(key)
	}
	return AllowOK(0, 0)
}

// AllowGlobalRPS is the single-bucket rate check applied to every
// request. Keyed on a constant ("global") inside the bucket map so the
// tokenBucketMap eviction machinery is reused without special-casing.
func (r *Registry) AllowGlobalRPS() Decision {
	if r.cfg.Load().Off {
		return AllowOK(0, 0)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.globalRate == nil {
		return AllowOK(0, 0)
	}
	return r.globalRate.allow("global")
}

// AcquireGlobal takes a slot from the server-wide in-flight semaphore.
// Returns nil release + Deny when the cap is hit.
func (r *Registry) AcquireGlobal(ctx context.Context) (func(), Decision) {
	if r.cfg.Load().Off {
		return func() {}, AllowOK(0, 0)
	}
	r.mu.RLock()
	sem := r.globalSem
	r.mu.RUnlock()
	if sem == nil {
		return func() {}, AllowOK(0, 0)
	}
	return sem.acquire(ctx)
}

// ProxyEnforcement is the outcome of Registry.EnforceProxy. On denial,
// Release is nil and the caller emits a 429 using Decision + ErrCode
// + Message. On allow, defer Release() to free the concurrency slot.
type ProxyEnforcement struct {
	Allowed  bool
	Release  func()
	Decision Decision
	ErrCode  string // "rate_limit_scope" | "concurrency_scope"
	Message  string
}

// EnforceProxy runs the two TierProxy checks (token bucket first,
// concurrency semaphore second) for one proxy request. Shared between
// /proxy/* and the MITM forward handler so limits apply uniformly
// regardless of ingress.
func (r *Registry) EnforceProxy(ctx context.Context, actorID, vaultID string) ProxyEnforcement {
	if r == nil || r.cfg.Load().Off || actorID == "" || vaultID == "" {
		return ProxyEnforcement{Allowed: true, Release: func() {}}
	}
	scopeKey := "scope:" + actorID + ":" + vaultID
	if d := r.Allow(TierProxy, scopeKey); !d.Allow {
		return ProxyEnforcement{Decision: d, ErrCode: "rate_limit_scope", Message: "Proxy rate limit exceeded for this scope"}
	}
	release, d := r.acquireKeyed(ctx, TierProxy, scopeKey)
	if !d.Allow {
		return ProxyEnforcement{Decision: d, ErrCode: "concurrency_scope", Message: "Proxy at concurrency limit for this scope"}
	}
	return ProxyEnforcement{Allowed: true, Release: release}
}

// acquireKeyed takes a slot on a per-key semaphore for tier.
func (r *Registry) acquireKeyed(ctx context.Context, tier Tier, key string) (func(), Decision) {
	if r.cfg.Load().Off || key == "" {
		return func() {}, AllowOK(0, 0)
	}
	r.mu.RLock()
	k := r.kSemaphores[tier]
	r.mu.RUnlock()
	if k == nil {
		return func() {}, AllowOK(0, 0)
	}
	return k.acquire(ctx, key)
}

// FailureCheck reports whether key is still allowed to attempt. Used
// for verification-code invalidation (not a rate limit — a failure
// budget).
func (r *Registry) FailureCheck(tier Tier, key string) bool {
	if r.cfg.Load().Off || key == "" {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	fc := r.failures[tier]
	if fc == nil {
		return true
	}
	return fc.check(key)
}

// FailureRecord increments the failure counter for key.
func (r *Registry) FailureRecord(tier Tier, key string) {
	if r.cfg.Load().Off || key == "" {
		return
	}
	r.mu.RLock()
	fc := r.failures[tier]
	r.mu.RUnlock()
	if fc != nil {
		fc.record(key)
	}
}

// FailureReset clears the counter for key (called on successful
// verification).
func (r *Registry) FailureReset(tier Tier, key string) {
	if key == "" {
		return
	}
	r.mu.RLock()
	fc := r.failures[tier]
	r.mu.RUnlock()
	if fc != nil {
		fc.reset(key)
	}
}

