// Package ratelimit is Agent Vault's tiered rate limiter. It groups
// endpoints into tiers by attack surface and cost, keys each tier on
// the principal being defended (IP, hashed token, actor, scope-host),
// and exposes one Registry that owns all in-memory state.
package ratelimit

import (
	"errors"
	"fmt"
	"time"
)

// Tier identifies a rate-limiting bucket. Each tier carries its own
// Config and covers a distinct attack surface.
type Tier int

const (
	// TierAuth covers every unauthenticated endpoint: login, register,
	// forgot/reset password, email verification, OAuth login/callback,
	// invite redemption, approval-token lookups. Sliding window. The
	// caller picks the keyer — IPKey for IP-flood defense, IPTokenKey
	// for token-enumeration, and the login handler uses both an IP
	// and email key against this tier (reject if either is exhausted).
	TierAuth Tier = iota

	// TierProxy is the /proxy and MITM rate limit keyed on
	// (actor, vault). Token bucket for smooth traffic + a per-scope
	// concurrency semaphore for slow upstream calls.
	TierProxy

	// TierAuthed is the catch-all for authenticated endpoints (CRUD,
	// reads, admin, expensive fan-out ops). Token bucket keyed on
	// actor. Defaults accommodate the heaviest workload in the tier;
	// if a specific endpoint needs tighter protection, add it inline.
	TierAuthed

	// TierGlobal is the server-wide backstop: requests-per-second
	// ceiling + total in-flight cap. Rate/Burst drive the RPS token
	// bucket; Concurrency drives the in-flight semaphore.
	TierGlobal

	// TierVerifyFailure is an internal failure counter — not a rate
	// limit — for email-verification and password-reset codes. The
	// counter increments on bad codes per email and resets on success;
	// hitting the cap invalidates the outstanding code. Not exposed in
	// the operator UI because there is nothing useful to tune.
	TierVerifyFailure

	tierCount
)

// tierNames is the authoritative mapping between the stable wire
// name (also the env-var suffix) and the internal Tier constant.
// Exposed via String and TierByName so callers never duplicate it.
var tierNames = [tierCount]string{
	TierAuth:          "AUTH",
	TierProxy:         "PROXY",
	TierAuthed:        "AUTHED",
	TierGlobal:        "GLOBAL",
	TierVerifyFailure: "VERIFY_FAIL",
}

// String returns the stable env-suffix form of a Tier, used for
// AGENT_VAULT_RATELIMIT_<TIER>_<KNOB> variable names.
func (t Tier) String() string {
	if t < 0 || int(t) >= len(tierNames) {
		return fmt.Sprintf("TIER_%d", int(t))
	}
	return tierNames[t]
}

// TierByName returns the Tier matching name, or (0, false) if name is
// not recognized. Case-sensitive — callers that accept user input
// should upper-case the name first.
func TierByName(name string) (Tier, bool) {
	for i, n := range tierNames {
		if n == name {
			return Tier(i), true
		}
	}
	return 0, false
}

// AllTiers returns the list of valid Tier values in declaration order.
// Use in UI enumeration and config serialization; do not rely on slice
// index matching Tier value (that's only guaranteed today because
// Tier is a simple iota).
func AllTiers() []Tier {
	out := make([]Tier, 0, tierCount)
	for i := 0; i < int(tierCount); i++ {
		out = append(out, Tier(i))
	}
	return out
}

// Algorithm selects the backing implementation for a tier.
type Algorithm int

const (
	// AlgSliding is the sliding-window limiter: at most N events within
	// a rolling Window. Best for strict attempt caps (login floods).
	AlgSliding Algorithm = iota

	// AlgTokenBucket is the smooth token-bucket: Rate refill per second
	// with Burst as bucket depth. Best for sustained traffic (proxy).
	AlgTokenBucket

	// AlgSemaphore is a counting semaphore: at most Concurrency
	// in-flight acquirers. Used alongside another algorithm.
	AlgSemaphore

	// AlgFailureCounter counts failures (not rate): increments on
	// recordFailure, resets on reset. Used for verify-code invalidation.
	AlgFailureCounter
)

// Decision is the outcome of an Allow/Acquire check. A Decision with
// Allow=false carries a RetryAfter and Reason so the caller can emit a
// well-formed 429.
type Decision struct {
	Allow      bool
	RetryAfter time.Duration
	Remaining  int
	Limit      int
	Reason     string // "rate", "concurrency", "global", or ""
}

// Deny builds a refusal decision.
func Deny(reason string, retryAfter time.Duration, limit int) Decision {
	return Decision{Allow: false, RetryAfter: retryAfter, Limit: limit, Reason: reason}
}

// Allow builds an allowance decision.
func AllowOK(remaining, limit int) Decision {
	return Decision{Allow: true, Remaining: remaining, Limit: limit}
}

// ErrLocked is returned by setting mutation when
// AGENT_VAULT_RATELIMIT_LOCK pins the config.
var ErrLocked = errors.New("rate-limit config is pinned by operator env var")
