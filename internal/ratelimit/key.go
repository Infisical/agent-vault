package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

// Keyer extracts a stable string key from a request for a rate-limit
// bucket. Returning "" tells the middleware to skip the check —
// useful when a keyer depends on context that isn't yet populated
// (e.g., session post-auth).
type Keyer func(*http.Request) string

// IPKey wraps a clientIP function into a Keyer. The server package
// owns the clientIP logic (AGENT_VAULT_TRUSTED_PROXIES handling) and
// passes it in, so this package has no http-header policy.
func IPKey(clientIP func(*http.Request) string) Keyer {
	return func(r *http.Request) string {
		return "ip:" + clientIP(r)
	}
}

// HashToken returns a base16 SHA-256 prefix of s. Used for token
// keys so raw secrets never sit in the limiter's memory or logs.
func HashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// IPTokenKey combines clientIP + hashed token/state from the request.
// tokenFromRequest picks the token out (path value, query param,
// body — handler's choice). Returns "" when the token is empty so
// the middleware skips the check.
func IPTokenKey(clientIP func(*http.Request) string, tokenFromRequest func(*http.Request) string) Keyer {
	return func(r *http.Request) string {
		tok := tokenFromRequest(r)
		if tok == "" {
			return ""
		}
		return "ipt:" + clientIP(r) + ":" + HashToken(tok)
	}
}

// ActorKey keys on a caller-provided actor identifier. The server
// package resolves session→actor once per request post-auth and
// passes a closure that reads from the request context.
func ActorKey(actorFromRequest func(*http.Request) string) Keyer {
	return func(r *http.Request) string {
		id := actorFromRequest(r)
		if id == "" {
			return ""
		}
		return "actor:" + id
	}
}
