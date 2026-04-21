package ratelimit

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
)

// HandlerFunc returns a per-route wrapper that applies tier to each
// request. Empty-key requests pass through (fail-open). On denial:
// 429 with Retry-After + X-RateLimit-* headers; logs WARN with the
// already-scoped key.
//
// For the proxy path, handlers call Registry.EnforceProxy directly —
// the scope and target host aren't known until after vault resolution.
func (r *Registry) HandlerFunc(tier Tier, keyer Keyer, logger *slog.Logger) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			if r.cfg.Load().Off {
				next(w, req)
				return
			}
			key := ""
			if keyer != nil {
				key = keyer(req)
			}
			if key == "" {
				next(w, req)
				return
			}
			d := r.Allow(tier, key)
			if d.Allow {
				writeRateLimitHeaders(w, d)
				next(w, req)
				return
			}
			if logger != nil {
				logger.Warn("ratelimit deny",
					"tier", tier.String(),
					"key", key,
					"path", req.URL.Path,
					"method", req.Method,
					"reason", d.Reason,
					"retry_after_sec", int(d.RetryAfter.Seconds()),
				)
			}
			WriteDenial(w, d, "Too many requests, try again later")
		}
	}
}

// GlobalMiddleware is the outermost wrapper: server-wide RPS ceiling
// + in-flight semaphore. Off short-circuits immediately so operators
// fronting with their own edge limiter pay no overhead.
func (r *Registry) GlobalMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if r.cfg.Load().Off {
				next.ServeHTTP(w, req)
				return
			}
			if d := r.AllowGlobalRPS(); !d.Allow {
				if logger != nil {
					logger.Warn("ratelimit deny (global_rps)", "path", req.URL.Path, "method", req.Method)
				}
				WriteDenial(w, d, "Server busy, try again shortly")
				return
			}
			release, d := r.AcquireGlobal(req.Context())
			if !d.Allow {
				if logger != nil {
					logger.Warn("ratelimit deny (global_inflight)", "path", req.URL.Path, "method", req.Method)
				}
				WriteDenial(w, d, "Server at capacity, try again shortly")
				return
			}
			defer release()
			next.ServeHTTP(w, req)
		})
	}
}

// WriteDenial emits a 429 with standard rate-limit headers. Exported
// so handlers that do in-handler limit checks (e.g. login's email
// bucket) share the same response shape as the middleware.
func WriteDenial(w http.ResponseWriter, d Decision, message string) {
	writeRateLimitHeaders(w, d)
	if d.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(d.RetryAfter.Seconds())))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	body, _ := json.Marshal(map[string]string{
		"error":   "too_many_requests",
		"message": message,
	})
	_, _ = w.Write(body)
}

func writeRateLimitHeaders(w http.ResponseWriter, d Decision) {
	if d.Limit > 0 {
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(d.Limit))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(d.Remaining))
	}
}

