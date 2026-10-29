package mitm

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/ratelimit"
)

// denialLogInterval bounds how often denials for one rate-limit key are
// logged. A client hammering a closed gate would otherwise turn every 429
// into a log line, amplifying the flood into the log pipeline.
const denialLogInterval = 30 * time.Second

// denialLogMaxKeys caps the per-key throttle map. Once every tracked key is
// still live, further new keys share one overflow bucket, so the log rate
// stays bounded by roughly (denialLogMaxKeys+1) lines per interval.
const denialLogMaxKeys = 4096

// denialOverflowKey is the shared bucket for new keys while the map is full.
const denialOverflowKey = "overflow" // real keys are "mitm:"-prefixed

// maxLoggedTargetLen bounds the client-supplied authority in denial logs;
// the gate runs before target validation. 253-byte hostname plus port.
const maxLoggedTargetLen = 260

type denialEntry struct {
	last       time.Time
	suppressed int
}

// denialLog throttles MITM rate-limit denial logs per key. The zero value
// is ready to use.
type denialLog struct {
	mu        sync.Mutex
	seen      map[string]*denialEntry
	lastPrune time.Time
}

// admit reports whether a denial for key should be logged now and, if so,
// how many denials for key (or for the overflow bucket it fell into) were
// suppressed since the last logged one.
func (l *denialLog) admit(key string, now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil {
		l.seen = make(map[string]*denialEntry)
	}
	e, ok := l.seen[key]
	if !ok && len(l.seen) >= denialLogMaxKeys {
		l.prune(now)
		if len(l.seen) >= denialLogMaxKeys {
			key = denialOverflowKey
			e, ok = l.seen[key]
		}
	}
	if !ok {
		l.seen[key] = &denialEntry{last: now}
		return true, 0
	}
	if now.Sub(e.last) < denialLogInterval {
		e.suppressed++
		return false, 0
	}
	suppressed := e.suppressed
	e.last, e.suppressed = now, 0
	return true, suppressed
}

// prune drops expired entries, at most once per interval so a flood of
// distinct keys against a full map doesn't rescan it on every denial.
func (l *denialLog) prune(now time.Time) {
	if now.Sub(l.lastPrune) < denialLogInterval {
		return
	}
	l.lastPrune = now
	for k, e := range l.seen {
		if now.Sub(e.last) >= denialLogInterval {
			delete(l.seen, k)
		}
	}
}

func truncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}

// denyAuthFlood writes the 429 for a TierAuth pre-gate denial and logs it
// (throttled per key). Denied requests never reach the forward handler, so
// without this log there is no broker-side trace of the denial at all.
func (p *Proxy) denyAuthFlood(w http.ResponseWriter, r *http.Request, ingress, key string, d ratelimit.Decision, message string) {
	if ok, suppressed := p.denials.admit(key, time.Now()); ok {
		p.logger.Warn("mitm rate limit denied",
			slog.String("ingress", ingress),
			slog.String("tier", ratelimit.TierAuth.String()),
			slog.String("key", key),
			slog.String("reason", d.Reason),
			slog.String("target", truncateForLog(r.Host, maxLoggedTargetLen)),
			slog.Duration("retry_after", d.RetryAfter),
			slog.Int("suppressed", suppressed))
	}
	ratelimit.WriteDenial(w, d, message)
}
