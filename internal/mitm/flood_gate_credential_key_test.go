package mitm

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Infisical/agent-vault/internal/ratelimit"
)

// Regression test for https://github.com/Infisical/agent-vault/issues/380.
//
// The auth-failure flood gate must key on the presented credential, not
// the peer IP: behind a shared ingress or NAT the backend's RemoteAddr
// collapses to a small set of proxy IPs, so an IP-keyed bucket lets one
// client's bad credentials exhaust the budget and 429 every other
// client arriving through the same ingress — including fully
// authenticated ones.
func TestConnectFloodGateKeysOnCredential(t *testing.T) {
	cfg := ratelimit.DefaultsFor(ratelimit.ProfileDefault)
	cfg.Tiers[ratelimit.TierAuth].Max = 3
	p := &Proxy{rateLimit: ratelimit.New(cfg)}

	const sharedIP = "203.0.113.7:5555" // one ingress IP for everyone

	badConnect := func(proxyAuth string) int {
		r := httptest.NewRequest(http.MethodConnect, "http://github.com:443", nil)
		r.RemoteAddr = sharedIP
		if proxyAuth != "" {
			r.Header.Set("Proxy-Authorization", proxyAuth)
		}
		w := httptest.NewRecorder()
		p.handleConnect(w, r)
		return w.Code
	}

	// Client A burns its whole auth-failure budget with bad credentials.
	for i := 0; i < 3; i++ {
		if code := badConnect("Basic !!!bad-a!!!"); code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d: client A gated before its budget was spent", i+1)
		}
	}
	// Client A is now gated.
	if code := badConnect("Basic !!!bad-a!!!"); code != http.StatusTooManyRequests {
		t.Fatalf("exhausted credential: want 429, got %d", code)
	}
	// A different credential from the SAME source IP must not be gated.
	if code := badConnect("Basic !!!bad-b!!!"); code == http.StatusTooManyRequests {
		t.Fatal("credential B from the same source IP was 429'd by client A's failures")
	}
	// An unauthenticated request from the same IP must not be gated either
	// (its first failure starts a fresh IP-fallback budget).
	if code := badConnect(""); code == http.StatusTooManyRequests {
		t.Fatal("unauthenticated request from the same source IP was 429'd by client A's failures")
	}
	// The IP fallback still gates unauthenticated floods.
	for i := 0; i < 3; i++ {
		badConnect("")
	}
	if code := badConnect(""); code != http.StatusTooManyRequests {
		t.Fatalf("unauthenticated flood: want 429 after budget exhausted, got %d", code)
	}
}
