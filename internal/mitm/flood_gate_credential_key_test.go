package mitm

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
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

// Keying on the credential alone would let an unauthenticated client
// dodge the gate by sending a fresh Proxy-Authorization value on every
// attempt. Every newly seen failing credential must still count against
// the peer, so a rotating-credential flood from one peer is gated.
func TestConnectFloodGateGatesRotatingCredentials(t *testing.T) {
	cfg := ratelimit.DefaultsFor(ratelimit.ProfileDefault)
	cfg.Tiers[ratelimit.TierAuth].Max = 3
	p := &Proxy{rateLimit: ratelimit.New(cfg)}

	connect := func(proxyAuth string) int {
		r := httptest.NewRequest(http.MethodConnect, "http://github.com:443", nil)
		r.RemoteAddr = "203.0.113.7:5555"
		r.Header.Set("Proxy-Authorization", proxyAuth)
		w := httptest.NewRecorder()
		p.handleConnect(w, r)
		return w.Code
	}

	for i := 0; i < 3; i++ {
		if code := connect(fmt.Sprintf("Basic !!!rotating-%d!!!", i)); code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d: gated before the peer budget was spent", i+1)
		}
	}
	if code := connect("Basic !!!rotating-fresh!!!"); code != http.StatusTooManyRequests {
		t.Fatalf("rotating-credential flood: want 429 once the peer budget is spent, got %d", code)
	}
}

// Forward-proxy (absolute-form) requests share the gate with CONNECT:
// one credential's failures from a shared peer must not 429 a different,
// valid credential arriving from that same peer, while rotating bad
// credentials from the peer are still gated.
func TestForwardFloodGateKeysOnCredential(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	upHost, upPort, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upHost: {result: &brokercore.InjectResult{Passthrough: true}},
	}}
	proxyURL, _, p := setupProxy(t, sr, cp)

	cfg := ratelimit.DefaultsFor(ratelimit.ProfileDefault)
	cfg.Tiers[ratelimit.TierAuth].Max = 3
	p.rateLimit = ratelimit.New(cfg)
	overrideRemoteAddr(p, "203.0.113.7:5555") // one ingress IP for everyone

	forward := func(token string) int {
		conn := dialProxy(t, proxyURL)
		defer conn.Close()
		resp := writeRawRequestLine(t, conn,
			fmt.Sprintf("GET http://%s:%s/x HTTP/1.1", upHost, upPort),
			map[string]string{
				"Host":                upstream.Listener.Addr().String(),
				"Proxy-Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(token+":")),
			})
		resp.Body.Close()
		return resp.StatusCode
	}

	// Client A burns its whole budget with one bad credential.
	for i := 0; i < 3; i++ {
		if code := forward("av_sess_bad_a"); code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d: client A gated before its budget was spent", i+1)
		}
	}
	if code := forward("av_sess_bad_a"); code != http.StatusTooManyRequests {
		t.Fatalf("exhausted credential: want 429, got %d", code)
	}
	// A valid credential from the same peer is unaffected.
	if code := forward("av_sess_ok"); code != http.StatusOK {
		t.Fatalf("valid credential from the same peer: want 200, got %d", code)
	}
	// Rotating bad credentials from the peer still hit the peer budget
	// (A's first failure already counted once against it).
	for i := 0; i < 2; i++ {
		if code := forward(fmt.Sprintf("av_sess_rotating_%d", i)); code == http.StatusTooManyRequests {
			t.Fatalf("rotating attempt %d: gated before the peer budget was spent", i+1)
		}
	}
	if code := forward("av_sess_rotating_fresh"); code != http.StatusTooManyRequests {
		t.Fatalf("rotating-credential flood: want 429 once the peer budget is spent, got %d", code)
	}
}
