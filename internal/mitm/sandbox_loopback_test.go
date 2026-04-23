package mitm

import (
	"net/http"
	"testing"
)

// TestIsLoopbackPeer_CoversForwarderLaundering pins the invariant that
// lets `vault run --sandbox=container` skip TierAuth rate limiting
// without any code change to the limiter: the sandbox forwarder dials
// 127.0.0.1:<mitm-port>, so every container CONNECT arrives at the
// MITM with a loopback RemoteAddr — matching the same exemption that
// the local-agent process path relies on.
//
// If this test ever fails, the forwarder is no longer laundering the
// source IP (the forwarder changed how it dials upstream, or
// isLoopbackPeer was tightened). Either way, container mode would
// start getting 429'd on CONNECT bursts; update the rate-limit path
// before merging such a change.
func TestIsLoopbackPeer_CoversForwarderLaundering(t *testing.T) {
	// RemoteAddr shape matches what net/http reports after Hijack on
	// a loopback-dialed connection: "127.0.0.1:<ephemeral>".
	r := &http.Request{RemoteAddr: "127.0.0.1:48293"}
	if !isLoopbackPeer(r) {
		t.Fatal("forwarder-laundered loopback conn must be recognized as loopback peer")
	}
}
