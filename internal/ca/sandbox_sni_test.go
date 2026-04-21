package ca

import (
	"testing"
)

// TestValidateSNI_HostDockerInternal locks in the invariant that the
// sandbox container mode depends on: a TLS ClientHello with
// SNI=host.docker.internal (what the container's HTTPS client sends
// when dialing the forwarder) must be accepted by MintLeaf, so the
// inner MITM listener can mint a matching leaf and the handshake
// succeeds. Tightening validateSNI without updating this test would
// silently break `vault run --sandbox=container`.
func TestValidateSNI_HostDockerInternal(t *testing.T) {
	isIP, err := validateSNI("host.docker.internal")
	if err != nil {
		t.Fatalf("validateSNI(host.docker.internal) = err %v, want nil", err)
	}
	if isIP {
		t.Error("host.docker.internal should validate as a DNS name, not an IP")
	}
}
