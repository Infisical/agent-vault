package sandbox

import (
	"net"
	"runtime"
)

// HostBindIP returns the IP the forwarder should bind on so that the
// container's host.docker.internal resolves to a listener we own.
//
// On Linux, Docker's `--add-host=host.docker.internal:host-gateway`
// makes the container resolve that name to *this network's* gateway
// IP, so we bind there. On macOS and Windows (Docker Desktop),
// host.docker.internal is routed through Docker Desktop's VPN to the
// host's loopback, so binding 127.0.0.1 is correct.
func HostBindIP(n *Network) net.IP {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return net.IPv4(127, 0, 0, 1)
	}
	if n == nil || n.GatewayIP == nil {
		return nil
	}
	return n.GatewayIP
}
