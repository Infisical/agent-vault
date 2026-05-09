package isolation

import (
	"net"
	"runtime"
)

// HostBindIP returns the IP the forwarder should bind on so that the
// container's host.docker.internal resolves to a listener we own.
//
// On Linux, `--add-host=host.docker.internal:host-gateway` makes the
// container resolve that name to *this network's* gateway IP on the
// host side, so we bind there — reachable only from the per-invocation
// network.
//
// On macOS/Windows (Docker Desktop), host.docker.internal is routed
// through Docker Desktop's VM networking to some host interface, but
// which one varies by Docker Desktop version + VM backend (vpnkit
// historically targeted lo0; VZ/virtiofsd on Apple Silicon deliver to
// a different bridge). To be robust across versions we bind 0.0.0.0.
// The forwarder still requires a vault-scoped session token for any
// request to reach the broker, so LAN exposure on an ephemeral port
// is not a meaningful attack surface.
func HostBindIP(n *Network) net.IP {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return net.IPv4(0, 0, 0, 0)
	}
	if n == nil || n.GatewayIP == nil {
		return nil
	}
	return n.GatewayIP
}
