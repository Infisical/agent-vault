package server

import (
	"net"
	"net/http"
)

// handleMITMCA serves the transparent-proxy root CA certificate in PEM form.
// Public (no auth): the CA is world-readable by design — clients install it
// into local trust stores to validate proxy-minted leaves.
//
// Gated on IsListening, not just non-nil: when the proxy fails to bind
// (port conflict with default-on MITM), s.mitm is still attached but
// nothing is accepting connections. Returning a PEM in that state would
// lead operators to install a cert and configure HTTPS_PROXY for a port
// that silently refuses connections.
//
// The X-MITM-Port response header advertises the port the proxy is bound
// to. Clients (e.g. `agent-vault vault run`) use this instead of a
// hardcoded default so non-standard --mitm-port values actually work.
func (s *Server) handleMITMCA(w http.ResponseWriter, _ *http.Request) {
	if s.mitm == nil || !s.mitm.IsListening() {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("MITM proxy is not enabled on this server\n"))
		return
	}
	if _, port, err := net.SplitHostPort(s.mitm.Addr()); err == nil && port != "" && port != "0" {
		w.Header().Set("X-MITM-Port", port)
	}
	w.Header().Set("X-MITM-TLS", "1")
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="agent-vault-ca.pem"`)
	_, _ = w.Write(s.mitm.RootPEM())
}
