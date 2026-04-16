package server

import "net/http"

// handleMITMCA serves the transparent-proxy root CA certificate in PEM form.
// Public (no auth): the CA is world-readable by design — clients install it
// into local trust stores to validate proxy-minted leaves.
func (s *Server) handleMITMCA(w http.ResponseWriter, _ *http.Request) {
	if s.mitm == nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("MITM proxy is not enabled on this server\n"))
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="agent-vault-ca.pem"`)
	_, _ = w.Write(s.mitm.RootPEM())
}
