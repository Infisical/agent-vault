package server

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/ca"
	"github.com/Infisical/agent-vault/internal/mitm"
)

func TestHandleMITMCA(t *testing.T) {
	t.Run("mitm_enabled", func(t *testing.T) {
		srv := newTestServer()

		masterKey := make([]byte, 32)
		if _, err := rand.Read(masterKey); err != nil {
			t.Fatalf("rand: %v", err)
		}
		caProv, err := ca.New(masterKey, ca.Options{Dir: t.TempDir()})
		if err != nil {
			t.Fatalf("ca.New: %v", err)
		}
		p := mitm.New("127.0.0.1:0", caProv, srv.SessionResolver(), srv.CredentialProvider(), srv.BaseURL(), srv.Logger())
		srv.AttachMITM(p)

		// Start the proxy so IsListening() reports true. The handler gates
		// the PEM response on listener state to avoid advertising a CA cert
		// for a proxy that failed to bind.
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = p.Serve(l)
		}()
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = p.Shutdown(ctx)
			wg.Wait()
		})
		waitForListening(t, p)

		req := httptest.NewRequest(http.MethodGet, "/v1/mitm/ca.pem", nil)
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/x-pem-file" {
			t.Fatalf("Content-Type: got %q, want application/x-pem-file", ct)
		}
		if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "agent-vault-ca.pem") {
			t.Fatalf("Content-Disposition: got %q, want filename=agent-vault-ca.pem", cd)
		}

		if got := rec.Header().Get("X-MITM-TLS"); got != "1" {
			t.Errorf("X-MITM-TLS = %q, want \"1\"", got)
		}

		block, _ := pem.Decode(rec.Body.Bytes())
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatal("response body did not decode as a CERTIFICATE PEM block")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("x509.ParseCertificate: %v", err)
		}
		if !cert.IsCA {
			t.Fatal("returned certificate is not a CA certificate")
		}
	})

	// Guards the contract relied on by `vault run`: the listening port must
	// be advertised so clients can build HTTPS_PROXY pointing at the *real*
	// port (not the compile-time default) when --mitm-port is non-standard.
	t.Run("mitm_port_header", func(t *testing.T) {
		srv := newTestServer()

		masterKey := make([]byte, 32)
		if _, err := rand.Read(masterKey); err != nil {
			t.Fatalf("rand: %v", err)
		}
		caProv, err := ca.New(masterKey, ca.Options{Dir: t.TempDir()})
		if err != nil {
			t.Fatalf("ca.New: %v", err)
		}
		// Bind to an explicit non-default port so we can assert the
		// header reflects the configured Addr rather than any constant.
		p := mitm.New("127.0.0.1:19322", caProv, srv.SessionResolver(), srv.CredentialProvider(), srv.BaseURL(), srv.Logger())
		srv.AttachMITM(p)

		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = p.Serve(l)
		}()
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = p.Shutdown(ctx)
			wg.Wait()
		})
		waitForListening(t, p)

		req := httptest.NewRequest(http.MethodGet, "/v1/mitm/ca.pem", nil)
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		if got := rec.Header().Get("X-MITM-Port"); got != "19322" {
			t.Errorf("X-MITM-Port = %q, want 19322", got)
		}
	})

	t.Run("mitm_disabled", func(t *testing.T) {
		srv := newTestServer()

		req := httptest.NewRequest(http.MethodGet, "/v1/mitm/ca.pem", nil)
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Fatalf("Content-Type: got %q, want text/plain*", ct)
		}
		if strings.TrimSpace(rec.Body.String()) == "" {
			t.Fatal("expected non-empty plaintext error body")
		}
	})

	// Guards the regression where a bind failure left s.mitm non-nil and
	// the endpoint kept serving a PEM for a proxy that was not listening.
	t.Run("mitm_attached_but_not_listening", func(t *testing.T) {
		srv := newTestServer()

		masterKey := make([]byte, 32)
		if _, err := rand.Read(masterKey); err != nil {
			t.Fatalf("rand: %v", err)
		}
		caProv, err := ca.New(masterKey, ca.Options{Dir: t.TempDir()})
		if err != nil {
			t.Fatalf("ca.New: %v", err)
		}
		p := mitm.New("127.0.0.1:0", caProv, srv.SessionResolver(), srv.CredentialProvider(), srv.BaseURL(), srv.Logger())
		srv.AttachMITM(p)
		// Intentionally do not call Serve — simulates a bind failure.

		req := httptest.NewRequest(http.MethodGet, "/v1/mitm/ca.pem", nil)
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 while proxy not listening, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}

// waitForListening spins until the Proxy reports it has bound its listener,
// or fails the test after a short timeout. Needed because Serve flips the
// atomic flag on a background goroutine.
func waitForListening(t *testing.T, p *mitm.Proxy) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p.IsListening() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("proxy did not report IsListening within timeout")
}
