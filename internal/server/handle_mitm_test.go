package server

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
		p := mitm.New("127.0.0.1:0", caProv, srv.SessionResolver(), srv.CredentialProvider())
		srv.AttachMITM(p)

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
}
