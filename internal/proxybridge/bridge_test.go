package proxybridge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestBridgeSplicesBytesBidirectionally is the flagship test: a plain TCP
// client writes bytes into the bridge, the bridge wraps them in TLS to the
// upstream, the upstream's reply is decrypted and copied back to the
// client. This is the property the bug fix turns on.
func TestBridgeSplicesBytesBidirectionally(t *testing.T) {
	caPEM, serverCert := newTestCA(t)
	upstream, upstreamAddr := startTLSEchoServer(t, serverCert)
	defer upstream.Close()

	caPath := writeTempPEM(t, caPEM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bridge, err := Start(ctx, upstreamAddr, caPath, "localhost", nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = bridge.Close() }()

	// Client side: plain TCP to the bridge — no TLS, no auth.
	client, err := net.Dial("tcp", bridge.Addr())
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	// Client → upstream: send a payload, expect it echoed back.
	const payload = "hello-bridge-12345"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatalf("client write: %v", err)
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf) != payload {
		t.Fatalf("echoed bytes = %q, want %q", buf, payload)
	}

	// Second round-trip confirms the splice keeps working past the first frame.
	const payload2 = "second-frame-67890"
	if _, err := client.Write([]byte(payload2)); err != nil {
		t.Fatalf("client write 2: %v", err)
	}
	buf2 := make([]byte, len(payload2))
	if _, err := io.ReadFull(client, buf2); err != nil {
		t.Fatalf("client read 2: %v", err)
	}
	if string(buf2) != payload2 {
		t.Fatalf("echoed bytes 2 = %q, want %q", buf2, payload2)
	}
}

// TestBridgeRejectsTrustFailureFromBadCA confirms the bridge fails closed
// when its CA bundle doesn't sign the upstream's cert. The client
// connection should close without bytes flowing.
func TestBridgeRejectsTrustFailureFromBadCA(t *testing.T) {
	// Server uses one CA; bridge is configured to trust a *different* CA.
	_, serverCert := newTestCA(t)
	otherCAPEM, _ := newTestCA(t)

	upstream, upstreamAddr := startTLSEchoServer(t, serverCert)
	defer upstream.Close()

	caPath := writeTempPEM(t, otherCAPEM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bridge, err := Start(ctx, upstreamAddr, caPath, "localhost", nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = bridge.Close() }()

	client, err := net.Dial("tcp", bridge.Addr())
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))

	// Bridge does a TLS handshake to upstream lazily — i.e. only after
	// the client connects. With a bad CA, the handshake fails and the
	// bridge closes the client side. A read should return EOF (clean
	// close) or a connection-closed error; anything else means bytes
	// flowed when they shouldn't have.
	buf := make([]byte, 16)
	n, err := client.Read(buf)
	if n != 0 {
		t.Fatalf("read returned %d bytes %q, want 0 (trust failure should close immediately)", n, buf[:n])
	}
	if err == nil {
		t.Fatal("read returned nil error after trust failure, want EOF or closed-conn error")
	}
	if !errors.Is(err, io.EOF) && !isClosedConnErr(err) {
		t.Fatalf("read err = %v, want EOF or closed-conn error", err)
	}
}

// TestBridgeRejectsMissingCAFile covers the constructor's PEM-load path:
// a missing or unreadable CA file must surface an error at Start time,
// before any listener binds, so launch code fails fast.
func TestBridgeRejectsMissingCAFile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err := Start(ctx, "127.0.0.1:1", "/nonexistent/path/to/ca.pem", "localhost", nil)
	if err == nil {
		t.Fatal("Start with missing CA returned nil error, want failure")
	}
}

// TestBridgeRejectsEmptyCAFile covers the empty-PEM branch: a file that
// exists but contains no parseable certs must also fail at Start time.
func TestBridgeRejectsEmptyCAFile(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(caPath, []byte("not a pem file\n"), 0o600); err != nil {
		t.Fatalf("write empty CA: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err := Start(ctx, "127.0.0.1:1", caPath, "localhost", nil)
	if err == nil {
		t.Fatal("Start with empty CA returned nil error, want failure")
	}
}

// TestBridgeCloseStopsAcceptingNewConnections confirms the listener is
// shut down when Close() is called and new dials fail.
func TestBridgeCloseStopsAcceptingNewConnections(t *testing.T) {
	caPEM, serverCert := newTestCA(t)
	upstream, upstreamAddr := startTLSEchoServer(t, serverCert)
	defer upstream.Close()
	caPath := writeTempPEM(t, caPEM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bridge, err := Start(ctx, upstreamAddr, caPath, "localhost", nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := bridge.Addr()
	if err := bridge.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// New dials should fail. Give the OS a moment to surface the closed
	// listener — the dial races against the kernel's accept-queue teardown.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return // expected
		}
		_ = c.Close()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("dial to closed bridge at %s succeeded; expected refusal", addr)
}

// TestBridgeBindsLoopbackOnly asserts the listener address is on
// 127.0.0.1, not 0.0.0.0 or any external interface. This is a
// security-critical property — the bridge intentionally limits
// cleartext exposure to the network namespace.
func TestBridgeBindsLoopbackOnly(t *testing.T) {
	caPEM, serverCert := newTestCA(t)
	upstream, upstreamAddr := startTLSEchoServer(t, serverCert)
	defer upstream.Close()
	caPath := writeTempPEM(t, caPEM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bridge, err := Start(ctx, upstreamAddr, caPath, "localhost", nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = bridge.Close() }()

	host, _, err := net.SplitHostPort(bridge.Addr())
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", bridge.Addr(), err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		t.Fatalf("bridge bound to %s (loopback=%v); must be loopback-only", host, ip != nil && ip.IsLoopback())
	}
}

// ----- test helpers below -----

// newTestCA creates a self-signed cert+key valid for "localhost" / 127.0.0.1
// and returns both the PEM-encoded CA cert (to write to disk for the
// bridge) and a tls.Certificate ready to plug into a server. We're using
// the same cert as CA and leaf for brevity — production code wouldn't,
// but the bridge only validates that the leaf chains to the configured
// trust pool, which it does trivially when leaf == root.
func newTestCA(t *testing.T) ([]byte, tls.Certificate) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "agent-vault-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return certPEM, tlsCert
}

// writeTempPEM dumps PEM bytes to a per-test temp file and returns its
// path. Cleaned up by t.TempDir() teardown.
func writeTempPEM(t *testing.T, pem []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	return path
}

// startTLSEchoServer is a minimal TLS server that echoes every byte it
// reads back to the same connection. Stands in for agent-vault's MITM
// listener for the purposes of byte-splice testing — we don't care
// about HTTP semantics here, just that bytes flow.
func startTLSEchoServer(t *testing.T, cert tls.Certificate) (net.Listener, string) {
	t.Helper()
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}

	var wg sync.WaitGroup
	t.Cleanup(func() { wg.Wait() })

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return // listener closed
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn) // echo
			}()
		}
	}()

	return l, l.Addr().String()
}

// isClosedConnErr returns true for the platform-specific bag of errors
// that mean "the other side hung up." Used in the trust-failure test
// where the exact error varies by OS and TLS implementation.
func isClosedConnErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	// On macOS/Linux, a reset connection surfaces as a syscall.ECONNRESET
	// wrapped in net.OpError. The string check is a pragmatic fallback —
	// the trust-failure test doesn't need surgical error matching, just
	// "the bytes didn't flow."
	msg := err.Error()
	for _, needle := range []string{"closed", "reset", "broken pipe", "EOF"} {
		if containsCI(msg, needle) {
			return true
		}
	}
	return false
}

func containsCI(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(haystack) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			a, b := haystack[i+j], needle[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
