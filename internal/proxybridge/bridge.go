// Package proxybridge implements a per-child loopback TLS terminator.
//
// Some HTTP clients (notably tokio-tungstenite, which Codex uses for its
// Responses WebSocket transport) reject HTTPS_PROXY URLs whose scheme is
// `https://`. Agent Vault's MITM listener is TLS-wrapped so that
// Proxy-Authorization stays confidential on the wire, which means the
// default HTTPS_PROXY value uses `https://`. Those clients fail at proxy
// URL parsing before any I/O.
//
// The bridge accepts plain TCP on 127.0.0.1 and splices each connection to
// agent-vault's TLS-wrapped MITM proxy. The child sees scheme `http://`
// (which its proxy parser accepts) on a loopback authority; the on-wire
// hop between agent and broker remains TLS-wrapped exactly as today. The
// cleartext exposure is bounded to the agent container's own network
// namespace — any attacker who can sniff loopback there can already read
// /proc/<pid>/environ.
package proxybridge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
)

// Bridge accepts plain TCP on loopback and splices each connection to a
// TLS upstream. Callers point the child's HTTPS_PROXY/HTTP_PROXY at
// Addr() and must Close() when the child has exited.
type Bridge struct {
	listener net.Listener
	upstream string
	tlsCfg   *tls.Config
}

// Start binds 127.0.0.1:0 and returns a Bridge running its accept loop in
// a goroutine. upstreamHostPort is the host:port of agent-vault's MITM
// listener; caPath is a PEM file the bridge trusts when dialing the
// upstream; sniHost is the ServerName used for the TLS handshake.
func Start(ctx context.Context, upstreamHostPort, caPath, sniHost string) (*Bridge, error) {
	pem, err := os.ReadFile(caPath) //nolint:gosec // caPath comes from the same trusted source as the existing CA write path
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA file %s contains no usable certs", caPath)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen on loopback: %w", err)
	}
	b := &Bridge{
		listener: l,
		upstream: upstreamHostPort,
		tlsCfg: &tls.Config{
			RootCAs:    pool,
			ServerName: sniHost,
			MinVersion: tls.VersionTLS12,
		},
	}
	go b.acceptLoop(ctx)
	return b, nil
}

// Addr returns the loopback host:port the listener is bound to.
func (b *Bridge) Addr() string { return b.listener.Addr().String() }

// Close stops accepting new connections. In-flight connections continue
// until their bytes drain or one side closes.
func (b *Bridge) Close() error { return b.listener.Close() }

func (b *Bridge) acceptLoop(ctx context.Context) {
	for {
		conn, err := b.listener.Accept()
		if err != nil {
			return // listener closed
		}
		go b.handle(ctx, conn)
	}
}

func (b *Bridge) handle(ctx context.Context, client net.Conn) {
	defer func() { _ = client.Close() }()

	d := &tls.Dialer{Config: b.tlsCfg}
	upstream, err := d.DialContext(ctx, "tcp", b.upstream)
	if err != nil {
		return
	}
	defer func() { _ = upstream.Close() }()

	// Bidirectional splice. First side to EOF/error ends both.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}
