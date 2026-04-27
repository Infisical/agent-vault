package isolation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Forwarder is a pair of raw TCP relays (HTTP + MITM) that bridge the
// container's per-invocation network gateway to agent-vault's loopback
// listeners. Relaying by loopback dial is load-bearing: it keeps
// isLoopbackPeer() true for container traffic, preserving the rate-limit
// exemption without a code change to the limiter.
type Forwarder struct {
	HTTPPort int
	MITMPort int

	cancel context.CancelFunc
	wg     sync.WaitGroup
	done   chan struct{}

	httpListener net.Listener
	mitmListener net.Listener
}

// StartForwarder binds two ephemeral listeners on bindIP and relays to
// 127.0.0.1:{upstreamHTTPPort, upstreamMITMPort}. The caller calls
// Close on error paths; in the success path syscall.Exec replaces the
// process and the kernel closes the CLOEXEC listeners.
func StartForwarder(parent context.Context, bindIP net.IP, upstreamHTTPPort, upstreamMITMPort int) (*Forwarder, error) {
	if bindIP == nil {
		return nil, errors.New("StartForwarder: bindIP required")
	}
	ctx, cancel := context.WithCancel(parent)
	fwd := &Forwarder{cancel: cancel, done: make(chan struct{})}

	httpL, err := listenEphemeral(bindIP)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("bind HTTP forwarder: %w", err)
	}
	mitmL, err := listenEphemeral(bindIP)
	if err != nil {
		_ = httpL.Close()
		cancel()
		return nil, fmt.Errorf("bind MITM forwarder: %w", err)
	}
	fwd.httpListener = httpL
	fwd.mitmListener = mitmL
	fwd.HTTPPort = httpL.Addr().(*net.TCPAddr).Port
	fwd.MITMPort = mitmL.Addr().(*net.TCPAddr).Port

	fwd.wg.Add(2)
	go fwd.serve(ctx, httpL, upstreamHTTPPort)
	go fwd.serve(ctx, mitmL, upstreamMITMPort)
	go func() {
		fwd.wg.Wait()
		close(fwd.done)
	}()
	return fwd, nil
}

// Close is safe to call multiple times.
func (f *Forwarder) Close() error {
	if f.cancel != nil {
		f.cancel()
	}
	if f.httpListener != nil {
		_ = f.httpListener.Close()
	}
	if f.mitmListener != nil {
		_ = f.mitmListener.Close()
	}
	<-f.done
	return nil
}

func listenEphemeral(bindIP net.IP) (net.Listener, error) {
	return net.Listen("tcp", net.JoinHostPort(bindIP.String(), "0"))
}

func (f *Forwarder) serve(ctx context.Context, l net.Listener, upstreamPort int) {
	defer f.wg.Done()

	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	var connWG sync.WaitGroup
	defer connWG.Wait()

	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		connWG.Add(1)
		go func() {
			defer connWG.Done()
			relay(ctx, conn, upstreamPort)
		}()
	}
}

func relay(ctx context.Context, client net.Conn, upstreamPort int) {
	defer func() { _ = client.Close() }()

	upstream, err := dialLoopback(ctx, upstreamPort)
	if err != nil {
		return
	}
	defer func() { _ = upstream.Close() }()

	// First EOF closes both conns. HTTPS record streams can't do
	// anything useful after either side closes, so no half-close dance.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}

func dialLoopback(ctx context.Context, port int) (net.Conn, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	return d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
}
