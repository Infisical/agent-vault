package sandbox

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// startEchoUpstream starts a loopback TCP server that echoes each line
// back with "echo: " prefix. Returns the bound port and a stop func.
func startEchoUpstream(t *testing.T) (int, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						_, _ = c.Write(append([]byte("echo: "), buf[:n]...))
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, func() {
		_ = l.Close()
		wg.Wait()
	}
}

func TestForwarder_RoundTripsBytes(t *testing.T) {
	httpPort, stopHTTP := startEchoUpstream(t)
	defer stopHTTP()
	mitmPort, stopMITM := startEchoUpstream(t)
	defer stopMITM()

	fwd, err := StartForwarder(context.Background(), net.ParseIP("127.0.0.1"), httpPort, mitmPort)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer fwd.Close()

	for name, port := range map[string]int{"http": fwd.HTTPPort, "mitm": fwd.MITMPort} {
		t.Run(name, func(t *testing.T) {
			c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
			if err != nil {
				t.Fatalf("dial forwarder: %v", err)
			}
			defer func() { _ = c.Close() }()
			if _, err := c.Write([]byte("ping")); err != nil {
				t.Fatalf("write: %v", err)
			}
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			got, err := io.ReadAll(io.LimitReader(c, 1024))
			if err != nil && err != io.EOF {
				// ReadAll will block until upstream closes; we close client
				// after write so upstream echoes, then we expect to read
				// whatever has arrived. Use a read deadline to bail.
				if !strings.Contains(err.Error(), "i/o timeout") {
					t.Fatalf("read: %v", err)
				}
			}
			if !strings.Contains(string(got), "echo: ping") {
				t.Errorf("got %q, want substring %q", got, "echo: ping")
			}
		})
	}
}

func TestForwarder_CancelClosesCleanly(t *testing.T) {
	_, stop := startEchoUpstream(t)
	defer stop()

	ctx, cancel := context.WithCancel(context.Background())
	fwd, err := StartForwarder(ctx, net.ParseIP("127.0.0.1"), 65534, 65533)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	httpPort := fwd.HTTPPort
	cancel()

	select {
	case <-fwd.done:
	case <-time.After(2 * time.Second):
		t.Fatal("forwarder did not shut down within 2s of ctx cancel")
	}

	// Post-cancel dial should fail — the listener is closed.
	_, err = net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(httpPort)), 200*time.Millisecond)
	if err == nil {
		t.Error("expected dial to fail after forwarder shutdown")
	}
}

func TestForwarder_RequiresBindIP(t *testing.T) {
	_, err := StartForwarder(context.Background(), nil, 1, 2)
	if err == nil {
		t.Fatal("expected error when bindIP is nil")
	}
}

func TestForwarder_UpstreamDownFailsGracefully(t *testing.T) {
	// No echo server running; the forwarder accepts but the relay
	// dial to 127.0.0.1:<port> fails and the client conn is closed.
	// Forwarder itself must not crash.
	fwd, err := StartForwarder(context.Background(), net.ParseIP("127.0.0.1"), 1, 2)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer fwd.Close()

	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(fwd.HTTPPort)), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	// Read should hit EOF quickly when upstream dial fails.
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	_, err = c.Read(buf)
	if err == nil {
		t.Error("expected EOF or read error when upstream is down")
	}
}
