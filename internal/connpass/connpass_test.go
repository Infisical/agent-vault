//go:build unix

package connpass

import (
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// controlPair returns the parent's end and Agent Vault's end of a control
// socket pair.
func controlPair(t *testing.T) (parent *net.UnixConn, child *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn := func(fd int, name string) *net.UnixConn {
		f := os.NewFile(uintptr(fd), name)
		defer f.Close()
		c, err := net.FileConn(f)
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	parent, child = conn(fds[0], "parent"), conn(fds[1], "child")
	t.Cleanup(func() { parent.Close(); child.Close() })
	return parent, child
}

// pass sends a fresh socket pair's far end over control with tag, and
// returns the near end.
func pass(t *testing.T, control *net.UnixConn, tag byte) net.Conn {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := control.WriteMsgUnix([]byte{tag}, syscall.UnixRights(fds[1]), nil); err != nil {
		t.Fatal(err)
	}
	syscall.Close(fds[1])
	f := os.NewFile(uintptr(fds[0]), "near")
	defer f.Close()
	c, err := net.FileConn(f)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func accept(t *testing.T, l net.Listener) net.Conn {
	t.Helper()
	got := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
		}
		got <- c
	}()
	select {
	case c := <-got:
		t.Cleanup(func() { c.Close() })
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("nothing accepted")
		return nil
	}
}

func roundTrip(t *testing.T, from, to net.Conn) {
	t.Helper()
	if _, err := from.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(to, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("read %q, %v", buf, err)
	}
}

func TestServe_DeliversEachConnectionToTheListenerItsTagNames(t *testing.T) {
	parent, child := controlPair(t)
	api, proxy := NewListener("api"), NewListener("proxy")
	go Serve(child, api, proxy)

	near := pass(t, parent, TagAPI)
	roundTrip(t, near, accept(t, api))
	near = pass(t, parent, TagProxy)
	roundTrip(t, accept(t, proxy), near)
}

func TestServe_ReturnsWhenTheParentsEndCloses(t *testing.T) {
	parent, child := controlPair(t)
	done := make(chan error, 1)
	go func() { done <- Serve(child, NewListener("api"), NewListener("proxy")) }()
	parent.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve didn't return after the parent's end closed")
	}
}

func TestServe_ClosesAConnectionWithAnUnknownTagAndGoesOn(t *testing.T) {
	parent, child := controlPair(t)
	api := NewListener("api")
	go Serve(child, api, NewListener("proxy"))

	stray := pass(t, parent, 'x')
	_ = stray.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := stray.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("stray connection still open: %d, %v", n, err)
	}
	near := pass(t, parent, TagAPI)
	roundTrip(t, near, accept(t, api))
}

func TestServe_AcksEachMessageWithItsTagOnceItHoldsTheDescriptor(t *testing.T) {
	parent, child := controlPair(t)
	go Serve(child, NewListener("api"), NewListener("proxy"))

	for _, tag := range []byte{TagAPI, TagProxy, 'x'} {
		pass(t, parent, tag)
		_ = parent.SetReadDeadline(time.Now().Add(5 * time.Second))
		ack := make([]byte, 1)
		if _, err := io.ReadFull(parent, ack); err != nil || ack[0] != tag {
			t.Fatalf("ack for %q: %q, %v", tag, ack, err)
		}
	}
}

// A proxy connection passed with TagProxyAs starts with one line,
// "<token> <vault>", that the parent wrote: the connection's identity. The
// bytes after it are the client's.
func TestServe_BindsAProxyAsConnectionsPreambleAsItsIdentity(t *testing.T) {
	parent, child := controlPair(t)
	proxy := NewListener("proxy")
	go Serve(child, NewListener("api"), proxy)

	near := pass(t, parent, TagProxyAs)
	if _, err := near.Write([]byte("av_sess_tok vault-a\nCONNECT x:443")); err != nil {
		t.Fatal(err)
	}
	c := accept(t, proxy)
	bound, ok := c.(interface{ ProxyIdentity() (string, string) })
	if !ok {
		t.Fatalf("%T has no identity", c)
	}
	if token, vault := bound.ProxyIdentity(); token != "av_sess_tok" || vault != "vault-a" {
		t.Fatalf("identity %q %q", token, vault)
	}
	buf := make([]byte, len("CONNECT x:443"))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "CONNECT x:443" {
		t.Fatalf("read %q, %v", buf, err)
	}
	roundTrip(t, c, near)
}

// A TagProxy connection carries no identity.
func TestServe_PassesAPlainProxyConnectionWithoutAnIdentity(t *testing.T) {
	parent, child := controlPair(t)
	proxy := NewListener("proxy")
	go Serve(child, NewListener("api"), proxy)

	pass(t, parent, TagProxy)
	c := accept(t, proxy)
	if _, ok := c.(interface{ ProxyIdentity() (string, string) }); ok {
		t.Fatalf("%T has an identity", c)
	}
}

// A preamble that isn't "<token> <vault>" closes the connection.
func TestServe_ClosesAProxyAsConnectionWithABadPreamble(t *testing.T) {
	for _, preamble := range []string{"onlytoken\n", " vault\n", "tok \n", "a b c\n"} {
		parent, child := controlPair(t)
		go Serve(child, NewListener("api"), NewListener("proxy"))
		near := pass(t, parent, TagProxyAs)
		if _, err := near.Write([]byte(preamble)); err != nil {
			t.Fatal(err)
		}
		_ = near.SetReadDeadline(time.Now().Add(5 * time.Second))
		if n, err := near.Read(make([]byte, 1)); n != 0 || err == nil {
			t.Fatalf("%q: connection still open: %d, %v", preamble, n, err)
		}
	}
}

func TestListener_AcceptFailsOnceClosed(t *testing.T) {
	l := NewListener("api")
	errs := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		errs <- err
	}()
	l.Close()
	select {
	case err := <-errs:
		if err == nil {
			t.Fatal("Accept succeeded after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept still blocked after Close")
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestFileConn_WrapsADescriptorNetCantType(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	c := fileConn(r)
	defer c.Close()
	if _, err := w.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("read %q, %v", buf, err)
	}
}
