//go:build unix

// Package connpass serves connections a parent process passes over a
// private control socket (SCM_RIGHTS), instead of listening on a port.
// Nothing on the machine can reach the server except through its parent,
// and the control socket's EOF says the parent is gone.
package connpass

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Each message on the control socket is one tag byte with one descriptor.
// Serve writes the tag byte back once it holds the descriptor: until then
// the parent keeps its copy open, since macOS can flush a Unix socket that
// only a message in flight refers to.
const (
	TagAPI   byte = 'A'
	TagProxy byte = 'P'
	// TagProxyAs is a proxy connection whose first line, written by the
	// parent, is "<token> <vault>": its identity for every request, in
	// place of the client's Proxy-Authorization (mitm.BoundConn).
	TagProxyAs byte = 'I'
)

// maxPreamble bounds the identity line.
const maxPreamble = 1024

// Listener is a net.Listener fed by Serve.
type Listener struct {
	addr   addr
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func NewListener(name string) *Listener {
	return &Listener{
		addr:   addr(name),
		conns:  make(chan net.Conn),
		closed: make(chan struct{}),
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *Listener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *Listener) Addr() net.Addr { return l.addr }

// deliver hands c to Accept, or closes it once the listener is closed.
func (l *Listener) deliver(c net.Conn) {
	select {
	case l.conns <- c:
	case <-l.closed:
		_ = c.Close()
	}
}

type addr string

func (a addr) Network() string { return "connpass" }
func (a addr) String() string  { return string(a) }

// Serve delivers each passed connection to api or proxy by its tag, until
// the parent's end of control closes (nil) or reading it fails.
func Serve(control *net.UnixConn, api, proxy *Listener) error {
	tag := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(4*4))
	for {
		n, oobn, _, _, err := control.ReadMsgUnix(tag, oob)
		if n == 0 && oobn == 0 {
			if err == nil || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		files := passedFiles(oob[:oobn])
		// The descriptors are ours now; the parent may close its copies.
		_, _ = control.Write(tag[:1])
		for _, f := range files {
			c := fileConn(f)
			switch {
			case n == 1 && tag[0] == TagAPI:
				go api.deliver(c)
			case n == 1 && tag[0] == TagProxy:
				go proxy.deliver(c)
			case n == 1 && tag[0] == TagProxyAs:
				go func() {
					if b, err := bind(c); err == nil {
						proxy.deliver(b)
					} else {
						_ = c.Close()
					}
				}()
			default:
				_ = c.Close()
			}
		}
	}
}

// boundConn is a TagProxyAs connection past its identity line.
type boundConn struct {
	net.Conn
	r            *bufio.Reader
	token, vault string
}

func (c *boundConn) Read(p []byte) (int, error)           { return c.r.Read(p) }
func (c *boundConn) ProxyIdentity() (token, vault string) { return c.token, c.vault }

// bind reads c's identity line ("<token> <vault>", both non-empty), keeping
// whatever followed it for the reader.
func bind(c net.Conn) (*boundConn, error) {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReaderSize(c, maxPreamble)
	line, err := r.ReadSlice('\n')
	if err != nil {
		return nil, err
	}
	_ = c.SetReadDeadline(time.Time{})
	fields := strings.Split(strings.TrimSuffix(string(line), "\n"), " ")
	if len(fields) != 2 || fields[0] == "" || fields[1] == "" {
		return nil, errors.New("connpass: bad identity line")
	}
	return &boundConn{Conn: c, r: r, token: fields[0], vault: fields[1]}, nil
}

func passedFiles(oob []byte) []*os.File {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	var files []*os.File
	for _, m := range msgs {
		fds, err := syscall.ParseUnixRights(&m)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			syscall.CloseOnExec(fd)
			files = append(files, os.NewFile(uintptr(fd), "passed"))
		}
	}
	return files
}

// fileConn turns a passed descriptor into a net.Conn. net.FileConn knows
// TCP and Unix sockets; anything else (a vsock socket, a pipe) is served
// through the file itself.
func fileConn(f *os.File) net.Conn {
	if c, err := net.FileConn(f); err == nil {
		_ = f.Close()
		return c
	}
	return &osConn{File: f}
}

type osConn struct{ *os.File }

func (c *osConn) LocalAddr() net.Addr  { return addr("passed") }
func (c *osConn) RemoteAddr() net.Addr { return addr("passed") }

func (c *osConn) SetDeadline(t time.Time) error      { return c.File.SetDeadline(t) }
func (c *osConn) SetReadDeadline(t time.Time) error  { return c.File.SetReadDeadline(t) }
func (c *osConn) SetWriteDeadline(t time.Time) error { return c.File.SetWriteDeadline(t) }
