package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

func isWebSocketUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, header := range r.Header.Values("Connection") {
		for _, token := range strings.Split(header, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

func copyWebSocketHandshakeHeaders(src, dst http.Header) {
	for _, name := range websocketHandshakeHeaderNames {
		for _, value := range src.Values(name) {
			dst.Add(name, value)
		}
	}
}

var websocketHandshakeHeaderNames = []string{
	"Connection",
	"Origin",
	"Sec-Websocket-Extensions",
	"Sec-Websocket-Key",
	"Sec-Websocket-Protocol",
	"Sec-Websocket-Version",
	"Upgrade",
}

func (p *Proxy) forwardWebSocket(
	w http.ResponseWriter,
	r *http.Request,
	outReq *http.Request,
	emit func(status int, errCode string),
) {
	upstreamConn, upstreamReader, resp, err := p.dialWebSocketUpstream(r.Context(), outReq)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		emit(http.StatusBadGateway, "upstream_error")
		return
	}
	defer func() {
		if resp == nil || resp.StatusCode != http.StatusSwitchingProtocols {
			_ = upstreamConn.Close()
		}
	}()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer func() { _ = resp.Body.Close() }()
		copyResponseHeaders(resp.Header, w.Header(), true)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, brokercore.MaxResponseBytes))
		emit(resp.StatusCode, "")
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstreamConn.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		emit(http.StatusInternalServerError, "internal")
		return
	}

	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		_ = upstreamConn.Close()
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		emit(http.StatusInternalServerError, "internal")
		return
	}

	_ = clientConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := writeWebSocketSwitchingResponse(clientConn, resp); err != nil {
		_ = clientConn.Close()
		_ = upstreamConn.Close()
		emit(http.StatusBadGateway, "upstream_error")
		return
	}
	_ = clientConn.SetWriteDeadline(time.Time{})
	emit(http.StatusSwitchingProtocols, "")

	pipeWebSocket(clientConn, clientBuf.Reader, upstreamConn, upstreamReader)
}

// Without an idle deadline, a stalled or abandoned WebSocket would pin a
// goroutine pair and a TLS connection indefinitely. Real-time APIs and
// keepalive pings comfortably fit inside this window.
const wsIdleTimeout = 10 * time.Minute

func (p *Proxy) dialWebSocketUpstream(
	ctx context.Context,
	outReq *http.Request,
) (net.Conn, *bufio.Reader, *http.Response, error) {
	dialCtx := p.upstream.DialContext
	if dialCtx == nil {
		dialer := &net.Dialer{}
		dialCtx = dialer.DialContext
	}

	rawConn, err := dialCtx(ctx, "tcp", outReq.URL.Host)
	if err != nil {
		return nil, nil, nil, err
	}

	// Plain-HTTP upstream (ws://): skip TLS, deadlines apply directly to
	// rawConn. pipeWebSocket/copyWithIdleTimeout downstream use only
	// net.Conn methods, so a *net.TCPConn substitutes for *tls.Conn.
	if outReq.URL.Scheme == "http" {
		headerTimeout := p.responseHeaderTimeout()
		_ = rawConn.SetDeadline(time.Now().Add(headerTimeout))
		if err := outReq.Write(rawConn); err != nil {
			_ = rawConn.Close()
			return nil, nil, nil, err
		}
		reader := bufio.NewReader(rawConn)
		resp, err := http.ReadResponse(reader, outReq)
		if err != nil {
			_ = rawConn.Close()
			return nil, nil, nil, err
		}
		_ = rawConn.SetDeadline(time.Time{})
		return rawConn, reader, resp, nil
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if p.upstream.TLSClientConfig != nil {
		tlsConfig = p.upstream.TLSClientConfig.Clone()
	}
	if tlsConfig.ServerName == "" {
		if host, _, err := net.SplitHostPort(outReq.URL.Host); err == nil {
			tlsConfig.ServerName = host
		} else {
			tlsConfig.ServerName = outReq.URL.Hostname()
		}
	}
	// WebSocket requires HTTP/1.1; pin ALPN so the server can't pick h2.
	tlsConfig.NextProtos = []string{"http/1.1"}

	tlsConn := tls.Client(rawConn, tlsConfig)
	_ = tlsConn.SetDeadline(time.Now().Add(p.tlsHandshakeTimeout()))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, nil, nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})

	headerTimeout := p.responseHeaderTimeout()
	_ = tlsConn.SetDeadline(time.Now().Add(headerTimeout))
	if err := outReq.Write(tlsConn); err != nil {
		_ = tlsConn.Close()
		return nil, nil, nil, err
	}

	reader := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(reader, outReq)
	if err != nil {
		_ = tlsConn.Close()
		return nil, nil, nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})

	return tlsConn, reader, resp, nil
}

func (p *Proxy) tlsHandshakeTimeout() time.Duration {
	if p.upstream.TLSHandshakeTimeout > 0 {
		return p.upstream.TLSHandshakeTimeout
	}
	return 10 * time.Second
}

func (p *Proxy) responseHeaderTimeout() time.Duration {
	if p.upstream.ResponseHeaderTimeout > 0 {
		return p.upstream.ResponseHeaderTimeout
	}
	return 30 * time.Second
}

func writeWebSocketSwitchingResponse(w io.Writer, resp *http.Response) error {
	proto := resp.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	status := resp.Status
	if status == "" {
		status = fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	if _, err := fmt.Fprintf(w, "%s %s\r\n", proto, status); err != nil {
		return err
	}

	header := make(http.Header)
	for k, vv := range resp.Header {
		if !isSafeWebSocketSwitchHeader(k) {
			continue
		}
		for _, v := range vv {
			header.Add(k, v)
		}
	}
	header.Set("Connection", "Upgrade")
	header.Set("Upgrade", "websocket")

	for k, vv := range header {
		name := textproto.CanonicalMIMEHeaderKey(k)
		for _, v := range vv {
			if _, err := fmt.Fprintf(w, "%s: %s\r\n", name, v); err != nil {
				return err
			}
		}
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

func isSafeWebSocketSwitchHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Connection",
		"Upgrade",
		"Sec-Websocket-Accept",
		"Sec-Websocket-Extensions",
		"Sec-Websocket-Protocol":
		return true
	default:
		return !brokercore.ShouldStripResponseHeader(name) && !strings.HasPrefix(http.CanonicalHeaderKey(name), "Sec-")
	}
}

func pipeWebSocket(clientConn net.Conn, clientReader *bufio.Reader, upstreamConn net.Conn, upstreamReader *bufio.Reader) {
	done := make(chan struct{}, 2)
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = clientConn.Close()
			_ = upstreamConn.Close()
		})
	}
	go func() {
		defer func() {
			done <- struct{}{}
			closeBoth()
		}()
		copyWithIdleTimeout(upstreamConn, io.MultiReader(clientReader, clientConn), clientConn, wsIdleTimeout)
	}()
	go func() {
		defer func() {
			done <- struct{}{}
			closeBoth()
		}()
		copyWithIdleTimeout(clientConn, io.MultiReader(upstreamReader, upstreamConn), upstreamConn, wsIdleTimeout)
	}()

	<-done
	<-done
}

// copyWithIdleTimeout streams src→dst, refreshing srcConn's read deadline
// on each iteration so a silent connection trips the deadline rather than
// blocking forever. srcConn must be the underlying net.Conn that src
// reads from (directly or via a bufio.Reader); the deadline only applies
// to actual socket reads, not to bytes already buffered.
func copyWithIdleTimeout(dst io.Writer, src io.Reader, srcConn net.Conn, idle time.Duration) {
	buf := make([]byte, 32*1024)
	for {
		_ = srcConn.SetReadDeadline(time.Now().Add(idle))
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
