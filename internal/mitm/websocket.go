package mitm

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"math"
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
	wsSubs []brokercore.ResolvedSubstitution,
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

		if p.maxResponseBytes > 0 && resp.ContentLength > 0 && resp.ContentLength > p.maxResponseBytes {
			brokercore.WriteProxyError(w, http.StatusBadGateway, "response_too_large",
				fmt.Sprintf("Upstream response body (%d bytes) exceeds the proxy response-size limit (%d bytes).",
					resp.ContentLength, p.maxResponseBytes))
			emit(http.StatusBadGateway, "response_too_large")
			return
		}

		for k, vv := range resp.Header {
			if brokercore.ShouldStripResponseHeader(k) {
				continue
			}
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		var src io.Reader = resp.Body
		if p.maxResponseBytes > 0 {
			src = io.LimitReader(resp.Body, p.maxResponseBytes)
		}
		n, _ := io.Copy(w, src)

		if p.maxResponseBytes > 0 && n == p.maxResponseBytes {
			var probe [1]byte
			if extra, _ := resp.Body.Read(probe[:]); extra > 0 {
				p.logger.Warn("response body truncated mid-stream, aborting connection",
					slog.String("host", outReq.URL.Host),
					slog.String("path", outReq.URL.Path),
					slog.Int64("bytes_streamed", n),
					slog.Int64("max_response_bytes", p.maxResponseBytes),
				)
				emit(resp.StatusCode, "response_truncated")
				panic(http.ErrAbortHandler)
			}
		}

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

	pipeWebSocket(clientConn, clientBuf.Reader, upstreamConn, upstreamReader, wsSubs)
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

func pipeWebSocket(clientConn net.Conn, clientReader *bufio.Reader, upstreamConn net.Conn, upstreamReader *bufio.Reader, wsSubs []brokercore.ResolvedSubstitution) {
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
		src := io.MultiReader(clientReader, clientConn)
		if len(wsSubs) > 0 {
			copyWSFramesWithSubstitution(upstreamConn, src, clientConn, wsIdleTimeout, wsSubs)
		} else {
			copyWithIdleTimeout(upstreamConn, src, clientConn, wsIdleTimeout)
		}
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

// maxWSSubstitutionPayload caps the frame payload size we'll buffer for
// substitution. Frames larger than this are streamed through without
// substitution. Auth payloads are tiny; this prevents memory exhaustion.
const maxWSSubstitutionPayload = 1 << 20 // 1 MB

// WebSocket frame opcodes (RFC 6455 §11.8).
const (
	wsOpText  = 0x1
	wsOpBin   = 0x2
	wsOpClose = 0x8
	wsOpPing  = 0x9
	wsOpPong  = 0xA
)

func filterWebSocketSubs(subs []brokercore.ResolvedSubstitution) []brokercore.ResolvedSubstitution {
	var out []brokercore.ResolvedSubstitution
	for _, sub := range subs {
		for _, s := range sub.In {
			if s == "websocket" {
				out = append(out, sub)
				break
			}
		}
	}
	return out
}

// copyWSFramesWithSubstitution reads WebSocket frames from src, applies
// placeholder substitutions to unfragmented text frames, and writes them
// to dst. Non-text, compressed (RSV1), fragmented, and oversized frames
// are forwarded without modification.
func copyWSFramesWithSubstitution(dst io.Writer, src io.Reader, srcConn net.Conn, idle time.Duration, subs []brokercore.ResolvedSubstitution) {
	r := bufio.NewReaderSize(src, 32*1024)
	for {
		_ = srcConn.SetReadDeadline(time.Now().Add(idle))

		// --- Read frame header (2 bytes minimum) ---
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return
		}

		fin := hdr[0]&0x80 != 0
		rsv1 := hdr[0]&0x40 != 0
		opcode := hdr[0] & 0x0F
		masked := hdr[1]&0x80 != 0
		payloadLen := uint64(hdr[1] & 0x7F)

		// Extended payload length.
		var extHdr []byte
		switch payloadLen {
		case 126:
			extHdr = make([]byte, 2)
			if _, err := io.ReadFull(r, extHdr); err != nil {
				return
			}
			payloadLen = uint64(binary.BigEndian.Uint16(extHdr))
		case 127:
			extHdr = make([]byte, 8)
			if _, err := io.ReadFull(r, extHdr); err != nil {
				return
			}
			payloadLen = binary.BigEndian.Uint64(extHdr)
			// RFC 6455 §5.2: MSB must be 0. Reject to prevent int64 overflow
			// in io.CopyN which would desynchronize the frame parser.
			if payloadLen > math.MaxInt64 {
				return
			}
		}

		// Masking key (4 bytes if masked).
		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(r, maskKey[:]); err != nil {
				return
			}
		}

		// --- Decide: substitute or pass through ---
		canSubstitute := opcode == wsOpText && fin && !rsv1 && payloadLen <= maxWSSubstitutionPayload
		if !canSubstitute {
			if opcode == wsOpText && !fin {
				slog.Default().Warn("fragmented WebSocket text frame on connection with substitutions; passing through without substitution")
			}
			// Stream the frame through: write the already-read header bytes,
			// then copy the payload with io.CopyN.
			if _, err := dst.Write(hdr); err != nil {
				return
			}
			if len(extHdr) > 0 {
				if _, err := dst.Write(extHdr); err != nil {
					return
				}
			}
			if masked {
				if _, err := dst.Write(maskKey[:]); err != nil {
					return
				}
			}
			if payloadLen > 0 {
				if _, err := io.CopyN(dst, r, int64(payloadLen)); err != nil {
					return
				}
			}
			if opcode == wsOpClose {
				return
			}
			continue
		}

		// --- Read and unmask payload ---
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return
		}

		// Keep a copy of the raw frame for the no-change fast path.
		rawPayload := make([]byte, len(payload))
		copy(rawPayload, payload)
		rawHdr := hdr
		rawExtHdr := extHdr
		rawMaskKey := maskKey

		// Unmask.
		if masked {
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}

		// Apply substitutions to the unmasked text.
		text := string(payload)
		for _, sub := range subs {
			text = strings.ReplaceAll(text, sub.Placeholder, sub.Value)
		}

		// Fast path: nothing changed — write the original raw bytes.
		if text == string(payload) {
			if _, err := dst.Write(rawHdr); err != nil {
				return
			}
			if len(rawExtHdr) > 0 {
				if _, err := dst.Write(rawExtHdr); err != nil {
					return
				}
			}
			if masked {
				if _, err := dst.Write(rawMaskKey[:]); err != nil {
					return
				}
			}
			if _, err := dst.Write(rawPayload); err != nil {
				return
			}
			continue
		}

		// --- Rewrite frame with substituted payload ---
		modified := []byte(text)
		newLen := uint64(len(modified))

		// Generate a new masking key (RFC 6455 §5.3 requires unpredictable).
		var newMask [4]byte
		if masked {
			if _, err := rand.Read(newMask[:]); err != nil {
				return
			}
			for i := range modified {
				modified[i] ^= newMask[i%4]
			}
		}

		// Build frame header with correct length encoding.
		var frame []byte
		firstByte := hdr[0] // preserves FIN, RSV bits, opcode
		switch {
		case newLen <= 125:
			secondByte := byte(newLen)
			if masked {
				secondByte |= 0x80
			}
			frame = append(frame, firstByte, secondByte)
		case newLen <= 65535:
			secondByte := byte(126)
			if masked {
				secondByte |= 0x80
			}
			frame = append(frame, firstByte, secondByte)
			frame = binary.BigEndian.AppendUint16(frame, uint16(newLen))
		default:
			secondByte := byte(127)
			if masked {
				secondByte |= 0x80
			}
			frame = append(frame, firstByte, secondByte)
			frame = binary.BigEndian.AppendUint64(frame, newLen)
		}
		if masked {
			frame = append(frame, newMask[:]...)
		}
		frame = append(frame, modified...)

		if _, err := dst.Write(frame); err != nil {
			return
		}
	}
}
