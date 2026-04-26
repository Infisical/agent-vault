package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

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
		for k, vv := range resp.Header {
			if brokercore.ShouldStripResponseHeader(k) {
				continue
			}
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
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

	if err := writeWebSocketSwitchingResponse(clientConn, resp); err != nil {
		_ = clientConn.Close()
		_ = upstreamConn.Close()
		emit(http.StatusBadGateway, "upstream_error")
		return
	}
	emit(http.StatusSwitchingProtocols, "")

	pipeWebSocket(clientConn, clientBuf.Reader, upstreamConn, upstreamReader)
}

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
	out := &http.Response{
		Status:        resp.Status,
		StatusCode:    resp.StatusCode,
		Proto:         resp.Proto,
		ProtoMajor:    resp.ProtoMajor,
		ProtoMinor:    resp.ProtoMinor,
		Header:        make(http.Header),
		ContentLength: -1,
	}
	for k, vv := range resp.Header {
		if !isSafeWebSocketSwitchHeader(k) {
			continue
		}
		for _, v := range vv {
			out.Header.Add(k, v)
		}
	}
	return out.Write(w)
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
		_, _ = io.Copy(upstreamConn, io.MultiReader(clientReader, clientConn))
	}()
	go func() {
		defer func() {
			done <- struct{}{}
			closeBoth()
		}()
		_, _ = io.Copy(clientConn, io.MultiReader(upstreamReader, upstreamConn))
	}()

	<-done
	<-done
}
