package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
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

	if err := resp.Write(clientConn); err != nil {
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

	return tlsConn, reader, resp, nil
}

func (p *Proxy) tlsHandshakeTimeout() time.Duration {
	if p.upstream.TLSHandshakeTimeout > 0 {
		return p.upstream.TLSHandshakeTimeout
	}
	return 10 * time.Second
}

func pipeWebSocket(clientConn net.Conn, clientReader *bufio.Reader, upstreamConn net.Conn, upstreamReader *bufio.Reader) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstreamConn, io.MultiReader(clientReader, clientConn))
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, io.MultiReader(upstreamReader, upstreamConn))
		done <- struct{}{}
	}()

	go func() {
		<-done
		_ = clientConn.Close()
		_ = upstreamConn.Close()
	}()
}
