package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

func responseRedactionRule(value string) []brokercore.ResolvedRedaction {
	return []brokercore.ResolvedRedaction{{
		Value:       value,
		Replacement: brokercore.DefaultRedactionReplacement,
		Source:      "credential",
	}}
}

type readTrackingBody struct {
	read bool
}

func (b *readTrackingBody) Read([]byte) (int, error) {
	b.read = true
	return 0, io.EOF
}

func (b *readTrackingBody) Close() error {
	return nil
}

func TestMITMDoesNotExposeInjectedCredentialEchoedInResponseBody(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"token":"injected-secret"}`)
	}))
	defer upstream.Close()

	upstreamAuthority := strings.TrimPrefix(upstream.URL, "https://")
	upstreamHost, _, _ := net.SplitHostPort(upstreamAuthority)

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{
			Headers:    map[string]string{"Authorization": "Bearer injected-secret"},
			Redactions: responseRedactionRule("injected-secret"),
		}},
	}}

	proxyURL, clientRoots, p := setupProxy(t, sr, cp)
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	p.upstream.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: upstreamRoots}

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	resp, err := client.Get(upstream.URL + "/echo")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "injected-secret") {
		t.Fatalf("response body exposed injected credential: %s", body)
	}
	if !strings.Contains(string(body), brokercore.DefaultRedactionReplacement) {
		t.Fatalf("response body was not redacted: %s", body)
	}
}

func TestMITMResponseRedactionDisabledDoesNotScanBody(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"token":"injected-secret"}`)
	}))
	defer upstream.Close()

	upstreamAuthority := strings.TrimPrefix(upstream.URL, "https://")
	upstreamHost, _, _ := net.SplitHostPort(upstreamAuthority)

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{
			Headers: map[string]string{"Authorization": "Bearer injected-secret"},
		}},
	}}

	proxyURL, clientRoots, p := setupProxy(t, sr, cp)
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	p.upstream.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: upstreamRoots}

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	resp, err := client.Get(upstream.URL + "/echo")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "injected-secret") {
		t.Fatalf("response body was unexpectedly redacted: %s", body)
	}
}

func TestMITMResponseRedactionFailsClosedForEncodedBody(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "br")
		_, _ = io.WriteString(w, `{"token":"injected-secret"}`)
	}))
	defer upstream.Close()

	upstreamAuthority := strings.TrimPrefix(upstream.URL, "https://")
	upstreamHost, _, _ := net.SplitHostPort(upstreamAuthority)

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{
			Headers:    map[string]string{"Authorization": "Bearer injected-secret"},
			Redactions: responseRedactionRule("injected-secret"),
		}},
	}}

	proxyURL, clientRoots, p := setupProxy(t, sr, cp)
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	p.upstream.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: upstreamRoots}

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	resp, err := client.Get(upstream.URL + "/echo")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, http.StatusBadGateway, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "injected-secret") {
		t.Fatalf("fail-closed response exposed secret: %s", body)
	}
}

func TestMITMResponseRedactionFailsClosedForOversizedBody(t *testing.T) {
	secret := "injected-secret"
	body := strings.Repeat("x", 128) + secret
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "143")
		_, _ = io.WriteString(w, body)
	}))
	defer upstream.Close()

	upstreamAuthority := strings.TrimPrefix(upstream.URL, "https://")
	upstreamHost, _, _ := net.SplitHostPort(upstreamAuthority)

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{
			Headers:    map[string]string{"Authorization": "Bearer " + secret},
			Redactions: responseRedactionRule(secret),
		}},
	}}

	proxyURL, clientRoots, p := setupProxy(t, sr, cp, func(o *Options) {
		o.MaxResponseBytes = 64
	})
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	p.upstream.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: upstreamRoots}

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	resp, err := client.Get(upstream.URL + "/echo")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, http.StatusBadGateway, body)
	}
	respBody, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(respBody), secret) {
		t.Fatalf("fail-closed response exposed secret: %s", respBody)
	}
}

func TestApplyResponseRedactionsSkipsLargeBinaryBodyBeforeRead(t *testing.T) {
	body := &readTrackingBody{}
	resp := &http.Response{
		Body:          body,
		ContentLength: brokercore.MaxMaterializeBytes + 1,
		Header:        make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/octet-stream")

	p := &Proxy{}
	modified, err := p.applyResponseRedactions(resp, responseRedactionRule("secret"))
	if err != nil {
		t.Fatalf("applyResponseRedactions: %v", err)
	}
	if modified {
		t.Fatal("binary response was unexpectedly modified")
	}
	if body.read {
		t.Fatal("binary response body was read before content-type skip")
	}
}
