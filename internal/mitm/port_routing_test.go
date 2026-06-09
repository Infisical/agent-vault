package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// TestMITMPortBasedRouting verifies that two HTTPS services on the same
// host but different ports each receive their own credentials through
// the CONNECT tunnel path.
func TestMITMPortBasedRouting(t *testing.T) {
	var sawAuth1, sawAuth2 string

	upstream1 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth1 = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "svc1")
	}))
	defer upstream1.Close()

	upstream2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth2 = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "svc2")
	}))
	defer upstream2.Close()

	authority1 := strings.TrimPrefix(upstream1.URL, "https://")
	host1, port1, _ := net.SplitHostPort(authority1)
	authority2 := strings.TrimPrefix(upstream2.URL, "https://")
	_, port2, _ := net.SplitHostPort(authority2)

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{
		byHost: map[string]fakeInjectResult{},
		byHostPort: map[string]fakeInjectResult{
			net.JoinHostPort(host1, port1): {result: &brokercore.InjectResult{
				Headers: map[string]string{"Authorization": "Bearer cred-for-port-1"},
			}},
			net.JoinHostPort(host1, port2): {result: &brokercore.InjectResult{
				Headers: map[string]string{"Authorization": "Bearer cred-for-port-2"},
			}},
		},
	}

	proxyURL, clientRoots, p := setupProxy(t, sr, cp)

	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream1.Certificate())
	upstreamRoots.AddCert(upstream2.Certificate())
	p.upstream.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    upstreamRoots,
	}

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)

	resp1, err := client.Get(upstream1.URL + "/ping")
	if err != nil {
		t.Fatalf("GET upstream1: %v", err)
	}
	_ = resp1.Body.Close()
	if sawAuth1 != "Bearer cred-for-port-1" {
		t.Fatalf("upstream1 saw Authorization %q, want cred-for-port-1", sawAuth1)
	}

	resp2, err := client.Get(upstream2.URL + "/ping")
	if err != nil {
		t.Fatalf("GET upstream2: %v", err)
	}
	_ = resp2.Body.Close()
	if sawAuth2 != "Bearer cred-for-port-2" {
		t.Fatalf("upstream2 saw Authorization %q, want cred-for-port-2", sawAuth2)
	}
}

// TestMITMForwardPortExtraction verifies the plain HTTP forward-proxy path
// correctly extracts port from the URL and routes to port-specific services.
func TestMITMForwardPortExtraction(t *testing.T) {
	var sawAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	authority := strings.TrimPrefix(upstream.URL, "http://")
	host, port, _ := net.SplitHostPort(authority)

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{
		byHost: map[string]fakeInjectResult{},
		byHostPort: map[string]fakeInjectResult{
			net.JoinHostPort(host, port): {result: &brokercore.InjectResult{
				Headers: map[string]string{"Authorization": "Bearer http-port-cred"},
			}},
		},
	}

	proxyURL, _, _ := setupProxy(t, sr, cp)

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	req, _ := http.NewRequest("GET", upstream.URL+"/test", nil)
	req.Header.Set("Proxy-Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte("av_sess_ok:")))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if sawAuth != "Bearer http-port-cred" {
		t.Fatalf("upstream saw Authorization %q, want http-port-cred", sawAuth)
	}
}
