package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

func TestStripMethodOverrideParam(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"no override", "a=1&b=2", "a=1&b=2"},
		{"only override", "_method=DELETE", ""},
		{"override first", "_method=DELETE&a=1", "a=1"},
		{"override middle", "a=1&_method=DELETE&b=2", "a=1&b=2"},
		{"override last", "a=1&_method=DELETE", "a=1"},
		{"override without value", "a=1&_method", "a=1"},
		{"similar keys untouched", "x_method=1&_methodx=2&a=_method", "x_method=1&_methodx=2&a=_method"},
		{"encoding preserved", "sig=a%2Fb%3D&_method=PUT", "sig=a%2Fb%3D"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripMethodOverrideParam(tc.in); got != tc.want {
				t.Fatalf("stripMethodOverrideParam(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestMITMStripsMethodOverrideOnRestrictedService drives a request with a
// method-override header and a _method query param through the proxy
// twice: against a method-restricted service (both must be stripped
// before the upstream sees them) and against an unrestricted one (both
// must pass through untouched).
func TestMITMStripsMethodOverrideOnRestrictedService(t *testing.T) {
	for _, restricted := range []bool{true, false} {
		name := "restricted"
		if !restricted {
			name = "unrestricted"
		}
		t.Run(name, func(t *testing.T) {
			var sawOverride, sawQuery string
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sawOverride = r.Header.Get("X-Http-Method-Override")
				sawQuery = r.URL.RawQuery
			}))
			defer upstream.Close()

			upstreamAuthority := strings.TrimPrefix(upstream.URL, "https://")
			upstreamHost, _, _ := net.SplitHostPort(upstreamAuthority)

			sr := validTokenResolver("av_sess_ok",
				&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
			cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
				upstreamHost: {result: &brokercore.InjectResult{
					Headers:          map[string]string{"Authorization": "Bearer injected"},
					MethodRestricted: restricted,
				}},
			}}

			proxyURL, clientRoots, p := setupProxy(t, sr, cp)

			upstreamRoots := x509.NewCertPool()
			upstreamRoots.AddCert(upstream.Certificate())
			p.upstream.TLSClientConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    upstreamRoots,
			}

			client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)

			req, err := http.NewRequest("GET", upstream.URL+"/ping?_method=DELETE&keep=1", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("X-HTTP-Method-Override", "DELETE")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("client.Do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}

			if restricted {
				if sawOverride != "" {
					t.Fatalf("upstream saw X-Http-Method-Override %q, want stripped", sawOverride)
				}
				if sawQuery != "keep=1" {
					t.Fatalf("upstream saw query %q, want _method stripped and keep=1 preserved", sawQuery)
				}
			} else {
				if sawOverride != "DELETE" {
					t.Fatalf("upstream saw X-Http-Method-Override %q, want passthrough", sawOverride)
				}
				if sawQuery != "_method=DELETE&keep=1" {
					t.Fatalf("upstream saw query %q, want untouched", sawQuery)
				}
			}
		})
	}
}
