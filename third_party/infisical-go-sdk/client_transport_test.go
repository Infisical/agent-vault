package infisical

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestConfiguredTransportRoutesLoginAndRefresh(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")
	var mu sync.Mutex
	var paths []string
	var proxyHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/universal-auth/login":
			_, _ = io.WriteString(w, `{"accessToken":"test-token-1","expiresIn":3600,"accessTokenMaxTTL":86400,"tokenType":"Bearer"}`)
		case "/api/v1/auth/token/renew":
			_, _ = io.WriteString(w, `{"accessToken":"test-token-2","expiresIn":3600,"accessTokenMaxTTL":86400,"tokenType":"Bearer"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		proxyHits++
		mu.Unlock()
		httputil.NewSingleHostReverseProxy(originURL).ServeHTTP(w, r)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	t.Cleanup(transport.CloseIdleConnections)

	c := NewInfisicalClient(context.Background(), Config{
		SiteUrl:          origin.URL,
		AutoTokenRefresh: BoolPtr(false),
		Transport:        transport,
		SilentMode:       true,
	}).(*InfisicalClient)
	if _, err := c.Auth().UniversalAuthLogin("fixture-client", "fixture-secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	c.mu.Lock()
	c.lastFetchedTime = time.Now().Add(-time.Hour)
	c.mu.Unlock()
	if err := c.refreshTokenSynchronously(true); err != nil {
		t.Fatalf("token refresh: %v", err)
	}
	if got := c.Auth().GetAccessToken(); got != "test-token-2" {
		t.Fatalf("refreshed access token = %q", got)
	}
	c.mu.Lock()
	c.firstFetchedTime = time.Now().Add(-25 * time.Hour)
	c.lastFetchedTime = time.Now().Add(-time.Hour)
	c.mu.Unlock()
	if err := c.refreshTokenSynchronously(true); err != nil {
		t.Fatalf("re-authentication: %v", err)
	}
	if got := c.Auth().GetAccessToken(); got != "test-token-1" {
		t.Fatalf("re-authenticated access token = %q", got)
	}

	mu.Lock()
	gotPaths := append([]string(nil), paths...)
	mu.Unlock()
	wantPaths := []string{
		"POST /api/v1/auth/universal-auth/login",
		"POST /api/v1/auth/token/renew",
		"POST /api/v1/auth/universal-auth/login",
	}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("SDK auth requests did not use configured proxy: got %#v, want %#v", gotPaths, wantPaths)
	}

	// The injected transport is carried in Resty's HTTP client, not just the
	// first request's config; changing it and clearing it must also be honored.
	secondTransport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	c.UpdateConfiguration(Config{SiteUrl: origin.URL, AutoTokenRefresh: BoolPtr(false), Transport: secondTransport, SilentMode: true})
	if got := c.httpClient.GetClient().Transport; got != secondTransport {
		t.Fatalf("updated Resty transport = %T, want second injected transport", got)
	}
	if _, err := c.Auth().UniversalAuthLogin("fixture-client", "fixture-secret"); err != nil {
		t.Fatalf("login through replacement transport: %v", err)
	}
	mu.Lock()
	gotProxyHits := proxyHits
	mu.Unlock()
	if gotProxyHits != 4 {
		t.Fatalf("replacement transport proxy requests = %d, want 4", gotProxyHits)
	}
	c.UpdateConfiguration(Config{SiteUrl: origin.URL, AutoTokenRefresh: BoolPtr(false), SilentMode: true})
	if got := c.httpClient.GetClient().Transport; got != c.defaultTransport {
		t.Fatal("nil transport did not restore the original Resty transport")
	}
	if _, err := c.Auth().UniversalAuthLogin("fixture-client", "fixture-secret"); err != nil {
		t.Fatalf("login after resetting transport: %v", err)
	}
	mu.Lock()
	gotProxyHits = proxyHits
	mu.Unlock()
	if gotProxyHits != 4 {
		t.Fatalf("nil transport retained proxy: proxy requests = %d, want 4", gotProxyHits)
	}
	secondTransport.CloseIdleConnections()
}
