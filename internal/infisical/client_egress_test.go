package infisical

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestNewClientRoutesLoginAndAPIThroughTransport(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	var proxyHits int
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/universal-auth/login":
			_, _ = io.WriteString(w, `{"accessToken":"test-token-1","expiresIn":3600,"accessTokenMaxTTL":86400,"tokenType":"Bearer"}`)
		case "/api/v3/secrets/raw":
			_, _ = io.WriteString(w, `{"secrets":[{"secretKey":"TEST_KEY","secretValue":"test-value"}]}`)
		case "/api/v1/workspace/project-1":
			_, _ = io.WriteString(w, `{"workspace":{"slug":"test-project"}}`)
		case "/api/v1/dynamic-secrets":
			_, _ = io.WriteString(w, `{"dynamicSecrets":[{"id":"ds-1","name":"db"}]}`)
		case "/api/v1/dynamic-secrets/leases":
			_, _ = io.WriteString(w, `{"lease":{"id":"lease-1","expireAt":"2099-01-01T00:00:00Z"},"dynamicSecret":{"id":"ds-1","name":"db"},"data":{"username":"test-db-user","password":"test-db-pass"}}`)
		case "/api/v1/dynamic-secrets/leases/lease-1/renew", "/api/v1/dynamic-secrets/leases/lease-1":
			_, _ = io.WriteString(w, `{"lease":{"id":"lease-1","expireAt":"2099-01-02T00:00:00Z"}}`)
		default:
			http.Error(w, fmt.Sprintf("unexpected fixture path: %s", r.URL.Path), http.StatusNotFound)
		}
	})
	server := httptest.NewServer(origin)
	defer server.Close()
	originURL, err := url.Parse(server.URL)
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

	t.Setenv("INFISICAL_URL", server.URL)
	t.Setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "fixture-client")
	t.Setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET", "fixture-secret")

	client, err := NewClient(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), transport)
	if err != nil {
		t.Fatal(err)
	}
	cfg := VaultConfig{ProjectID: "project-1", Environment: "dev", SecretPath: "/"}
	secrets, err := client.FetchSecrets(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 1 || secrets[0] != (Secret{Key: "TEST_KEY", Value: "test-value"}) {
		t.Fatalf("unexpected secrets: %#v", secrets)
	}
	list, err := client.ListDynamicSecrets(context.Background(), cfg)
	if err != nil || !reflect.DeepEqual(list, []DynamicSecretInfo{{Name: "db"}}) {
		t.Fatalf("ListDynamicSecrets = %#v, %v", list, err)
	}
	lease, err := client.CreateLease(context.Background(), cfg, "db")
	if err != nil {
		t.Fatal(err)
	}
	if lease.LeaseID != "lease-1" || lease.Fields["username"] != "test-db-user" || lease.Fields["password"] != "test-db-pass" {
		t.Fatalf("unexpected lease: %#v", lease)
	}
	expires, err := client.RenewLease(context.Background(), cfg, "lease-1")
	if err != nil || !expires.Equal(time.Date(2099, time.January, 2, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("RenewLease = %v, %v", expires, err)
	}
	if err := client.RevokeLease(context.Background(), cfg, "lease-1"); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	gotPaths := append([]string(nil), paths...)
	mu.Unlock()
	wantPaths := []string{
		"POST /api/v1/auth/universal-auth/login",
		"GET /api/v3/secrets/raw",
		"GET /api/v1/workspace/project-1",
		"GET /api/v1/dynamic-secrets",
		"POST /api/v1/dynamic-secrets/leases",
		"POST /api/v1/dynamic-secrets/leases/lease-1/renew",
		"DELETE /api/v1/dynamic-secrets/leases/lease-1",
	}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("requests did not all reach fixture via configured transport:\n got: %#v\nwant: %#v", gotPaths, wantPaths)
	}
	mu.Lock()
	gotProxyHits := proxyHits
	mu.Unlock()
	if gotProxyHits != len(wantPaths) {
		t.Fatalf("configured transport proxy requests = %d, want %d", gotProxyHits, len(wantPaths))
	}
}
