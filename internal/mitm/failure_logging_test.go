package mitm

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

type failureLogBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *failureLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}

func (b *failureLogBuffer) snapshot() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.String()
}

func TestMITMUpstreamFailureLoggedAtInfoWithoutSecrets(t *testing.T) {
	for _, websocket := range []bool{false, true} {
		name := "https"
		if websocket {
			name = "websocket"
		}
		t.Run(name, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("untrusted upstream must not receive a request")
			}))
			defer upstream.Close()
			authority := strings.TrimPrefix(upstream.URL, "https://")
			host, _, err := net.SplitHostPort(authority)
			if err != nil {
				t.Fatal(err)
			}
			const token = "agent-token-sentinel"
			const credential = "credential-value-sentinel"
			const pathSecret = "path-secret-sentinel"
			const querySecret = "query-secret-sentinel"
			var logs failureLogBuffer
			sr := validTokenResolver(token, &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
			cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
				host: {result: &brokercore.InjectResult{MatchedName: "test-service", Headers: map[string]string{"Authorization": "Bearer " + credential}}},
			}}
			proxyURL, roots, _ := setupProxy(t, sr, cp, func(opts *Options) {
				opts.Logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
			})
			client := newTrustingClient(proxyURL, url.User(token), roots)
			defer client.CloseIdleConnections()
			req, err := http.NewRequest("GET", upstream.URL+"/"+pathSecret+"?token="+querySecret, nil)
			if err != nil {
				t.Fatal(err)
			}
			if websocket {
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Upgrade", "websocket")
				req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
				req.Header.Set("Sec-WebSocket-Version", "13")
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusBadGateway || string(body) != "bad gateway\n" {
				t.Fatalf("response = %d %q, want 502 bad gateway", resp.StatusCode, body)
			}
			logged := logs.snapshot()
			for _, secret := range []string{token, credential, pathSecret, querySecret} {
				if strings.Contains(logged, secret) {
					t.Fatal("diagnostic log leaked request secrets")
				}
			}
			found := false
			decoder := json.NewDecoder(strings.NewReader(logged))
			for decoder.More() {
				var entry map[string]any
				if err := decoder.Decode(&entry); err != nil {
					t.Fatal(err)
				}
				cause, _ := entry["error"].(string)
				if entry["level"] == "WARN" && entry["target_host"] == authority && strings.Contains(cause, "x509:") {
					if entry["vault_id"] != "v1" || entry["service"] != "test-service" || entry["method"] != "GET" || entry["route"] != "direct" {
						t.Fatalf("missing diagnostic context: %v", entry)
					}
					found = true
				}
			}
			if !found {
				t.Fatalf("502 has no visible TLS failure cause at info level: %s", logged)
			}
		})
	}
}
