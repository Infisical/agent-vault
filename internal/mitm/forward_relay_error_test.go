package mitm

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// When the upstream dies mid-body, the relay must surface it: the client
// receives the bytes streamed so far and then a failed read (not a clean,
// silently truncated body), and the request log carries a non-empty
// error_code (#362 follow-up).
func TestMITMForwardUpstreamBodyFailureIsSurfaced(t *testing.T) {
	const partial = "partial-body"
	chunked := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\nc\r\n" + partial + "\r\n"
	cases := []struct {
		name     string
		raw      string // written verbatim before the upstream drops the connection
		maxBytes int64  // proxy response cap; 0 = unlimited
	}{
		{
			name: "content-length",
			raw:  "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100\r\n\r\n" + partial,
		},
		{name: "chunked", raw: chunked},
		// The upstream dies exactly at the cap: the capped copy stops before
		// the error, so the post-cap probe must catch it.
		{name: "chunked at response cap", raw: chunked, maxBytes: int64(len(partial))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				conn, buf, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				_, _ = buf.WriteString(tc.raw)
				_ = buf.Flush()
				_ = conn.Close()
			}))
			defer upstream.Close()
			host, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))

			sr := validTokenResolver("av_sess_ok",
				&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
			cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
				host: {result: &brokercore.InjectResult{
					MatchedName: "api",
					Headers:     map[string]string{"Authorization": "Bearer token"},
				}},
			}}
			sink := &recordingSink{}
			proxyURL, clientRoots, _ := setupProxy(t, sr, cp, func(o *Options) {
				o.LogSink = sink
				o.MaxResponseBytes = tc.maxBytes
			})
			client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)

			resp, err := client.Get(upstream.URL + "/stream")
			if err != nil {
				t.Fatalf("client.Get: %v (want a response, then a failing body read)", err)
			}
			got, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(got) != partial {
				t.Fatalf("client received %q before the failure, want %q", got, partial)
			}
			if err == nil {
				t.Fatal("client read the truncated body without error; truncation must be visible")
			}

			rows := sink.waitForRows(t, 1)
			if rows[0].ErrorCode != "upstream_body_error" {
				t.Fatalf("error_code = %q, want upstream_body_error", rows[0].ErrorCode)
			}
		})
	}
}
