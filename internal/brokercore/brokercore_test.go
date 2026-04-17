package brokercore

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestIsHopByHop(t *testing.T) {
	cases := map[string]bool{
		"Proxy-Authorization": true,
		"proxy-authorization": true,
		"Connection":          true,
		"Upgrade":             true,
		"Content-Type":        false,
		"Authorization":       false,
	}
	for name, want := range cases {
		if got := IsHopByHop(name); got != want {
			t.Errorf("IsHopByHop(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestPassthroughHeadersExcludesAuthorization(t *testing.T) {
	for _, h := range PassthroughHeaders {
		if strings.EqualFold(h, "Authorization") {
			t.Fatalf("PassthroughHeaders must not include Authorization; clients must not be able to shadow injected credentials")
		}
		if strings.EqualFold(h, "Proxy-Authorization") {
			t.Fatalf("PassthroughHeaders must not include Proxy-Authorization")
		}
	}
}

func TestIsBrokerScopedRequestHeader(t *testing.T) {
	cases := map[string]bool{
		"X-Vault":             true,
		"x-vault":             true,
		"Proxy-Authorization": true,
		"proxy-authorization": true,
		"Authorization":       false,
		"Cookie":              false,
		"Content-Type":        false,
		"X-Request-Id":        false,
	}
	for name, want := range cases {
		if got := IsBrokerScopedRequestHeader(name); got != want {
			t.Errorf("IsBrokerScopedRequestHeader(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestCopyPassthroughRequestHeaders_ForwardsClientCredentials(t *testing.T) {
	src := http.Header{}
	src.Set("Authorization", "Bearer client-token")
	src.Set("Cookie", "session=abc")
	src.Set("X-Trace-Id", "trace-123")
	src.Set("Content-Type", "application/json")
	src.Set("User-Agent", "client/1.0")

	dst := http.Header{}
	CopyPassthroughRequestHeaders(src, dst)

	for _, h := range []string{"Authorization", "Cookie", "X-Trace-Id", "Content-Type", "User-Agent"} {
		if dst.Get(h) != src.Get(h) {
			t.Errorf("header %q: got %q, want %q", h, dst.Get(h), src.Get(h))
		}
	}
}

func TestCopyPassthroughRequestHeaders_StripsBrokerScoped(t *testing.T) {
	src := http.Header{}
	src.Set("Authorization", "Bearer client-token")
	src.Set("X-Vault", "default")
	src.Set("Proxy-Authorization", "Basic xxx")
	src.Set("Connection", "keep-alive")
	src.Set("Te", "trailers")

	dst := http.Header{}
	CopyPassthroughRequestHeaders(src, dst)

	if dst.Get("Authorization") == "" {
		t.Error("Authorization should be forwarded on passthrough")
	}
	for _, h := range []string{"X-Vault", "Proxy-Authorization", "Connection", "Te"} {
		if dst.Get(h) != "" {
			t.Errorf("header %q should have been stripped, got %q", h, dst.Get(h))
		}
	}
}

func TestCopyPassthroughRequestHeaders_PreservesMultipleValues(t *testing.T) {
	src := http.Header{}
	src.Add("X-Multi", "a")
	src.Add("X-Multi", "b")
	src.Add("X-Multi", "c")

	dst := http.Header{}
	CopyPassthroughRequestHeaders(src, dst)

	got := dst.Values("X-Multi")
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("X-Multi values = %v, want [a b c]", got)
	}
}

func TestCopyPassthroughRequestHeaders_ExtraStrip(t *testing.T) {
	// Explicit /proxy ingress passes "Authorization" as extra strip so the
	// Agent Vault session token never leaks upstream.
	src := http.Header{}
	src.Set("Authorization", "Bearer session-token")
	src.Set("Cookie", "session=abc")
	src.Set("X-Trace-Id", "trace-123")

	dst := http.Header{}
	CopyPassthroughRequestHeaders(src, dst, "Authorization")

	if got := dst.Get("Authorization"); got != "" {
		t.Errorf("Authorization should be stripped when listed in extraStrip, got %q", got)
	}
	if dst.Get("Cookie") != "session=abc" {
		t.Error("Cookie should still pass through")
	}
	if dst.Get("X-Trace-Id") != "trace-123" {
		t.Error("X-Trace-Id should still pass through")
	}
}

func TestForbiddenHintBody(t *testing.T) {
	body := ForbiddenHintBody("api.example.com", "default")
	if body["error"] != "forbidden" {
		t.Fatalf("error = %v", body["error"])
	}
	msg, ok := body["message"].(string)
	if !ok || !strings.Contains(msg, `"api.example.com"`) || !strings.Contains(msg, `"default"`) {
		t.Fatalf("message = %v", body["message"])
	}
	hint, ok := body["proposal_hint"].(map[string]interface{})
	if !ok {
		t.Fatalf("proposal_hint type = %T", body["proposal_hint"])
	}
	if hint["host"] != "api.example.com" {
		t.Fatalf("hint host = %v", hint["host"])
	}
	if hint["endpoint"] != "POST /v1/proposals" {
		t.Fatalf("hint endpoint = %v", hint["endpoint"])
	}

	// Must be JSON-serializable (used by both ingresses as response body).
	if _, err := json.Marshal(body); err != nil {
		t.Fatalf("marshal: %v", err)
	}
}
