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
		"Proxy-Connection":    true,
		"proxy-connection":    true,
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

func TestApplyInjection_StripsHopByHop(t *testing.T) {
	src := http.Header{}
	src.Set("Connection", "keep-alive")
	src.Set("Keep-Alive", "timeout=5")
	src.Set("Proxy-Connection", "keep-alive")
	src.Set("Te", "trailers")
	src.Set("Trailer", "Expires")
	src.Set("Transfer-Encoding", "chunked")
	src.Set("Upgrade", "h2c")
	src.Set("Content-Type", "application/json")

	dst := http.Header{}
	ApplyInjection(src, dst, &InjectResult{})

	for _, h := range []string{"Connection", "Keep-Alive", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		if dst.Get(h) != "" {
			t.Errorf("hop-by-hop header %q should have been stripped, got %q", h, dst.Get(h))
		}
	}
	if dst.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type should pass through, got %q", dst.Get("Content-Type"))
	}
}

func TestApplyInjection_StripsBrokerScoped(t *testing.T) {
	src := http.Header{}
	src.Set("X-Vault", "default")
	src.Set("Proxy-Authorization", "Basic xxx")
	src.Set("X-Trace-Id", "trace-123")

	dst := http.Header{}
	ApplyInjection(src, dst, &InjectResult{})

	if dst.Get("X-Vault") != "" {
		t.Errorf("X-Vault must never reach upstream, got %q", dst.Get("X-Vault"))
	}
	if dst.Get("Proxy-Authorization") != "" {
		t.Errorf("Proxy-Authorization must never reach upstream, got %q", dst.Get("Proxy-Authorization"))
	}
	if dst.Get("X-Trace-Id") != "trace-123" {
		t.Errorf("X-Trace-Id should pass through, got %q", dst.Get("X-Trace-Id"))
	}
}

func TestApplyInjection_StripsExtraStrip(t *testing.T) {
	// extraStrip lets an ingress drop the header that carries its
	// session token so it never reaches the upstream.
	src := http.Header{}
	src.Set("Authorization", "Bearer session-token")
	src.Set("X-Trace-Id", "trace-123")

	dst := http.Header{}
	ApplyInjection(src, dst, &InjectResult{Headers: map[string]string{"X-Api-Key": "real"}}, "Authorization")

	if dst.Get("Authorization") != "" {
		t.Errorf("Authorization should be stripped via extraStrip, got %q", dst.Get("Authorization"))
	}
	if dst.Get("X-Api-Key") != "real" {
		t.Errorf("injected X-Api-Key not set, got %q", dst.Get("X-Api-Key"))
	}
	if dst.Get("X-Trace-Id") != "trace-123" {
		t.Errorf("X-Trace-Id should pass through, got %q", dst.Get("X-Trace-Id"))
	}
}

func TestApplyInjection_PassthroughForwardsArbitraryHeaders(t *testing.T) {
	// Passthrough auth: inject.Headers is nil, no extraStrip — client
	// headers (including Authorization, Cookie) flow through unchanged
	// modulo hop-by-hop and broker-scoped.
	src := http.Header{}
	src.Set("Authorization", "Bearer client-token")
	src.Set("Cookie", "session=abc")
	src.Set("X-Trace-Id", "trace-123")
	src.Set("Anthropic-Version", "2023-06-01")

	dst := http.Header{}
	ApplyInjection(src, dst, &InjectResult{})

	for _, h := range []string{"Authorization", "Cookie", "X-Trace-Id", "Anthropic-Version"} {
		if dst.Get(h) != src.Get(h) {
			t.Errorf("header %q: got %q, want %q", h, dst.Get(h), src.Get(h))
		}
	}
}

func TestApplyInjection_BearerForwardsAnthropicVersion(t *testing.T) {
	// Vendor headers must reach the upstream on credentialed auth.
	src := http.Header{}
	src.Set("Anthropic-Version", "2023-06-01")
	src.Set("Anthropic-Beta", "messages-2024-04-04")
	src.Set("Content-Type", "application/json")

	dst := http.Header{}
	ApplyInjection(src, dst, &InjectResult{
		Headers: map[string]string{"Authorization": "Bearer real"},
	})

	if dst.Get("Anthropic-Version") != "2023-06-01" {
		t.Errorf("Anthropic-Version should reach upstream, got %q", dst.Get("Anthropic-Version"))
	}
	if dst.Get("Anthropic-Beta") != "messages-2024-04-04" {
		t.Errorf("Anthropic-Beta should reach upstream, got %q", dst.Get("Anthropic-Beta"))
	}
	if dst.Get("Authorization") != "Bearer real" {
		t.Errorf("injected Authorization not set, got %q", dst.Get("Authorization"))
	}
}

func TestApplyInjection_InjectedWinsOverClient(t *testing.T) {
	src := http.Header{}
	src.Set("Authorization", "Bearer attacker")

	dst := http.Header{}
	ApplyInjection(src, dst, &InjectResult{
		Headers: map[string]string{"Authorization": "Bearer real"},
	})

	got := dst.Values("Authorization")
	if len(got) != 1 || got[0] != "Bearer real" {
		t.Fatalf("Authorization values = %v, want exactly [Bearer real]", got)
	}
}

func TestApplyInjection_InjectedWinsOverClient_NonCanonicalKey(t *testing.T) {
	// custom auth lets operators choose header names; a non-canonical
	// inject.Headers key must still shadow the canonicalized client copy.
	src := http.Header{}
	src.Set("Authorization", "Bearer attacker")

	dst := http.Header{}
	ApplyInjection(src, dst, &InjectResult{
		Headers: map[string]string{"authorization": "Bearer real"},
	})

	got := dst.Values("Authorization")
	if len(got) != 1 || got[0] != "Bearer real" {
		t.Fatalf("Authorization values = %v, want exactly [Bearer real]", got)
	}
}

func TestApplyInjection_ApiKeyStripsConfiguredHeader(t *testing.T) {
	// api-key with a custom auth.header — client-supplied value must
	// not shadow the injected one.
	src := http.Header{}
	src.Set("X-Api-Key", "client-supplied")
	src.Set("Anthropic-Version", "2023-06-01")

	dst := http.Header{}
	ApplyInjection(src, dst, &InjectResult{
		Headers: map[string]string{"X-Api-Key": "real"},
	})

	got := dst.Values("X-Api-Key")
	if len(got) != 1 || got[0] != "real" {
		t.Fatalf("X-Api-Key values = %v, want exactly [real]", got)
	}
	if dst.Get("Anthropic-Version") != "2023-06-01" {
		t.Errorf("Anthropic-Version should still pass through, got %q", dst.Get("Anthropic-Version"))
	}
}

func TestApplyInjection_CustomMultiHeaderAuthStripsAllConfigured(t *testing.T) {
	// custom auth with multiple managed headers — every key in
	// inject.Headers must be stripped from the client copy.
	src := http.Header{}
	src.Set("X-Foo", "client-foo")
	src.Set("X-Bar", "client-bar")
	src.Set("X-Other", "client-other")

	dst := http.Header{}
	ApplyInjection(src, dst, &InjectResult{
		Headers: map[string]string{"X-Foo": "real-foo", "X-Bar": "real-bar"},
	})

	if got := dst.Values("X-Foo"); len(got) != 1 || got[0] != "real-foo" {
		t.Errorf("X-Foo = %v, want [real-foo]", got)
	}
	if got := dst.Values("X-Bar"); len(got) != 1 || got[0] != "real-bar" {
		t.Errorf("X-Bar = %v, want [real-bar]", got)
	}
	if dst.Get("X-Other") != "client-other" {
		t.Errorf("X-Other should pass through, got %q", dst.Get("X-Other"))
	}
}

func TestApplyInjection_PreservesMultiValueClientHeaders(t *testing.T) {
	src := http.Header{}
	src.Add("Accept", "application/json")
	src.Add("Accept", "text/plain")
	src.Add("X-Multi", "a")
	src.Add("X-Multi", "b")

	dst := http.Header{}
	ApplyInjection(src, dst, &InjectResult{})

	if got := dst.Values("Accept"); len(got) != 2 || got[0] != "application/json" || got[1] != "text/plain" {
		t.Errorf("Accept values = %v", got)
	}
	if got := dst.Values("X-Multi"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("X-Multi values = %v", got)
	}
}

func TestForbiddenHintBody(t *testing.T) {
	body := ForbiddenHintBody("api.example.com", "default", "http://127.0.0.1:14321")
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

	// help field must contain actionable URLs.
	help, ok := body["help"].(string)
	if !ok {
		t.Fatal("expected help field in body")
	}
	if !strings.Contains(help, "http://127.0.0.1:14321/discover") {
		t.Fatalf("help missing discover URL: %s", help)
	}
	if !strings.Contains(help, "http://127.0.0.1:14321/v1/skills/http") {
		t.Fatalf("help missing skills URL: %s", help)
	}

	// Must be JSON-serializable (used by both ingresses as response body).
	if _, err := json.Marshal(body); err != nil {
		t.Fatalf("marshal: %v", err)
	}
}

func TestForbiddenHintBody_EmptyBaseURL(t *testing.T) {
	body := ForbiddenHintBody("api.example.com", "default", "")
	if _, ok := body["help"]; ok {
		t.Fatal("help field should be absent when baseURL is empty")
	}
}
