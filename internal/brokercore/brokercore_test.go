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

// ─────────────────────────────────────────────────────────────────────────
// ApplyInjection: ExtraPassthroughHeaders for credentialed services
// ─────────────────────────────────────────────────────────────────────────

func TestApplyInjection_ForwardsExtraPassthroughHeaders(t *testing.T) {
	// A credentialed service that opts a non-standard request header into
	// the allowlist (Anthropic's mandatory anthropic-version) must see it
	// forwarded to the upstream, while injected Authorization still wins.
	src := http.Header{}
	src.Set("anthropic-version", "2023-06-01")
	src.Set("anthropic-beta", "tools-2024-04-04")
	src.Set("Content-Type", "application/json")
	src.Set("Authorization", "Bearer CLIENT_SHOULD_BE_IGNORED")

	dst := http.Header{}
	inject := &InjectResult{
		Headers:                 map[string]string{"x-api-key": "sk-injected"},
		ExtraPassthroughHeaders: []string{"anthropic-version", "anthropic-beta"},
	}
	ApplyInjection(src, dst, inject)

	if got := dst.Get("Anthropic-Version"); got != "2023-06-01" {
		t.Fatalf("anthropic-version not forwarded: got %q", got)
	}
	if got := dst.Get("Anthropic-Beta"); got != "tools-2024-04-04" {
		t.Fatalf("anthropic-beta not forwarded: got %q", got)
	}
	if got := dst.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type lost: got %q", got)
	}
	if got := dst.Get("x-api-key"); got != "sk-injected" {
		t.Fatalf("injected header missing: got %q", got)
	}
	// Client-supplied Authorization must not leak through \u2014 it wasn't on
	// the allowlist and the ExtraPassthroughHeaders denylist check at
	// config time ensures it could never be added.
	if got := dst.Get("Authorization"); got != "" {
		t.Fatalf("client Authorization leaked: got %q", got)
	}
}

func TestApplyInjection_ExtraPassthroughHeaders_AreCaseInsensitive(t *testing.T) {
	// Clients may send headers with any casing; net/http canonicalizes keys.
	// The allowlist extension must match regardless of how the client spelled it.
	src := http.Header{}
	src.Set("Anthropic-Version", "2023-06-01") // canonical
	dst := http.Header{}

	ApplyInjection(src, dst, &InjectResult{
		Headers:                 map[string]string{"x-api-key": "k"},
		ExtraPassthroughHeaders: []string{"anthropic-version"}, // lowercase
	})

	if got := dst.Get("anthropic-version"); got != "2023-06-01" {
		t.Fatalf("extra passthrough should be case-insensitive; got %q", got)
	}
}

func TestApplyInjection_ExtraPassthrough_IgnoredForPassthroughService(t *testing.T) {
	// Passthrough services forward everything via the denylist, so
	// ExtraPassthroughHeaders has no effect \u2014 but must not crash either.
	// (Validation also rejects this config upstream; this is runtime
	// defense-in-depth.)
	src := http.Header{}
	src.Set("anthropic-version", "2023-06-01")
	src.Set("X-Vault", "session-token")
	dst := http.Header{}

	ApplyInjection(src, dst, &InjectResult{
		Passthrough:             true,
		ExtraPassthroughHeaders: []string{"anthropic-version"},
	})

	// Passthrough forwards the header via the denylist path regardless.
	if got := dst.Get("anthropic-version"); got != "2023-06-01" {
		t.Fatalf("passthrough should forward header; got %q", got)
	}
	// Broker-scoped header must still be stripped even on passthrough.
	if got := dst.Get("X-Vault"); got != "" {
		t.Fatalf("X-Vault leaked through passthrough: got %q", got)
	}
}

func TestApplyInjection_ExtraPassthrough_InjectionStillWins(t *testing.T) {
	// If a client sends a header that both the service adds to the
	// allowlist AND the auth config injects, the injected value must win.
	// This is the same guarantee PassthroughHeaders provides for
	// Authorization, extended to the custom-header case.
	src := http.Header{}
	src.Set("anthropic-version", "CLIENT_VALUE")
	dst := http.Header{}

	ApplyInjection(src, dst, &InjectResult{
		Headers:                 map[string]string{"anthropic-version": "SERVICE_VALUE"},
		ExtraPassthroughHeaders: []string{"anthropic-version"},
	})

	if got := dst.Get("anthropic-version"); got != "SERVICE_VALUE" {
		t.Fatalf("injection must win; got %q", got)
	}
	vals := dst.Values("anthropic-version")
	if len(vals) != 1 {
		t.Fatalf("expected exactly one value after injection overwrite, got %v", vals)
	}
}
