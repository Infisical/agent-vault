package brokercore

import (
	"encoding/json"
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
