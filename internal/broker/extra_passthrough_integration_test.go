package broker

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestServiceJSONRoundTripPreservesExtraPassthroughHeaders simulates the
// exact data-flow the HTTP service uses: client JSON body \u2192 Unmarshal
// into broker.Service \u2192 Validate \u2192 JSON-serialize into store \u2192
// Unmarshal again when loading. If any struct tag is missing or
// validation drops the field, this round-trip detects it.
func TestServiceJSONRoundTripPreservesExtraPassthroughHeaders(t *testing.T) {
	raw := []byte(`{
		"host": "api.anthropic.com",
		"auth": {"type": "api-key", "key": "ANTHROPIC_API_KEY", "header": "x-api-key"},
		"extra_passthrough_headers": ["anthropic-version", "anthropic-beta"]
	}`)

	var s Service
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(s.ExtraPassthroughHeaders) != 2 {
		t.Fatalf("expected 2 headers, got %v", s.ExtraPassthroughHeaders)
	}
	if s.ExtraPassthroughHeaders[0] != "anthropic-version" {
		t.Fatalf("first header wrong: %q", s.ExtraPassthroughHeaders[0])
	}

	cfg := &Config{Vault: "default", Services: []Service{s}}
	if err := Validate(cfg); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// Round-trip through JSON mirrors the store's serialize/deserialize.
	marshaled, err := json.Marshal(cfg.Services)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var round []Service
	if err := json.Unmarshal(marshaled, &round); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	if len(round[0].ExtraPassthroughHeaders) != 2 ||
		round[0].ExtraPassthroughHeaders[0] != "anthropic-version" {
		t.Fatalf("round-trip lost headers: %+v", round[0].ExtraPassthroughHeaders)
	}
}

// TestServiceJSONOmitsEmptyExtraPassthroughHeaders confirms the field is
// omitted from serialized JSON when unset so old records and services
// that don't need the extension stay byte-compatible with pre-upgrade
// data \u2014 important for forward/backward compatibility on existing
// vaults.
func TestServiceJSONOmitsEmptyExtraPassthroughHeaders(t *testing.T) {
	s := Service{
		Host: "api.github.com",
		Auth: Auth{Type: "bearer", Token: "GITHUB_TOKEN"},
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// omitempty should keep the field out of the output when nil.
	if strings.Contains(string(b), "extra_passthrough_headers") {
		t.Fatalf("expected field to be omitted when empty, got %s", string(b))
	}
}
