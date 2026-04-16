package brokercore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
)

// randomSentinel returns a long, lowercase, hyphen-prefixed token whose
// character class cannot collide with UPPER_SNAKE_CASE credential key
// names. This matters for the redaction assertion: a naive sentinel like
// "SECRET_12345" could be a substring of a key name and produce a false
// positive when the log contains the key.
func randomSentinel(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return "sentinel-" + strings.ToLower(base64.RawURLEncoding.EncodeToString(b))
}

// TestLogProxyEvent_NoSecretLeak proves the debug log line never contains
// the resolved credential value across all four broker auth types — the
// core redaction guardrail called out in the plan.
func TestLogProxyEvent_NoSecretLeak(t *testing.T) {
	encKey := make32(0xAB)

	cases := []struct {
		name         string
		auth         broker.Auth
		expectedKeys []string
	}{
		{
			name:         "bearer",
			auth:         broker.Auth{Type: "bearer", Token: "BEARER_TOKEN"},
			expectedKeys: []string{"BEARER_TOKEN"},
		},
		{
			name:         "basic",
			auth:         broker.Auth{Type: "basic", Username: "BASIC_USER", Password: "BASIC_PASS"},
			expectedKeys: []string{"BASIC_USER", "BASIC_PASS"},
		},
		{
			name:         "api_key",
			auth:         broker.Auth{Type: "api-key", Key: "APIKEY_SECRET", Header: "X-Api-Key"},
			expectedKeys: []string{"APIKEY_SECRET"},
		},
		{
			name: "custom",
			auth: broker.Auth{
				Type: "custom",
				Headers: map[string]string{
					"X-Token":  "Bearer {{ CUSTOM_TOKEN }}",
					"X-Second": "{{ CUSTOM_SECOND }}",
				},
			},
			expectedKeys: []string{"CUSTOM_TOKEN", "CUSTOM_SECOND"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeCredStore()
			f.setServices(t, "v1", []broker.Service{{Host: "api.example.com", Auth: tc.auth}})

			sentinels := make(map[string]string, len(tc.expectedKeys))
			for _, k := range tc.expectedKeys {
				s := randomSentinel(t)
				sentinels[k] = s
				f.setCred(t, encKey, "v1", k, s)
			}

			provider := NewStoreCredentialProvider(f, encKey)
			result, err := provider.Inject(context.Background(), "v1", "api.example.com")
			if err != nil {
				t.Fatalf("Inject: %v", err)
			}
			if result.MatchedHost != "api.example.com" {
				t.Errorf("MatchedHost = %q, want api.example.com", result.MatchedHost)
			}

			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

			LogProxyEvent(logger, ProxyEvent{
				Ingress:        "explicit",
				Method:         "GET",
				Host:           "api.example.com",
				Path:           "/v1/users",
				MatchedService: result.MatchedHost,
				CredentialKeys: result.CredentialKeys,
				Status:         200,
				TotalMs:        42,
			})

			out := buf.String()
			if len(out) == 0 {
				t.Fatal("expected log output, got empty buffer (log path did not fire)")
			}
			for key, sentinel := range sentinels {
				if strings.Contains(out, sentinel) {
					t.Errorf("credential value for %s leaked into log output: %q\nfull log: %s", key, sentinel, out)
				}
				if !strings.Contains(out, key) {
					t.Errorf("expected key name %s in log output, got: %s", key, out)
				}
			}
		})
	}
}

// TestLogProxyEvent_CredentialMissingCarriesMetadata verifies that even
// when credential resolution fails, the InjectResult still carries the
// matched service + credential key names so the log line remains useful.
func TestLogProxyEvent_CredentialMissingCarriesMetadata(t *testing.T) {
	encKey := make32(0xCD)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.example.com",
		Auth: broker.Auth{Type: "bearer", Token: "MISSING_TOKEN"},
	}})
	// Deliberately don't seed MISSING_TOKEN — Resolve will fail.

	provider := NewStoreCredentialProvider(f, encKey)
	result, err := provider.Inject(context.Background(), "v1", "api.example.com")
	if err == nil {
		t.Fatal("expected ErrCredentialMissing, got nil")
	}
	if result == nil {
		t.Fatal("expected non-nil result even on credential miss")
	}
	if result.MatchedHost != "api.example.com" {
		t.Errorf("MatchedHost = %q, want api.example.com", result.MatchedHost)
	}
	if len(result.CredentialKeys) != 1 || result.CredentialKeys[0] != "MISSING_TOKEN" {
		t.Errorf("CredentialKeys = %v, want [MISSING_TOKEN]", result.CredentialKeys)
	}
}

// TestLogProxyEvent_Shape verifies the structured field shape of the
// emitted line, including empty-match and mitm-ingress variants.
func TestLogProxyEvent_Shape(t *testing.T) {
	cases := []struct {
		name  string
		event ProxyEvent
		want  []string
	}{
		{
			name: "explicit_success",
			event: ProxyEvent{
				Ingress: "explicit", Method: "GET", Host: "api.example.com",
				Path: "/v1/users", MatchedService: "api.example.com",
				CredentialKeys: []string{"API_KEY"}, Status: 200, TotalMs: 17,
			},
			want: []string{
				"ingress=explicit",
				"method=GET",
				"status=200",
				"matched_service=api.example.com",
				"API_KEY",
			},
		},
		{
			name: "mitm_no_match",
			event: ProxyEvent{
				Ingress: "mitm", Method: "POST", Host: "unknown.example.com",
				Path: "/", Status: 403, TotalMs: 3, Err: "no_match",
			},
			want: []string{
				"ingress=mitm",
				"err=no_match",
				"status=403",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			LogProxyEvent(logger, tc.event)
			out := buf.String()
			if !strings.Contains(out, "proxy_request") {
				t.Errorf("missing proxy_request message in %q", out)
			}
			for _, needle := range tc.want {
				if !strings.Contains(out, needle) {
					t.Errorf("missing %q in log output: %s", needle, out)
				}
			}
		})
	}
}

// TestLogProxyEvent_InfoLevelSuppressed confirms that the default
// info-level handler filters out the per-request debug line entirely.
func TestLogProxyEvent_InfoLevelSuppressed(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	LogProxyEvent(logger, ProxyEvent{Ingress: "explicit", Status: 200})
	if buf.Len() != 0 {
		t.Errorf("expected zero output at info level, got: %s", buf.String())
	}
}

// TestLogProxyEvent_NilLoggerSafe guards handlers passing a nil logger.
func TestLogProxyEvent_NilLoggerSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	LogProxyEvent(nil, ProxyEvent{Ingress: "explicit"})
}
