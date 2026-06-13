package brokercore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

// fakeCredStore satisfies CredentialStore for tests.
type fakeCredStore struct {
	brokerCfg     map[string]*store.BrokerConfig // vaultID → config
	creds         map[string]*store.Credential   // key = vaultID+"|"+key
	missKey       string                         // if set, GetCredential for this key returns nil/err
	policy        UnmatchedHostPolicy            // unmatched-host policy returned by UnmatchedHostPolicy
	brokerCfgErr  error                          // if non-nil, GetBrokerConfig returns this error

	getCredentialCalls int // call count — used by passthrough tests to assert no lookup
}

func newFakeCredStore() *fakeCredStore {
	return &fakeCredStore{
		brokerCfg: map[string]*store.BrokerConfig{},
		creds:     map[string]*store.Credential{},
		policy:    PolicyPassthrough,
	}
}

func (f *fakeCredStore) GetBrokerConfig(_ context.Context, vaultID string) (*store.BrokerConfig, error) {
	if f.brokerCfgErr != nil {
		return nil, f.brokerCfgErr
	}
	c, ok := f.brokerCfg[vaultID]
	if !ok {
		return nil, nil
	}
	return c, nil
}
func (f *fakeCredStore) GetCredential(_ context.Context, vaultID, key string) (*store.Credential, error) {
	f.getCredentialCalls++
	if key == f.missKey {
		return nil, errors.New("missing")
	}
	c, ok := f.creds[vaultID+"|"+key]
	if !ok {
		return nil, errors.New("not found")
	}
	return c, nil
}

func (f *fakeCredStore) UnmatchedHostPolicy(_ context.Context, _ string) (UnmatchedHostPolicy, error) {
	if f.policy == "" {
		return PolicyPassthrough, nil
	}
	return f.policy, nil
}

// make32 returns a deterministic 32-byte key for tests.
func make32(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func (f *fakeCredStore) setCred(t *testing.T, key32 []byte, vaultID, key, plaintext string) {
	t.Helper()
	ct, nonce, err := crypto.Encrypt([]byte(plaintext), key32)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	f.creds[vaultID+"|"+key] = &store.Credential{
		VaultID: vaultID, Key: key, Ciphertext: ct, Nonce: nonce,
	}
}

func (f *fakeCredStore) setServices(t *testing.T, vaultID string, svcs []broker.Service) {
	t.Helper()
	b, err := json.Marshal(svcs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	f.brokerCfg[vaultID] = &store.BrokerConfig{VaultID: vaultID, ServicesJSON: string(b)}
}

func TestInject_BearerHappyPath(t *testing.T) {
	key32 := make32(0x11)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.example.com",
		Auth: broker.Auth{Type: "bearer", Token: "MY_TOKEN"},
	}})
	f.setCred(t, key32, "v1", "MY_TOKEN", "s3cret")

	p := NewStoreCredentialProvider(f, key32)
	res, err := p.Inject(context.Background(), "v1", "api.example.com", 0, "/")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Headers["Authorization"] != "Bearer s3cret" {
		t.Fatalf("got Authorization=%q", res.Headers["Authorization"])
	}
}

func TestInject_BasicHappyPath(t *testing.T) {
	key32 := make32(0x22)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.example.com",
		Auth: broker.Auth{Type: "basic", Username: "USER", Password: "PASS"},
	}})
	f.setCred(t, key32, "v1", "USER", "alice")
	f.setCred(t, key32, "v1", "PASS", "wonderland")

	p := NewStoreCredentialProvider(f, key32)
	res, err := p.Inject(context.Background(), "v1", "api.example.com", 0, "/")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:wonderland"))
	if res.Headers["Authorization"] != want {
		t.Fatalf("got %q want %q", res.Headers["Authorization"], want)
	}
}

func TestInject_APIKeyCustomHeader(t *testing.T) {
	key32 := make32(0x33)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.example.com",
		Auth: broker.Auth{Type: "api-key", Key: "STRIPE_KEY", Header: "X-API-Key", Prefix: "sk_"},
	}})
	f.setCred(t, key32, "v1", "STRIPE_KEY", "live123")

	p := NewStoreCredentialProvider(f, key32)
	res, err := p.Inject(context.Background(), "v1", "api.example.com", 0, "/")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Headers["X-API-Key"] != "sk_live123" {
		t.Fatalf("got X-API-Key=%q", res.Headers["X-API-Key"])
	}
}

func TestInject_CustomHeaders(t *testing.T) {
	key32 := make32(0x44)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.example.com",
		Auth: broker.Auth{Type: "custom", Headers: map[string]string{
			"X-Api-Key": "{{ API_KEY }}",
			"X-Tenant":  "acme-{{ TENANT }}",
		}},
	}})
	f.setCred(t, key32, "v1", "API_KEY", "abc")
	f.setCred(t, key32, "v1", "TENANT", "42")

	p := NewStoreCredentialProvider(f, key32)
	res, err := p.Inject(context.Background(), "v1", "api.example.com", 0, "/")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Headers["X-Api-Key"] != "abc" {
		t.Fatalf("got X-Api-Key=%q", res.Headers["X-Api-Key"])
	}
	if res.Headers["X-Tenant"] != "acme-42" {
		t.Fatalf("got X-Tenant=%q", res.Headers["X-Tenant"])
	}
}

func TestInject_StripsPortForMatching(t *testing.T) {
	key32 := make32(0x55)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.example.com",
		Auth: broker.Auth{Type: "bearer", Token: "TOK"},
	}})
	f.setCred(t, key32, "v1", "TOK", "v")

	p := NewStoreCredentialProvider(f, key32)
	res, err := p.Inject(context.Background(), "v1", "api.example.com:443", 443, "/")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Headers["Authorization"] != "Bearer v" {
		t.Fatalf("got %q", res.Headers["Authorization"])
	}
}

// TestInject_HealsLegacyUnnamedServiceMatchedName pins that the proxy
// hot path auto-slugs missing Names before matching, so MatchedName
// (which lands in the request log and the X-Vault-Service header)
// never persists as "" for a matched service. The documented
// `?service=<name>` log filter depends on this.
func TestInject_HealsLegacyUnnamedServiceMatchedName(t *testing.T) {
	key32 := make32(0x77)
	f := newFakeCredStore()
	// Pre-#164 vault: persisted without `name`.
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.example.com",
		Auth: broker.Auth{Type: "bearer", Token: "TOK"},
	}})
	f.setCred(t, key32, "v1", "TOK", "s3cret")

	p := NewStoreCredentialProvider(f, key32)
	res, err := p.Inject(context.Background(), "v1", "api.example.com", 0, "/")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.MatchedName != "api-example-com" {
		t.Fatalf("expected MatchedName=api-example-com (auto-slug), got %q", res.MatchedName)
	}
}

func TestInject_WildcardMatch(t *testing.T) {
	key32 := make32(0x66)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "*.github.com",
		Auth: broker.Auth{Type: "bearer", Token: "GH"},
	}})
	f.setCred(t, key32, "v1", "GH", "ghp_abc")

	p := NewStoreCredentialProvider(f, key32)
	res, err := p.Inject(context.Background(), "v1", "api.github.com", 0, "/")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Headers["Authorization"] != "Bearer ghp_abc" {
		t.Fatalf("got %q", res.Headers["Authorization"])
	}
}

// TestInject_PathBasedDisambiguation pins that two services on the same
// host with different path globs both work end-to-end through the
// Inject path: the more specific path wins, the right credential is
// injected, and MatchedName/Host/Path on the result reflect the
// matched service. The motivating case is the Slack split where /api/*
// uses a Bot token and /api/apps.connections.* uses a Socket Mode
// token.
func TestInject_PathBasedDisambiguation(t *testing.T) {
	key32 := make32(0x88)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{
		{
			Name: "slack-bot",
			Host: "slack.com",
			Path: "/api/*",
			Auth: broker.Auth{Type: "bearer", Token: "SLACK_BOT_TOKEN"},
		},
		{
			Name: "slack-conn",
			Host: "slack.com",
			Path: "/api/apps.connections.*",
			Auth: broker.Auth{Type: "bearer", Token: "SLACK_CONN_TOKEN"},
		},
	})
	f.setCred(t, key32, "v1", "SLACK_BOT_TOKEN", "xoxb-bot")
	f.setCred(t, key32, "v1", "SLACK_CONN_TOKEN", "xapp-conn")
	p := NewStoreCredentialProvider(f, key32)

	cases := []struct {
		path     string
		wantAuth string
		wantName string
		wantPath string
	}{
		{"/api/chat.postMessage", "Bearer xoxb-bot", "slack-bot", "/api/*"},
		{"/api/apps.connections.open", "Bearer xapp-conn", "slack-conn", "/api/apps.connections.*"},
	}
	for _, tc := range cases {
		res, err := p.Inject(context.Background(), "v1", "slack.com", 0, tc.path)
		if err != nil {
			t.Fatalf("path %q: unexpected err: %v", tc.path, err)
		}
		if res.Headers["Authorization"] != tc.wantAuth {
			t.Fatalf("path %q: got Authorization=%q want %q", tc.path, res.Headers["Authorization"], tc.wantAuth)
		}
		if res.MatchedName != tc.wantName {
			t.Fatalf("path %q: got MatchedName=%q want %q", tc.path, res.MatchedName, tc.wantName)
		}
		if res.MatchedHost != "slack.com" {
			t.Fatalf("path %q: got MatchedHost=%q want slack.com", tc.path, res.MatchedHost)
		}
		if res.MatchedPath != tc.wantPath {
			t.Fatalf("path %q: got MatchedPath=%q want %q", tc.path, res.MatchedPath, tc.wantPath)
		}
	}
}

func TestInject_UnmatchedHost_DefaultPassthrough(t *testing.T) {
	// With the default unmatched-host policy (passthrough), a host with
	// no matching service forwards without injection.
	f := newFakeCredStore()
	p := NewStoreCredentialProvider(f, make32(0x77))
	res, err := p.Inject(context.Background(), "v1", "api.example.com", 0, "/")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res == nil || !res.Passthrough {
		t.Fatalf("expected passthrough result, got %+v", res)
	}
	if len(res.Headers) != 0 {
		t.Fatalf("expected no injected headers, got %v", res.Headers)
	}
	if res.MatchedHost != "" {
		t.Fatalf("expected empty MatchedHost, got %q", res.MatchedHost)
	}
}

func TestInject_UnmatchedHost_HostMissPassthrough(t *testing.T) {
	// Even with services configured, a host that matches none of them
	// passes through under the default policy.
	key32 := make32(0x88)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.example.com",
		Auth: broker.Auth{Type: "bearer", Token: "T"},
	}})
	f.setCred(t, key32, "v1", "T", "x")

	p := NewStoreCredentialProvider(f, key32)
	res, err := p.Inject(context.Background(), "v1", "other.example.com", 0, "/")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res == nil || !res.Passthrough {
		t.Fatalf("expected passthrough result, got %+v", res)
	}
	if f.getCredentialCalls != 0 {
		t.Fatalf("passthrough should not resolve credentials, got %d calls", f.getCredentialCalls)
	}
}

func TestInject_UnmatchedHost_DenyPolicy(t *testing.T) {
	f := newFakeCredStore()
	f.policy = PolicyDeny
	p := NewStoreCredentialProvider(f, make32(0x77))
	_, err := p.Inject(context.Background(), "v1", "api.example.com", 0, "/")
	if !errors.Is(err, ErrServiceNotFound) {
		t.Fatalf("expected ErrServiceNotFound under deny policy, got %v", err)
	}
}

func TestInject_UnmatchedHost_HostMissDeny(t *testing.T) {
	key32 := make32(0x88)
	f := newFakeCredStore()
	f.policy = PolicyDeny
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.example.com",
		Auth: broker.Auth{Type: "bearer", Token: "T"},
	}})
	f.setCred(t, key32, "v1", "T", "x")

	p := NewStoreCredentialProvider(f, key32)
	_, err := p.Inject(context.Background(), "v1", "other.example.com", 0, "/")
	if !errors.Is(err, ErrServiceNotFound) {
		t.Fatalf("expected ErrServiceNotFound under deny policy, got %v", err)
	}
}

// Regression: a non-ErrNoRows GetBrokerConfig error must fail closed
// (ErrServiceNotFound), not fall through to passthrough. Otherwise a
// transient store failure silently strips credential injection from a
// vault that has services configured.
func TestInject_GetBrokerConfigError_FailsClosed(t *testing.T) {
	f := newFakeCredStore()
	f.brokerCfgErr = errors.New("transient sqlite I/O error")
	p := NewStoreCredentialProvider(f, make32(0xAB))
	_, err := p.Inject(context.Background(), "v1", "api.example.com", 0, "/")
	if !errors.Is(err, ErrServiceNotFound) {
		t.Fatalf("expected ErrServiceNotFound on store error, got %v", err)
	}
}

func TestInject_CredentialMissing(t *testing.T) {
	key32 := make32(0x99)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.example.com",
		Auth: broker.Auth{Type: "bearer", Token: "MISSING"},
	}})

	p := NewStoreCredentialProvider(f, key32)
	_, err := p.Inject(context.Background(), "v1", "api.example.com", 0, "/")
	if !errors.Is(err, ErrCredentialMissing) {
		t.Fatalf("expected ErrCredentialMissing, got %v", err)
	}
}

func TestInject_DecryptFails(t *testing.T) {
	// Encrypt with one key, try to decrypt with another → ErrCredentialMissing wrapping decrypt error.
	encKey := make32(0xAA)
	wrongKey := make32(0xBB)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.example.com",
		Auth: broker.Auth{Type: "bearer", Token: "TOK"},
	}})
	f.setCred(t, encKey, "v1", "TOK", "secret")

	p := NewStoreCredentialProvider(f, wrongKey)
	_, err := p.Inject(context.Background(), "v1", "api.example.com", 0, "/")
	if !errors.Is(err, ErrCredentialMissing) {
		t.Fatalf("expected ErrCredentialMissing, got %v", err)
	}
}

func TestInject_Passthrough(t *testing.T) {
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.example.com",
		Auth: broker.Auth{Type: "passthrough"},
	}})

	p := NewStoreCredentialProvider(f, make32(0xCC))
	res, err := p.Inject(context.Background(), "v1", "api.example.com", 0, "/")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Headers != nil {
		t.Fatalf("expected nil Headers on passthrough, got %v", res.Headers)
	}
	if res.MatchedHost != "api.example.com" {
		t.Fatalf("MatchedHost = %q, want %q", res.MatchedHost, "api.example.com")
	}
	if len(res.CredentialKeys) != 0 {
		t.Fatalf("expected no CredentialKeys, got %v", res.CredentialKeys)
	}
	if f.getCredentialCalls != 0 {
		t.Fatalf("expected GetCredential to NOT be called, got %d calls", f.getCredentialCalls)
	}
}

func TestInject_ServiceDisabled(t *testing.T) {
	key32 := make32(0xEE)
	disabled := false
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host:    "api.example.com",
		Enabled: &disabled,
		Auth:    broker.Auth{Type: "bearer", Token: "TOK"},
	}})
	f.setCred(t, key32, "v1", "TOK", "x")

	p := NewStoreCredentialProvider(f, key32)
	_, err := p.Inject(context.Background(), "v1", "api.example.com", 0, "/")
	if !errors.Is(err, ErrServiceDisabled) {
		t.Fatalf("expected ErrServiceDisabled, got %v", err)
	}
	if f.getCredentialCalls != 0 {
		t.Fatalf("expected no credential lookup when disabled, got %d calls", f.getCredentialCalls)
	}
}

func TestInject_ServiceDisabled_Passthrough(t *testing.T) {
	disabled := false
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host:    "api.example.com",
		Enabled: &disabled,
		Auth:    broker.Auth{Type: "passthrough"},
	}})
	p := NewStoreCredentialProvider(f, make32(0xEF))
	_, err := p.Inject(context.Background(), "v1", "api.example.com", 0, "/")
	if !errors.Is(err, ErrServiceDisabled) {
		t.Fatalf("expected ErrServiceDisabled for disabled passthrough, got %v", err)
	}
}

func TestInject_EnabledExplicitTrue(t *testing.T) {
	key32 := make32(0xF0)
	enabled := true
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host:    "api.example.com",
		Enabled: &enabled,
		Auth:    broker.Auth{Type: "bearer", Token: "TOK"},
	}})
	f.setCred(t, key32, "v1", "TOK", "v")

	p := NewStoreCredentialProvider(f, key32)
	res, err := p.Inject(context.Background(), "v1", "api.example.com", 0, "/")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Headers["Authorization"] != "Bearer v" {
		t.Fatalf("got %q", res.Headers["Authorization"])
	}
}

func TestInject_PassthroughPortStripped(t *testing.T) {
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.example.com",
		Auth: broker.Auth{Type: "passthrough"},
	}})
	p := NewStoreCredentialProvider(f, make32(0xDD))
	res, err := p.Inject(context.Background(), "v1", "api.example.com:443", 443, "/")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Headers != nil {
		t.Fatalf("expected nil Headers on passthrough host:port match, got %v", res.Headers)
	}
	if res.MatchedHost != "api.example.com" {
		t.Fatalf("MatchedHost = %q, want %q", res.MatchedHost, "api.example.com")
	}
}

// --- Substitution resolution tests ---

func TestInject_ResolvesSubstitutionAlongsideAuth(t *testing.T) {
	key32 := make32(0xAB)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.twilio.com",
		Auth: broker.Auth{Type: "basic", Username: "TWILIO_ACCOUNT_SID", Password: "TWILIO_AUTH_TOKEN"},
		Substitutions: []broker.Substitution{
			{Key: "TWILIO_ACCOUNT_SID", Placeholder: "__account_sid__", In: []string{"path"}},
		},
	}})
	f.setCred(t, key32, "v1", "TWILIO_ACCOUNT_SID", "AC12345")
	f.setCred(t, key32, "v1", "TWILIO_AUTH_TOKEN", "tok-shh")

	p := NewStoreCredentialProvider(f, key32)
	res, err := p.Inject(context.Background(), "v1", "api.twilio.com", 0, "/")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(res.Substitutions) != 1 {
		t.Fatalf("expected 1 resolved substitution, got %+v", res.Substitutions)
	}
	if res.Substitutions[0].Placeholder != "__account_sid__" || res.Substitutions[0].Value != "AC12345" {
		t.Fatalf("unexpected substitution: %+v", res.Substitutions[0])
	}
	if got := res.Substitutions[0].In; len(got) != 1 || got[0] != "path" {
		t.Fatalf("expected normalized In=[path], got %v", got)
	}
	// Cred shared with auth should be decrypted only once thanks to memo.
	if f.getCredentialCalls != 2 {
		t.Fatalf("expected exactly 2 credential lookups (one per unique key), got %d", f.getCredentialCalls)
	}
	if res.Headers["Authorization"] == "" {
		t.Fatal("expected basic auth header still injected")
	}
}

func TestInject_ResolvesSubstitutionOnPassthrough(t *testing.T) {
	key32 := make32(0xCD)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.twilio.com",
		Auth: broker.Auth{Type: "passthrough"},
		Substitutions: []broker.Substitution{
			{Key: "TWILIO_ACCOUNT_SID", Placeholder: "__account_sid__", In: []string{"path"}},
		},
	}})
	f.setCred(t, key32, "v1", "TWILIO_ACCOUNT_SID", "AC12345")

	p := NewStoreCredentialProvider(f, key32)
	res, err := p.Inject(context.Background(), "v1", "api.twilio.com", 0, "/")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Headers != nil {
		t.Fatalf("expected nil Headers on passthrough, got %v", res.Headers)
	}
	if len(res.Substitutions) != 1 || res.Substitutions[0].Value != "AC12345" {
		t.Fatalf("expected substitution resolved on passthrough service, got %+v", res.Substitutions)
	}
}

func TestInject_SubstitutionMissingCredentialErrorsLikeAuth(t *testing.T) {
	key32 := make32(0xEF)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.twilio.com",
		Auth: broker.Auth{Type: "passthrough"},
		Substitutions: []broker.Substitution{
			{Key: "TWILIO_ACCOUNT_SID", Placeholder: "__account_sid__", In: []string{"path"}},
		},
	}})
	// No credential set → lookup returns "not found".
	p := NewStoreCredentialProvider(f, key32)
	_, err := p.Inject(context.Background(), "v1", "api.twilio.com", 0, "/")
	if !errors.Is(err, ErrCredentialMissing) {
		t.Fatalf("expected ErrCredentialMissing, got %v", err)
	}
}

func TestInject_AuthFailureLeavesSubstitutionsNil(t *testing.T) {
	// Substitution resolves successfully, then auth resolution fails.
	// The error path must NOT leak the resolved (secret) substitution
	// values via result.Substitutions — callers that log result on
	// errors would otherwise expose plaintext credential values.
	key32 := make32(0x77)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.twilio.com",
		Auth: broker.Auth{Type: "bearer", Token: "MISSING_AUTH_KEY"},
		Substitutions: []broker.Substitution{
			{Key: "PRESENT_SUB_KEY", Placeholder: "__sid__", In: []string{"path"}},
		},
	}})
	f.setCred(t, key32, "v1", "PRESENT_SUB_KEY", "SECRET-VALUE")
	// MISSING_AUTH_KEY is intentionally not set.

	p := NewStoreCredentialProvider(f, key32)
	res, err := p.Inject(context.Background(), "v1", "api.twilio.com", 0, "/")
	if !errors.Is(err, ErrCredentialMissing) {
		t.Fatalf("expected ErrCredentialMissing, got %v", err)
	}
	if res == nil {
		t.Fatal("expected result returned alongside error for diagnostic logging")
	}
	if res.Substitutions != nil {
		t.Fatalf("expected res.Substitutions=nil on auth error to avoid leaking secrets, got %+v", res.Substitutions)
	}
}

func TestInject_PortMatch(t *testing.T) {
	port := 8080
	key32 := make32(0xA1)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.example.com",
		Port: &port,
		Auth: broker.Auth{Type: "bearer", Token: "TOK"},
	}})
	f.setCred(t, key32, "v1", "TOK", "secret")

	p := NewStoreCredentialProvider(f, key32)
	res, err := p.Inject(context.Background(), "v1", "api.example.com", 8080, "/")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.MatchedPort == nil || *res.MatchedPort != 8080 {
		t.Fatalf("expected MatchedPort=8080, got %v", res.MatchedPort)
	}
	if res.Headers["Authorization"] != "Bearer secret" {
		t.Fatalf("got %q", res.Headers["Authorization"])
	}
}

func TestInject_PortMismatch(t *testing.T) {
	port := 8080
	key32 := make32(0xA2)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.example.com",
		Port: &port,
		Auth: broker.Auth{Type: "bearer", Token: "TOK"},
	}})
	f.setCred(t, key32, "v1", "TOK", "secret")

	p := NewStoreCredentialProvider(f, key32)
	res, err := p.Inject(context.Background(), "v1", "api.example.com", 9090, "/")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !res.Passthrough {
		t.Fatal("expected passthrough for port mismatch")
	}
}

func TestInject_PortSpecificWinsOverGeneral(t *testing.T) {
	port443 := 443
	key32 := make32(0xA3)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{
		{Name: "general", Host: "api.example.com", Auth: broker.Auth{Type: "bearer", Token: "GEN_TOK"}},
		{Name: "port-specific", Host: "api.example.com", Port: &port443, Auth: broker.Auth{Type: "bearer", Token: "SPECIFIC_TOK"}},
	})
	f.setCred(t, key32, "v1", "GEN_TOK", "gen-secret")
	f.setCred(t, key32, "v1", "SPECIFIC_TOK", "specific-secret")

	p := NewStoreCredentialProvider(f, key32)
	res, err := p.Inject(context.Background(), "v1", "api.example.com", 443, "/")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.MatchedName != "port-specific" {
		t.Fatalf("expected port-specific to win, got %q", res.MatchedName)
	}
	if res.Headers["Authorization"] != "Bearer specific-secret" {
		t.Fatalf("got %q", res.Headers["Authorization"])
	}
}

func TestInject_NilPortMatchesAnyPort(t *testing.T) {
	key32 := make32(0xA4)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.example.com",
		Auth: broker.Auth{Type: "bearer", Token: "TOK"},
	}})
	f.setCred(t, key32, "v1", "TOK", "secret")

	p := NewStoreCredentialProvider(f, key32)
	res, err := p.Inject(context.Background(), "v1", "api.example.com", 8080, "/")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.MatchedPort != nil {
		t.Fatalf("expected MatchedPort=nil (any port), got %v", res.MatchedPort)
	}
}

func TestInject_CredentialKeysIncludesSubstitution(t *testing.T) {
	key32 := make32(0x12)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.twilio.com",
		Auth: broker.Auth{Type: "bearer", Token: "TWILIO_AUTH_TOKEN"},
		Substitutions: []broker.Substitution{
			{Key: "TWILIO_ACCOUNT_SID", Placeholder: "__account_sid__", In: []string{"path"}},
		},
	}})
	f.setCred(t, key32, "v1", "TWILIO_AUTH_TOKEN", "tok")
	// No SID credential → expect ErrCredentialMissing, but CredentialKeys
	// must already be populated for diagnostic logging.
	p := NewStoreCredentialProvider(f, key32)
	res, err := p.Inject(context.Background(), "v1", "api.twilio.com", 0, "/")
	if !errors.Is(err, ErrCredentialMissing) {
		t.Fatalf("expected ErrCredentialMissing, got %v", err)
	}
	if res == nil || len(res.CredentialKeys) != 2 {
		t.Fatalf("expected CredentialKeys to include both auth and substitution keys, got %+v", res)
	}
}
