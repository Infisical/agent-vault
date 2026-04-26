package broker

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestMatchHostExact(t *testing.T) {
	services := []Service{
		{Host: "api.stripe.com", Auth: Auth{Type: "bearer", Token: "STRIPE_KEY"}},
	}
	r := MatchHost("api.stripe.com", services)
	if r == nil {
		t.Fatal("expected a match")
	}
	if r.Host != "api.stripe.com" {
		t.Fatalf("expected api.stripe.com, got %s", r.Host)
	}
}

func TestMatchHostWildcard(t *testing.T) {
	services := []Service{
		{Host: "*.github.com", Auth: Auth{Type: "bearer", Token: "GH_TOKEN"}},
	}
	for _, host := range []string{"api.github.com", "uploads.github.com"} {
		r := MatchHost(host, services)
		if r == nil {
			t.Fatalf("expected match for %s", host)
		}
	}
	// Should not match bare "github.com"
	if r := MatchHost("github.com", services); r != nil {
		t.Fatal("did not expect match for github.com")
	}
}

func TestMatchHostNoMatch(t *testing.T) {
	services := []Service{
		{Host: "api.stripe.com", Auth: Auth{Type: "bearer", Token: "STRIPE_KEY"}},
	}
	if r := MatchHost("evil.com", services); r != nil {
		t.Fatal("expected no match")
	}
}

func TestMatchHostFirstWins(t *testing.T) {
	services := []Service{
		{Host: "*.example.com", Auth: Auth{Type: "custom", Headers: map[string]string{"X-First": "1"}}},
		{Host: "api.example.com", Auth: Auth{Type: "custom", Headers: map[string]string{"X-Second": "2"}}},
	}
	r := MatchHost("api.example.com", services)
	if r == nil {
		t.Fatal("expected a match")
	}
	if _, ok := r.Auth.Headers["X-First"]; !ok {
		t.Fatal("expected first service to win")
	}
}

// --- Auth.Validate tests ---

func TestAuthValidateBearer(t *testing.T) {
	a := Auth{Type: "bearer", Token: "STRIPE_KEY"}
	if err := a.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthValidateBearerMissingToken(t *testing.T) {
	a := Auth{Type: "bearer"}
	if err := a.Validate(); err == nil {
		t.Fatal("expected error for missing token")
	}
}

func TestAuthValidateBearerUnexpectedField(t *testing.T) {
	a := Auth{Type: "bearer", Token: "KEY", Username: "USER"}
	err := a.Validate()
	if err == nil {
		t.Fatal("expected error for unexpected field")
	}
}

func TestAuthValidateBasic(t *testing.T) {
	a := Auth{Type: "basic", Username: "USER_KEY"}
	if err := a.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthValidateBasicWithPassword(t *testing.T) {
	a := Auth{Type: "basic", Username: "USER_KEY", Password: "PASS_KEY"}
	if err := a.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthValidateBasicMissingUsername(t *testing.T) {
	a := Auth{Type: "basic", Password: "PASS_KEY"}
	if err := a.Validate(); err == nil {
		t.Fatal("expected error for missing username")
	}
}

func TestAuthValidateApiKey(t *testing.T) {
	a := Auth{Type: "api-key", Key: "MY_KEY"}
	if err := a.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthValidateApiKeyWithHeaderAndPrefix(t *testing.T) {
	a := Auth{Type: "api-key", Key: "MY_KEY", Header: "X-API-Key", Prefix: "Token "}
	if err := a.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthValidateApiKeyMissingKey(t *testing.T) {
	a := Auth{Type: "api-key", Header: "Authorization"}
	if err := a.Validate(); err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestAuthValidateCustom(t *testing.T) {
	a := Auth{Type: "custom", Headers: map[string]string{"X-Key": "{{ MY_KEY }}"}}
	if err := a.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthValidateCustomMissingHeaders(t *testing.T) {
	a := Auth{Type: "custom"}
	if err := a.Validate(); err == nil {
		t.Fatal("expected error for missing headers")
	}
}

func TestAuthValidateUnsupportedType(t *testing.T) {
	a := Auth{Type: "oauth2"}
	if err := a.Validate(); err == nil {
		t.Fatal("expected error for unsupported type")
	}
}

func TestAuthValidateMissingType(t *testing.T) {
	a := Auth{}
	if err := a.Validate(); err == nil {
		t.Fatal("expected error for missing type")
	}
}

func TestAuthValidateCredentialKeyFormat(t *testing.T) {
	a := Auth{Type: "bearer", Token: "my_lowercase_key"}
	err := a.Validate()
	if err == nil {
		t.Fatal("expected error for non-UPPER_SNAKE_CASE key")
	}
}

// --- Auth.CredentialKeys tests ---

func TestAuthCredentialKeysBearer(t *testing.T) {
	a := Auth{Type: "bearer", Token: "STRIPE_KEY"}
	keys := a.CredentialKeys()
	if len(keys) != 1 || keys[0] != "STRIPE_KEY" {
		t.Fatalf("expected [STRIPE_KEY], got %v", keys)
	}
}

func TestAuthCredentialKeysBasic(t *testing.T) {
	a := Auth{Type: "basic", Username: "USER_KEY", Password: "PASS_KEY"}
	keys := a.CredentialKeys()
	if len(keys) != 2 || keys[0] != "USER_KEY" || keys[1] != "PASS_KEY" {
		t.Fatalf("expected [USER_KEY PASS_KEY], got %v", keys)
	}
}

func TestAuthCredentialKeysBasicNoPassword(t *testing.T) {
	a := Auth{Type: "basic", Username: "USER_KEY"}
	keys := a.CredentialKeys()
	if len(keys) != 1 || keys[0] != "USER_KEY" {
		t.Fatalf("expected [USER_KEY], got %v", keys)
	}
}

func TestAuthCredentialKeysApiKey(t *testing.T) {
	a := Auth{Type: "api-key", Key: "MY_KEY"}
	keys := a.CredentialKeys()
	if len(keys) != 1 || keys[0] != "MY_KEY" {
		t.Fatalf("expected [MY_KEY], got %v", keys)
	}
}

func TestAuthCredentialKeysCustom(t *testing.T) {
	a := Auth{Type: "custom", Headers: map[string]string{
		"Authorization": "Bearer {{ TOKEN }}",
		"X-Tenant":      "{{ TENANT_ID }}",
	}}
	keys := a.CredentialKeys()
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %v", keys)
	}
}

// --- Auth.Resolve tests ---

func testGetCredential(creds map[string]string) func(string) (string, error) {
	return func(key string) (string, error) {
		v, ok := creds[key]
		if !ok {
			return "", fmt.Errorf("credential %q not found", key)
		}
		return v, nil
	}
}

func TestAuthResolveBearer(t *testing.T) {
	a := Auth{Type: "bearer", Token: "STRIPE_KEY"}
	resolved, err := a.Resolve(testGetCredential(map[string]string{"STRIPE_KEY": "sk_live_xxx"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved["Authorization"] != "Bearer sk_live_xxx" {
		t.Fatalf("expected 'Bearer sk_live_xxx', got %q", resolved["Authorization"])
	}
}

func TestAuthResolveBasic(t *testing.T) {
	a := Auth{Type: "basic", Username: "USER_KEY", Password: "PASS_KEY"}
	resolved, err := a.Resolve(testGetCredential(map[string]string{
		"USER_KEY": "myuser",
		"PASS_KEY": "mypass",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("myuser:mypass"))
	if resolved["Authorization"] != expected {
		t.Fatalf("expected %q, got %q", expected, resolved["Authorization"])
	}
}

func TestAuthResolveBasicNoPassword(t *testing.T) {
	a := Auth{Type: "basic", Username: "API_KEY"}
	resolved, err := a.Resolve(testGetCredential(map[string]string{"API_KEY": "key123"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("key123:"))
	if resolved["Authorization"] != expected {
		t.Fatalf("expected %q, got %q", expected, resolved["Authorization"])
	}
}

func TestAuthResolveApiKey(t *testing.T) {
	a := Auth{Type: "api-key", Key: "MY_KEY", Header: "X-API-Key"}
	resolved, err := a.Resolve(testGetCredential(map[string]string{"MY_KEY": "abc123"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved["X-API-Key"] != "abc123" {
		t.Fatalf("expected 'abc123', got %q", resolved["X-API-Key"])
	}
}

func TestAuthResolveApiKeyWithPrefix(t *testing.T) {
	a := Auth{Type: "api-key", Key: "MY_KEY", Header: "Authorization", Prefix: "Bearer "}
	resolved, err := a.Resolve(testGetCredential(map[string]string{"MY_KEY": "tok_xxx"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved["Authorization"] != "Bearer tok_xxx" {
		t.Fatalf("expected 'Bearer tok_xxx', got %q", resolved["Authorization"])
	}
}

func TestAuthResolveApiKeyDefaultHeader(t *testing.T) {
	a := Auth{Type: "api-key", Key: "MY_KEY"}
	resolved, err := a.Resolve(testGetCredential(map[string]string{"MY_KEY": "val"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resolved["Authorization"]; !ok {
		t.Fatal("expected Authorization header as default")
	}
}

func TestAuthResolveCustom(t *testing.T) {
	a := Auth{Type: "custom", Headers: map[string]string{
		"Authorization": "Bearer {{ STRIPE_KEY }}",
		"X-API-Key":     "{{ API_KEY }}",
	}}
	resolved, err := a.Resolve(testGetCredential(map[string]string{
		"STRIPE_KEY": "sk_live_xxx",
		"API_KEY":    "key123",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved["Authorization"] != "Bearer sk_live_xxx" {
		t.Fatalf("expected 'Bearer sk_live_xxx', got %q", resolved["Authorization"])
	}
	if resolved["X-API-Key"] != "key123" {
		t.Fatalf("expected 'key123', got %q", resolved["X-API-Key"])
	}
}

func TestAuthResolveMissingCredential(t *testing.T) {
	a := Auth{Type: "bearer", Token: "NONEXISTENT"}
	_, err := a.Resolve(testGetCredential(map[string]string{}))
	if err == nil {
		t.Fatal("expected error for missing credential")
	}
}

func TestAuthResolveUnsupportedType(t *testing.T) {
	a := Auth{Type: "oauth2"}
	_, err := a.Resolve(testGetCredential(map[string]string{}))
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
}

// --- Validate config tests ---

func TestValidateConfigWithAuth(t *testing.T) {
	cfg := &Config{
		Vault: "default",
		Services: []Service{
			{Host: "api.stripe.com", Auth: Auth{Type: "bearer", Token: "STRIPE_KEY"}},
			{Host: "api.ashby.com", Auth: Auth{Type: "basic", Username: "ASHBY_KEY"}},
		},
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateConfigInvalidAuth(t *testing.T) {
	cfg := &Config{
		Vault: "default",
		Services: []Service{
			{Host: "api.stripe.com", Auth: Auth{Type: "bearer"}}, // missing token
		},
	}
	if err := Validate(cfg); err == nil {
		t.Fatal("expected error for invalid auth")
	}
}

// --- Passthrough tests ---

func TestAuthValidatePassthrough(t *testing.T) {
	a := Auth{Type: "passthrough"}
	if err := a.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthValidatePassthroughRejectsCredentialFields(t *testing.T) {
	cases := []struct {
		name string
		auth Auth
	}{
		{"token", Auth{Type: "passthrough", Token: "FOO"}},
		{"username", Auth{Type: "passthrough", Username: "FOO"}},
		{"password", Auth{Type: "passthrough", Password: "FOO"}},
		{"key", Auth{Type: "passthrough", Key: "FOO"}},
		{"header", Auth{Type: "passthrough", Header: "X-Foo"}},
		{"prefix", Auth{Type: "passthrough", Prefix: "Bearer "}},
		{"headers", Auth{Type: "passthrough", Headers: map[string]string{"X-Foo": "bar"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.auth.Validate(); err == nil {
				t.Fatalf("expected error for %s on passthrough auth", tc.name)
			}
		})
	}
}

func TestAuthCredentialKeysPassthrough(t *testing.T) {
	a := Auth{Type: "passthrough"}
	if keys := a.CredentialKeys(); keys != nil {
		t.Fatalf("expected nil, got %v", keys)
	}
}

func TestAuthResolvePassthrough(t *testing.T) {
	a := Auth{Type: "passthrough"}
	resolved, err := a.Resolve(func(key string) (string, error) {
		t.Fatalf("getCredential should not be called for passthrough, got %q", key)
		return "", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != nil {
		t.Fatalf("expected nil headers, got %v", resolved)
	}
}

func TestValidateConfigPassthrough(t *testing.T) {
	cfg := &Config{
		Vault: "default",
		Services: []Service{
			{Host: "api.example.com", Auth: Auth{Type: "passthrough"}},
		},
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Substitution validation tests ---

func TestValidateSubstitutionsValid(t *testing.T) {
	cases := []struct {
		name string
		sub  Substitution
	}{
		{"underscore convention", Substitution{Key: "TWILIO_ACCOUNT_SID", Placeholder: "__account_sid__", In: []string{"path"}}},
		{"dot delimiter", Substitution{Key: "ACCOUNT_SID", Placeholder: "sid.value", In: []string{"path", "query"}}},
		{"hyphen delimiter", Substitution{Key: "ACCOUNT_SID", Placeholder: "sid-val", In: []string{"path"}}},
		{"tilde delimiter", Substitution{Key: "ACCOUNT_SID", Placeholder: "~sid~val", In: []string{"path"}}},
		{"in defaulted", Substitution{Key: "ACCOUNT_SID", Placeholder: "__sid__"}},
		{"header surface", Substitution{Key: "TENANT_ID", Placeholder: "__tenant__", In: []string{"header"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := Service{Host: "api.example.com", Auth: Auth{Type: "passthrough"}, Substitutions: []Substitution{tc.sub}}
			if err := s.ValidateSubstitutions(); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateSubstitutionsRejectsBareWord(t *testing.T) {
	s := Service{Host: "api.example.com", Auth: Auth{Type: "passthrough"}, Substitutions: []Substitution{
		{Key: "ACCOUNT_SID", Placeholder: "account_sid", In: []string{"path"}},
	}}
	if err := s.ValidateSubstitutions(); err == nil {
		t.Fatal("expected error for bare alphanumeric placeholder (would match URL words)")
	}
}

func TestValidateSubstitutionsRejectsTooShort(t *testing.T) {
	s := Service{Host: "api.example.com", Substitutions: []Substitution{
		{Key: "K", Placeholder: "__x", In: []string{"path"}},
	}}
	if err := s.ValidateSubstitutions(); err == nil {
		t.Fatal("expected error for placeholder shorter than 4 chars")
	}
}

func TestValidateSubstitutionsRejectsControlChars(t *testing.T) {
	cases := []string{"__a\nb__", "__a\rb__", "__a b__", "__a\tb__"}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			s := Service{Host: "api.example.com", Substitutions: []Substitution{
				{Key: "K_X", Placeholder: p, In: []string{"path"}},
			}}
			if err := s.ValidateSubstitutions(); err == nil {
				t.Fatalf("expected error for placeholder containing control/whitespace char: %q", p)
			}
		})
	}
}

func TestValidateSubstitutionsRejectsReservedURLChars(t *testing.T) {
	cases := []string{"__a/b__", "__a?b__", "__a#b__", "__a&b__", "{sid}", "<sid>", "%%SID%%"}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			s := Service{Host: "api.example.com", Substitutions: []Substitution{
				{Key: "K_X", Placeholder: p, In: []string{"path"}},
			}}
			if err := s.ValidateSubstitutions(); err == nil {
				t.Fatalf("expected error for placeholder containing URL-reserved char: %q", p)
			}
		})
	}
}

func TestValidateSubstitutionsRejectsAllSymbol(t *testing.T) {
	// All-delimiter strings would aggressively match URL punctuation.
	cases := []string{"____", "~~~~", "----", "....", "~-.~"}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			s := Service{Host: "api.example.com", Substitutions: []Substitution{
				{Key: "K_X", Placeholder: p, In: []string{"path"}},
			}}
			if err := s.ValidateSubstitutions(); err == nil {
				t.Fatalf("expected error for all-symbol placeholder %q", p)
			}
		})
	}
}

func TestValidateSubstitutionsRejectsEmptyPlaceholder(t *testing.T) {
	s := Service{Host: "api.example.com", Substitutions: []Substitution{
		{Key: "ACCOUNT_SID", Placeholder: "", In: []string{"path"}},
	}}
	if err := s.ValidateSubstitutions(); err == nil {
		t.Fatal("expected error for empty placeholder")
	}
}

func TestValidateSubstitutionsRejectsEmptyKey(t *testing.T) {
	s := Service{Host: "api.example.com", Substitutions: []Substitution{
		{Key: "", Placeholder: "__sid__", In: []string{"path"}},
	}}
	if err := s.ValidateSubstitutions(); err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestValidateSubstitutionsRejectsLowerCaseKey(t *testing.T) {
	s := Service{Host: "api.example.com", Substitutions: []Substitution{
		{Key: "account_sid", Placeholder: "__sid__", In: []string{"path"}},
	}}
	if err := s.ValidateSubstitutions(); err == nil {
		t.Fatal("expected error for non-UPPER_SNAKE_CASE key")
	}
}

func TestValidateSubstitutionsRejectsBodySurface(t *testing.T) {
	s := Service{Host: "api.example.com", Substitutions: []Substitution{
		{Key: "K_X", Placeholder: "__sid__", In: []string{"body"}},
	}}
	if err := s.ValidateSubstitutions(); err == nil {
		t.Fatal("expected error for body surface (deferred in v1)")
	}
}

func TestValidateSubstitutionsRejectsUnknownSurface(t *testing.T) {
	s := Service{Host: "api.example.com", Substitutions: []Substitution{
		{Key: "K_X", Placeholder: "__sid__", In: []string{"cookie"}},
	}}
	if err := s.ValidateSubstitutions(); err == nil {
		t.Fatal("expected error for unknown surface")
	}
}

func TestValidateSubstitutionsRejectsDuplicatePlaceholder(t *testing.T) {
	s := Service{Host: "api.example.com", Substitutions: []Substitution{
		{Key: "K_ONE", Placeholder: "__sid__", In: []string{"path"}},
		{Key: "K_TWO", Placeholder: "__sid__", In: []string{"query"}},
	}}
	if err := s.ValidateSubstitutions(); err == nil {
		t.Fatal("expected error for duplicate placeholder within service")
	}
}

func TestValidateSubstitutionsRejectsDuplicateSurface(t *testing.T) {
	s := Service{Host: "api.example.com", Substitutions: []Substitution{
		{Key: "K_X", Placeholder: "__sid__", In: []string{"path", "path"}},
	}}
	if err := s.ValidateSubstitutions(); err == nil {
		t.Fatal("expected error for duplicate surface in In")
	}
}

func TestValidateSubstitutionsEmptyOk(t *testing.T) {
	s := Service{Host: "api.example.com"}
	if err := s.ValidateSubstitutions(); err != nil {
		t.Fatalf("unexpected error for empty substitutions: %v", err)
	}
}

func TestValidateConfigInvalidSubstitution(t *testing.T) {
	cfg := &Config{
		Vault: "default",
		Services: []Service{
			{
				Host: "api.example.com",
				Auth: Auth{Type: "bearer", Token: "MY_KEY"},
				Substitutions: []Substitution{
					{Key: "MY_KEY", Placeholder: "tooshort", In: []string{"path"}}, // no non-alnum char
				},
			},
		},
	}
	if err := Validate(cfg); err == nil {
		t.Fatal("expected Validate to surface substitution error")
	}
}

func TestSubstitutionNormalizedInDefaults(t *testing.T) {
	s := Substitution{Key: "K", Placeholder: "__x__"}
	got := s.NormalizedIn()
	if len(got) != 2 || got[0] != "path" || got[1] != "query" {
		t.Fatalf("expected default [path query], got %v", got)
	}
}

func TestSubstitutionNormalizedInExplicit(t *testing.T) {
	s := Substitution{Key: "K", Placeholder: "__x__", In: []string{"header"}}
	got := s.NormalizedIn()
	if len(got) != 1 || got[0] != "header" {
		t.Fatalf("expected [header], got %v", got)
	}
}

func TestServiceCredentialKeysCombines(t *testing.T) {
	s := Service{
		Host: "api.twilio.com",
		Auth: Auth{Type: "basic", Username: "TWILIO_ACCOUNT_SID", Password: "TWILIO_AUTH_TOKEN"},
		Substitutions: []Substitution{
			{Key: "TWILIO_ACCOUNT_SID", Placeholder: "__account_sid__", In: []string{"path"}}, // dup of auth
			{Key: "TWILIO_REGION", Placeholder: "__region__", In: []string{"path"}},           // unique
		},
	}
	keys := s.CredentialKeys()
	if len(keys) != 3 {
		t.Fatalf("expected 3 unique keys, got %v", keys)
	}
	if keys[0] != "TWILIO_ACCOUNT_SID" || keys[1] != "TWILIO_AUTH_TOKEN" || keys[2] != "TWILIO_REGION" {
		t.Fatalf("expected auth keys first then unique substitution keys, got %v", keys)
	}
}

func TestServiceCredentialKeysOnlyAuth(t *testing.T) {
	s := Service{Host: "api.example.com", Auth: Auth{Type: "bearer", Token: "MY_KEY"}}
	keys := s.CredentialKeys()
	if len(keys) != 1 || keys[0] != "MY_KEY" {
		t.Fatalf("expected [MY_KEY], got %v", keys)
	}
}
