package broker

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestMatchServiceExact(t *testing.T) {
	services := []Service{
		{Name: "stripe", Host: "api.stripe.com", Auth: Auth{Type: "bearer", Token: "STRIPE_KEY"}},
	}
	r, score := MatchService("api.stripe.com", "/v1/charges", services)
	if r == nil {
		t.Fatal("expected a match")
	}
	if r.Host != "api.stripe.com" {
		t.Fatalf("expected api.stripe.com, got %s", r.Host)
	}
	if score.HostTier != HostTierExact {
		t.Fatalf("expected exact host tier, got %d", score.HostTier)
	}
}

func TestMatchServiceWildcard(t *testing.T) {
	services := []Service{
		{Name: "github", Host: "*.github.com", Auth: Auth{Type: "bearer", Token: "GH_TOKEN"}},
	}
	for _, host := range []string{"api.github.com", "uploads.github.com"} {
		r, score := MatchService(host, "/", services)
		if r == nil {
			t.Fatalf("expected match for %s", host)
		}
		if score.HostTier != HostTierWildcard {
			t.Fatalf("expected wildcard tier for %s, got %d", host, score.HostTier)
		}
	}
	// Should not match bare "github.com"
	if r, _ := MatchService("github.com", "/", services); r != nil {
		t.Fatal("did not expect match for github.com")
	}
}

func TestMatchServiceNoMatch(t *testing.T) {
	services := []Service{
		{Name: "stripe", Host: "api.stripe.com", Auth: Auth{Type: "bearer", Token: "STRIPE_KEY"}},
	}
	if r, _ := MatchService("evil.com", "/", services); r != nil {
		t.Fatal("expected no match")
	}
}

func TestMatchServiceSpecificityWins(t *testing.T) {
	// The Slack two-credential case: longer literal path prefix wins
	// within the same host tier, regardless of slice order.
	services := []Service{
		{Name: "slack-bot", Host: "slack.com", Path: "/api/*", Auth: Auth{Type: "bearer", Token: "SLACK_BOT_TOKEN"}},
		{Name: "slack-conn", Host: "slack.com", Path: "/api/apps.connections.*", Auth: Auth{Type: "bearer", Token: "SLACK_CONNECTION_TOKEN"}},
	}
	r, _ := MatchService("slack.com", "/api/apps.connections.open", services)
	if r == nil || r.Name != "slack-conn" {
		t.Fatalf("expected slack-conn (longer literal prefix), got %+v", r)
	}
	r, _ = MatchService("slack.com", "/api/chat.postMessage", services)
	if r == nil || r.Name != "slack-bot" {
		t.Fatalf("expected slack-bot, got %+v", r)
	}
}

func TestMatchServiceHostExactBeatsWildcardEvenWithShorterPath(t *testing.T) {
	// Even when the wildcard rule has a more specific path, an exact
	// host always wins. Mirrors nginx server_name precedence.
	services := []Service{
		{Name: "wildcard", Host: "*.slack.com", Path: "/api/apps.connections.*", Auth: Auth{Type: "bearer", Token: "T1"}},
		{Name: "exact", Host: "api.slack.com", Auth: Auth{Type: "bearer", Token: "T2"}},
	}
	r, score := MatchService("api.slack.com", "/api/apps.connections.open", services)
	if r == nil || r.Name != "exact" {
		t.Fatalf("expected exact-host rule to win regardless of path, got %+v", r)
	}
	if score.HostTier != HostTierExact {
		t.Fatalf("expected exact host tier, got %d", score.HostTier)
	}
}

func TestMatchServicePathWildcardCrossSlash(t *testing.T) {
	// '*' is greedy and matches across '/'.
	services := []Service{
		{Name: "slack-bot", Host: "slack.com", Path: "/api/*", Auth: Auth{Type: "bearer", Token: "T"}},
	}
	r, _ := MatchService("slack.com", "/api/foo/bar/baz", services)
	if r == nil {
		t.Fatal("expected /api/* to match /api/foo/bar/baz greedily")
	}
}

func TestMatchServiceDeclarationOrderTiebreak(t *testing.T) {
	// Identical (hostTier, pathLiteralLen) → earlier in the slice wins.
	services := []Service{
		{Name: "first", Host: "*.example.com", Path: "/v1/*", Auth: Auth{Type: "custom", Headers: map[string]string{"X-First": "1"}}},
		{Name: "second", Host: "*.example.com", Path: "/v1/*", Auth: Auth{Type: "custom", Headers: map[string]string{"X-Second": "2"}}},
	}
	r, score := MatchService("api.example.com", "/v1/users", services)
	if r == nil || r.Name != "first" {
		t.Fatalf("expected first service to win on tie, got %+v", r)
	}
	if score.DeclOrder != 0 {
		t.Fatalf("expected DeclOrder 0, got %d", score.DeclOrder)
	}
}

func TestMatchServiceEmptyPathIsCatchAll(t *testing.T) {
	services := []Service{
		{Name: "scoped", Host: "slack.com", Path: "/api/*", Auth: Auth{Type: "bearer", Token: "T1"}},
		{Name: "catchall", Host: "slack.com", Auth: Auth{Type: "bearer", Token: "T2"}},
	}
	// Path matches the scoped rule → scoped wins (longer literal prefix).
	r, _ := MatchService("slack.com", "/api/foo", services)
	if r == nil || r.Name != "scoped" {
		t.Fatalf("expected scoped rule to win when path matches, got %+v", r)
	}
	// Path does NOT match the scoped rule → catch-all wins.
	r, _ = MatchService("slack.com", "/oauth/v2/authorize", services)
	if r == nil || r.Name != "catchall" {
		t.Fatalf("expected catchall rule when scoped path doesn't match, got %+v", r)
	}
}

func TestMatchServicePortStripped(t *testing.T) {
	// Service hosts with a port are still matched by bare hostname.
	services := []Service{
		{Name: "legacy", Host: "api.stripe.com:443", Auth: Auth{Type: "bearer", Token: "T"}},
	}
	r, _ := MatchService("api.stripe.com", "/v1/charges", services)
	if r == nil {
		t.Fatal("expected port-stripped service host to match")
	}
}

// --- ValidateSlug tests ---

func TestValidateSlugHappyPath(t *testing.T) {
	for _, name := range []string{"abc", "slack-com", "slack-com-api-apps-connections", "a1-b2-c3"} {
		if err := ValidateSlug(name); err != nil {
			t.Errorf("ValidateSlug(%q) unexpected error: %v", name, err)
		}
	}
}

func TestValidateSlugRejects(t *testing.T) {
	cases := []struct{ name, in string }{
		{"empty", ""},
		{"too short", "ab"},
		{"too long", strings.Repeat("a", 65)},
		{"uppercase", "Slack-Com"},
		{"underscore", "slack_com"},
		{"dot", "slack.com"},
		{"slash", "slack/com"},
		{"leading hyphen", "-foo"},
		{"trailing hyphen", "foo-"},
		{"consecutive hyphens", "foo--bar"},
		{"only hyphens", "---"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateSlug(tc.in); err == nil {
				t.Fatalf("expected error for %q", tc.in)
			}
		})
	}
}

// --- ValidatePath tests ---

func TestValidatePathHappyPath(t *testing.T) {
	for _, p := range []string{"", "/", "/api/*", "/api/apps.connections.*", "/v1/customers/cus_*", "/repos/*/issues"} {
		if err := ValidatePath(p); err != nil {
			t.Errorf("ValidatePath(%q) unexpected error: %v", p, err)
		}
	}
}

func TestValidatePathRejects(t *testing.T) {
	cases := []struct{ name, in string }{
		{"missing leading slash", "api/*"},
		{"double star", "/api/**"},
		{"question mark", "/api/?"},
		{"control char", "/api/\x00"},
		{"space", "/api/ foo"},
		{"hash", "/api#frag"},
		{"square bracket", "/api/[a-z]"},
		{"backslash", "/api/\\d"},
		{"pipe", "/a|b"},
		{"too long", "/" + strings.Repeat("a", 256)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidatePath(tc.in); err == nil {
				t.Fatalf("expected error for %q", tc.in)
			}
		})
	}
}

// --- Slugify tests ---

func TestSlugifyDeterministic(t *testing.T) {
	cases := []struct{ host, path, want string }{
		{"slack.com", "/api/apps.connections.*", "slack-com-api-apps-connections"},
		{"slack.com", "/api/*", "slack-com-api"},
		{"slack.com", "", "slack-com"},
		{"*.github.com", "/repos/*", "github-com-repos"},
		{"api.stripe.com", "", "api-stripe-com"},
		// Uppercase host gets lowercased.
		{"API.STRIPE.COM", "", "api-stripe-com"},
		// Very short host pads up.
		{"x", "", "x-svc"},
		// Root-literal path must not collide with empty (catch-all) path:
		// match semantics differ, so the slugs must differ too.
		{"slack.com", "/", "slack-com-root"},
		{"slack.com", "/*", "slack-com-root"},
	}
	for _, tc := range cases {
		t.Run(tc.host+tc.path, func(t *testing.T) {
			got := Slugify(tc.host, tc.path)
			if got != tc.want {
				t.Fatalf("Slugify(%q, %q) = %q, want %q", tc.host, tc.path, got, tc.want)
			}
			if err := ValidateSlug(got); err != nil {
				t.Fatalf("Slugify(%q, %q) produced invalid slug %q: %v", tc.host, tc.path, got, err)
			}
		})
	}
}

// --- NormalizeServices tests ---

func TestNormalizeServicesBackfillsNames(t *testing.T) {
	in := []Service{
		{Host: "slack.com", Path: "/api/*", Auth: Auth{Type: "bearer", Token: "T1"}},
		{Host: "slack.com", Path: "/api/apps.connections.*", Auth: Auth{Type: "bearer", Token: "T2"}},
	}
	out := NormalizeServices(in)
	if out[0].Name != "slack-com-api" {
		t.Errorf("services[0].Name = %q, want slack-com-api", out[0].Name)
	}
	if out[1].Name != "slack-com-api-apps-connections" {
		t.Errorf("services[1].Name = %q, want slack-com-api-apps-connections", out[1].Name)
	}
	// Idempotent: second pass leaves names alone.
	out2 := NormalizeServices(out)
	if out2[0].Name != out[0].Name || out2[1].Name != out[1].Name {
		t.Fatal("NormalizeServices not idempotent")
	}
}

func TestNormalizeServicesPreservesExplicitNames(t *testing.T) {
	in := []Service{
		{Name: "slack-bot", Host: "slack.com", Path: "/api/*", Auth: Auth{Type: "bearer", Token: "T1"}},
		{Host: "slack.com", Path: "/api/apps.connections.*", Auth: Auth{Type: "bearer", Token: "T2"}},
	}
	out := NormalizeServices(in)
	if out[0].Name != "slack-bot" {
		t.Errorf("explicit name overwritten: got %q", out[0].Name)
	}
	if out[1].Name != "slack-com-api-apps-connections" {
		t.Errorf("services[1].Name = %q", out[1].Name)
	}
}

func TestNormalizeServicesResolvesCollisions(t *testing.T) {
	in := []Service{
		// Same (host, path) → same Slugify output → second must get -2 suffix.
		{Host: "slack.com", Path: "/api/*", Auth: Auth{Type: "bearer", Token: "T1"}},
		{Host: "slack.com", Path: "/api/*", Auth: Auth{Type: "bearer", Token: "T2"}},
	}
	out := NormalizeServices(in)
	if out[0].Name == out[1].Name {
		t.Fatalf("expected unique names, got both %q", out[0].Name)
	}
	if out[1].Name != "slack-com-api-2" {
		t.Errorf("services[1].Name = %q, want slack-com-api-2", out[1].Name)
	}
}

func TestNormalizeServicesAvoidsClashWithExplicit(t *testing.T) {
	// An explicit name reserves itself first, so an auto-generated slug
	// that would have collided gets a suffix.
	in := []Service{
		{Host: "slack.com", Path: "/api/*", Auth: Auth{Type: "bearer", Token: "T1"}},
		{Name: "slack-com-api", Host: "other.com", Auth: Auth{Type: "bearer", Token: "T2"}},
	}
	out := NormalizeServices(in)
	if out[0].Name == "slack-com-api" {
		t.Fatal("auto-generated name should not collide with explicit name")
	}
	if out[0].Name != "slack-com-api-2" {
		t.Errorf("services[0].Name = %q, want slack-com-api-2", out[0].Name)
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
			{Name: "stripe", Host: "api.stripe.com", Auth: Auth{Type: "bearer", Token: "STRIPE_KEY"}},
			{Name: "ashby", Host: "api.ashby.com", Auth: Auth{Type: "basic", Username: "ASHBY_KEY"}},
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
			{Name: "stripe", Host: "api.stripe.com", Auth: Auth{Type: "bearer"}}, // missing token
		},
	}
	if err := Validate(cfg); err == nil {
		t.Fatal("expected error for invalid auth")
	}
}

func TestValidateConfigRejectsMissingName(t *testing.T) {
	cfg := &Config{
		Vault: "default",
		Services: []Service{
			{Host: "api.stripe.com", Auth: Auth{Type: "bearer", Token: "STRIPE_KEY"}},
		},
	}
	if err := Validate(cfg); err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestValidateConfigRejectsDuplicateNames(t *testing.T) {
	cfg := &Config{
		Vault: "default",
		Services: []Service{
			{Name: "slack", Host: "slack.com", Path: "/api/*", Auth: Auth{Type: "bearer", Token: "T1"}},
			{Name: "slack", Host: "slack.com", Path: "/api/apps.connections.*", Auth: Auth{Type: "bearer", Token: "T2"}},
		},
	}
	if err := Validate(cfg); err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestValidateConfigRejectsHostWithSlash(t *testing.T) {
	cfg := &Config{
		Vault: "default",
		Services: []Service{
			{Name: "slack", Host: "slack.com/api/*", Auth: Auth{Type: "bearer", Token: "T"}},
		},
	}
	if err := Validate(cfg); err == nil {
		t.Fatal("expected error for host containing /")
	}
}

func TestValidateConfigInvalidPath(t *testing.T) {
	cfg := &Config{
		Vault: "default",
		Services: []Service{
			{Name: "slack", Host: "slack.com", Path: "api/*", Auth: Auth{Type: "bearer", Token: "T"}},
		},
	}
	if err := Validate(cfg); err == nil {
		t.Fatal("expected error for path missing leading /")
	}
}

// --- ValidateHost tests ---

func TestValidateHostHappyPath(t *testing.T) {
	for _, h := range []string{"api.stripe.com", "*.github.com", "sub.api.example.com"} {
		if err := ValidateHost(h); err != nil {
			t.Errorf("ValidateHost(%q) unexpected error: %v", h, err)
		}
	}
}

func TestValidateHostRejectsIP(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "10.0.0.1", "::1", "192.168.1.1"} {
		if err := ValidateHost(h); err == nil {
			t.Errorf("ValidateHost(%q) expected error", h)
		}
	}
}

func TestValidateHostRejectsInternalNames(t *testing.T) {
	t.Setenv("AGENT_VAULT_DEV_MODE", "")
	for _, h := range []string{"localhost", "kubernetes.default", "metadata.google.internal"} {
		if err := ValidateHost(h); err == nil {
			t.Errorf("ValidateHost(%q) expected error in non-dev mode", h)
		}
	}
}

func TestValidateHostAllowsInternalInDevMode(t *testing.T) {
	// Single-label names always fail hostLabelPattern. The dev-mode
	// override is for multi-label internal names like
	// localhost.localdomain — which pass the format check but are
	// blocked by default to dodge SSRF against cloud-metadata hosts.
	t.Setenv("AGENT_VAULT_DEV_MODE", "true")
	if err := ValidateHost("localhost.localdomain"); err != nil {
		t.Errorf("ValidateHost(localhost.localdomain) in dev mode: %v", err)
	}
}

func TestValidateHostRejectsBareWildcardAndShallow(t *testing.T) {
	for _, h := range []string{"*", "*.com", "*.example"} {
		if err := ValidateHost(h); err == nil {
			t.Errorf("ValidateHost(%q) expected error", h)
		}
	}
}

// TestValidateConfigEnforcesHostSafety pins that the direct upsert path
// (broker.Validate) now rejects IP addresses and internal hosts — the
// proposal flow has always done this, but admins doing a direct POST
// to /v1/vaults/{name}/services used to slip through.
func TestValidateConfigEnforcesHostSafety(t *testing.T) {
	t.Setenv("AGENT_VAULT_DEV_MODE", "")
	cases := []struct{ name, host string }{
		{"ip", "10.0.0.5"},
		{"localhost", "localhost"},
		{"metadata", "metadata.google.internal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Vault: "default",
				Services: []Service{
					{Name: "svc", Host: tc.host, Auth: Auth{Type: "bearer", Token: "K"}},
				},
			}
			if err := Validate(cfg); err == nil {
				t.Fatalf("expected Validate to reject host %q", tc.host)
			}
		})
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
			{Name: "example", Host: "api.example.com", Auth: Auth{Type: "passthrough"}},
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
