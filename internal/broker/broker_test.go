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
	r, score := MatchService("api.stripe.com", 0, "/v1/charges", services)
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
		r, score := MatchService(host, 0, "/", services)
		if r == nil {
			t.Fatalf("expected match for %s", host)
		}
		if score.HostTier != HostTierWildcard {
			t.Fatalf("expected wildcard tier for %s, got %d", host, score.HostTier)
		}
	}
	// Should not match bare "github.com"
	if r, _ := MatchService("github.com", 0, "/", services); r != nil {
		t.Fatal("did not expect match for github.com")
	}
}

func TestMatchServiceNoMatch(t *testing.T) {
	services := []Service{
		{Name: "stripe", Host: "api.stripe.com", Auth: Auth{Type: "bearer", Token: "STRIPE_KEY"}},
	}
	if r, _ := MatchService("evil.com", 0, "/", services); r != nil {
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
	r, _ := MatchService("slack.com", 0, "/api/apps.connections.open", services)
	if r == nil || r.Name != "slack-conn" {
		t.Fatalf("expected slack-conn (longer literal prefix), got %+v", r)
	}
	r, _ = MatchService("slack.com", 0, "/api/chat.postMessage", services)
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
	r, score := MatchService("api.slack.com", 0, "/api/apps.connections.open", services)
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
	r, _ := MatchService("slack.com", 0, "/api/foo/bar/baz", services)
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
	r, score := MatchService("api.example.com", 0, "/v1/users", services)
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
	r, _ := MatchService("slack.com", 0, "/api/foo", services)
	if r == nil || r.Name != "scoped" {
		t.Fatalf("expected scoped rule to win when path matches, got %+v", r)
	}
	// Path does NOT match the scoped rule → catch-all wins.
	r, _ = MatchService("slack.com", 0, "/oauth/v2/authorize", services)
	if r == nil || r.Name != "catchall" {
		t.Fatalf("expected catchall rule when scoped path doesn't match, got %+v", r)
	}
}

func TestMatchServicePortStripped(t *testing.T) {
	port := 443
	services := []Service{
		{Name: "legacy", Host: "api.stripe.com", Port: &port, Auth: Auth{Type: "bearer", Token: "T"}},
	}
	r, _ := MatchService("api.stripe.com", 443, "/v1/charges", services)
	if r == nil {
		t.Fatal("expected port-specific service to match")
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

func TestSlugify(t *testing.T) {
	cases := []struct {
		name, host, path, want string
	}{
		{"plain host", "api.anthropic.com", "", "api-anthropic-com"},
		{"host plus path", "slack.com", "/api/*", "slack-com-api"},
		{"host plus literal path", "slack.com", "/api/apps.connections.*", "slack-com-api-apps-connections"},
		{"wildcard host", "*.github.com", "", "github-com"},
		{"wildcard host with path", "*.github.com", "/repos/*", "github-com-repos"},
		{"underscores in path", "api.example.com", "/v1/foo_bar", "api-example-com-v1-foo-bar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Slugify(tc.host, tc.path, nil)
			if got != tc.want {
				t.Fatalf("Slugify(%q, %q) = %q, want %q", tc.host, tc.path, got, tc.want)
			}
			if err := ValidateSlug(got); err != nil {
				t.Fatalf("Slugify output %q failed ValidateSlug: %v", got, err)
			}
		})
	}
}

func TestSlugifyTruncatesAndStaysValid(t *testing.T) {
	long := strings.Repeat("a.", 100) + "com"
	got := Slugify(long, "", nil)
	if len(got) > 64 {
		t.Fatalf("expected truncation, got %d chars", len(got))
	}
	if err := ValidateSlug(got); err != nil {
		t.Fatalf("truncated slug %q failed ValidateSlug: %v", got, err)
	}
}

func TestAssignSlugNamesFillsAndDisambiguates(t *testing.T) {
	svcs := []Service{
		{Host: "api.anthropic.com"},
		{Host: "slack.com", Path: "/api/*"},
		{Host: "slack.com", Path: "/api/apps.connections.*"},
		{Name: "explicit", Host: "github.com"},
		{Host: "api.anthropic.com"}, // collides with svcs[0]; expect -2 suffix
	}
	AssignSlugNames(svcs)

	want := []string{
		"api-anthropic-com",
		"slack-com-api",
		"slack-com-api-apps-connections",
		"explicit",
		"api-anthropic-com-2",
	}
	for i, w := range want {
		if svcs[i].Name != w {
			t.Errorf("svcs[%d].Name = %q, want %q", i, svcs[i].Name, w)
		}
	}
}

func TestAssignSlugNamesLeavesExplicitUntouched(t *testing.T) {
	svcs := []Service{{Name: "custom-name", Host: "api.anthropic.com"}}
	AssignSlugNames(svcs)
	if svcs[0].Name != "custom-name" {
		t.Fatalf("expected explicit name to survive, got %q", svcs[0].Name)
	}
}

func TestDisambiguateSlug(t *testing.T) {
	taken := map[string]bool{"foo": true, "foo-2": true}
	if got := DisambiguateSlug("foo", taken); got != "foo-3" {
		t.Fatalf("expected foo-3, got %q", got)
	}
	if got := DisambiguateSlug("bar", taken); got != "bar" {
		t.Fatalf("expected unique base to pass through, got %q", got)
	}
}

// TestAssignSlugNamesAvoidingAdoptsByHostPath pins that an empty-Name
// incoming whose (Host, Path) uniquely matches an existing entry
// adopts that entry's Name instead of auto-slugging.
func TestAssignSlugNamesAvoidingAdoptsByHostPath(t *testing.T) {
	existing := []Service{{Name: "stripe-prod", Host: "api.stripe.com"}}
	incoming := []Service{{Host: "api.stripe.com"}}
	AssignSlugNamesAvoiding(incoming, existing)
	if incoming[0].Name != "stripe-prod" {
		t.Fatalf("expected adopted Name=stripe-prod, got %q", incoming[0].Name)
	}
}

// TestAssignSlugNamesAvoidingReservesExistingForCrossHostCollision pins
// the cross-host collision guard: when Slugify maps the incoming Host to
// a slug that already names an unrelated existing service (e.g.
// `github.com` and `*.github.com` both yield `github-com`), the auto-
// slug lands on a -2 suffix instead of silently replacing.
func TestAssignSlugNamesAvoidingReservesExistingForCrossHostCollision(t *testing.T) {
	existing := []Service{{Name: "github-com", Host: "*.github.com"}}
	incoming := []Service{{Host: "github.com"}}
	AssignSlugNamesAvoiding(incoming, existing)
	if incoming[0].Name != "github-com-2" {
		t.Fatalf("expected disambiguated Name=github-com-2, got %q", incoming[0].Name)
	}
}

// TestAssignSlugNamesAvoidingAmbiguousHostPathFallsThrough pins that an
// ambiguous (Host, Path) — 2+ existing matches with distinct Names —
// skips the adoption branch and the entry takes the auto-slug path
// instead. broker.Validate's duplicate-Name check does not catch this
// shape (different Names, same Host), so the helper's hpCount>1 guard
// is the load-bearing defense.
func TestAssignSlugNamesAvoidingAmbiguousHostPathFallsThrough(t *testing.T) {
	existing := []Service{
		{Name: "stripe-a", Host: "api.stripe.com"},
		{Name: "stripe-b", Host: "api.stripe.com"},
	}
	incoming := []Service{{Host: "api.stripe.com"}}
	AssignSlugNamesAvoiding(incoming, existing)
	// Adoption is skipped; auto-slug to api-stripe-com (neither
	// stripe-a nor stripe-b collides with that slug).
	if incoming[0].Name != "api-stripe-com" {
		t.Fatalf("expected fallthrough Name=api-stripe-com, got %q", incoming[0].Name)
	}
}

// TestAssignSlugNamesAvoidingNilExistingMatchesAssignSlugNames pins that
// passing nil existing reproduces the intra-slice-only behavior of the
// original AssignSlugNames.
func TestAssignSlugNamesAvoidingNilExistingMatchesAssignSlugNames(t *testing.T) {
	svcs := []Service{
		{Host: "api.anthropic.com"},
		{Host: "api.anthropic.com"},
	}
	AssignSlugNamesAvoiding(svcs, nil)
	if svcs[0].Name != "api-anthropic-com" || svcs[1].Name != "api-anthropic-com-2" {
		t.Fatalf("expected api-anthropic-com and api-anthropic-com-2, got %q / %q", svcs[0].Name, svcs[1].Name)
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

func TestValidateSubstitutionsAcceptsBodySurface(t *testing.T) {
	s := Service{Host: "api.example.com", Substitutions: []Substitution{
		{Key: "K_X", Placeholder: "__sid__", In: []string{"body"}},
	}}
	if err := s.ValidateSubstitutions(); err != nil {
		t.Fatalf("body surface should be valid: %v", err)
	}
}

func TestValidateSubstitutionsAcceptsWebsocketSurface(t *testing.T) {
	s := Service{Host: "api.example.com", Substitutions: []Substitution{
		{Key: "K_X", Placeholder: "__sid__", In: []string{"websocket"}},
	}}
	if err := s.ValidateSubstitutions(); err != nil {
		t.Fatalf("websocket surface should be valid: %v", err)
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

func TestAnyHostMatches(t *testing.T) {
	services := []Service{
		{Host: "api.stripe.com", Auth: Auth{Type: "bearer", Token: "K"}},
		{Host: "*.github.com", Auth: Auth{Type: "bearer", Token: "K"}},
		{Host: "slack.com", Path: "/api/*", Auth: Auth{Type: "bearer", Token: "K"}},
	}

	tests := []struct {
		host string
		want bool
	}{
		{"api.stripe.com", true},
		{"api.github.com", true},
		{"raw.github.com", true},
		{"github.com", false},
		{"a.b.github.com", false},
		{"slack.com", true},
		{"api.unknown.com", false},
		{"example.com", false},
	}
	for _, tt := range tests {
		got := AnyHostMatches(tt.host, services)
		if got != tt.want {
			t.Errorf("AnyHostMatches(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}

	// Nil services: nothing matches.
	if AnyHostMatches("anything.com", nil) {
		t.Error("AnyHostMatches with nil services should return false")
	}
}

// --- Helper ---

func intPtr(v int) *int { return &v }

// --- Port-specific MatchService tests ---

func TestMatchServicePortExactMatch(t *testing.T) {
	services := []Service{
		{Name: "svc", Host: "api.example.com", Port: intPtr(8080), Auth: Auth{Type: "bearer", Token: "T"}},
	}
	r, _ := MatchService("api.example.com", 8080, "/", services)
	if r == nil {
		t.Fatal("expected port-specific service to match when port matches")
	}
}

func TestMatchServicePortMismatch(t *testing.T) {
	services := []Service{
		{Name: "svc", Host: "api.example.com", Port: intPtr(8080), Auth: Auth{Type: "bearer", Token: "T"}},
	}
	r, _ := MatchService("api.example.com", 9090, "/", services)
	if r != nil {
		t.Fatal("expected no match when port does not match")
	}
}

func TestMatchServicePortNilMatchesAny(t *testing.T) {
	services := []Service{
		{Name: "svc", Host: "api.example.com", Auth: Auth{Type: "bearer", Token: "T"}},
	}
	r, _ := MatchService("api.example.com", 443, "/", services)
	if r == nil {
		t.Fatal("expected Port=nil service to match any target port")
	}
}

func TestMatchServicePortSpecificBeatsWildcard(t *testing.T) {
	services := []Service{
		{Name: "wildcard-port", Host: "api.example.com", Auth: Auth{Type: "bearer", Token: "T1"}},
		{Name: "specific-port", Host: "api.example.com", Port: intPtr(3000), Auth: Auth{Type: "bearer", Token: "T2"}},
	}
	r, score := MatchService("api.example.com", 3000, "/", services)
	if r == nil || r.Name != "specific-port" {
		t.Fatalf("expected specific-port to win, got %+v", r)
	}
	if !score.PortSpecific {
		t.Fatal("expected PortSpecific=true")
	}
}

func TestMatchServicePortSpecificDoesNotOverrideHostTier(t *testing.T) {
	services := []Service{
		{Name: "exact-host", Host: "api.example.com", Auth: Auth{Type: "bearer", Token: "T1"}},
		{Name: "wildcard-host", Host: "*.example.com", Port: intPtr(3000), Auth: Auth{Type: "bearer", Token: "T2"}},
	}
	r, _ := MatchService("api.example.com", 3000, "/", services)
	if r == nil || r.Name != "exact-host" {
		t.Fatalf("expected exact-host to win (host tier beats port specificity), got %+v", r)
	}
}

func TestMatchServiceTwoPortsSameHost(t *testing.T) {
	services := []Service{
		{Name: "port-3000", Host: "api.example.com", Port: intPtr(3000), Auth: Auth{Type: "bearer", Token: "T1"}},
		{Name: "port-4000", Host: "api.example.com", Port: intPtr(4000), Auth: Auth{Type: "bearer", Token: "T2"}},
	}
	r, _ := MatchService("api.example.com", 3000, "/", services)
	if r == nil || r.Name != "port-3000" {
		t.Fatalf("expected port-3000 for request to port 3000, got %+v", r)
	}
	r, _ = MatchService("api.example.com", 4000, "/", services)
	if r == nil || r.Name != "port-4000" {
		t.Fatalf("expected port-4000 for request to port 4000, got %+v", r)
	}
}

// --- ValidatePort tests ---

func TestValidatePortNil(t *testing.T) {
	if err := ValidatePort(nil); err != nil {
		t.Fatalf("expected nil port to pass, got %v", err)
	}
}

func TestValidatePortValid(t *testing.T) {
	for _, p := range []int{1, 80, 443, 8080, 65535} {
		if err := ValidatePort(intPtr(p)); err != nil {
			t.Errorf("ValidatePort(%d) unexpected error: %v", p, err)
		}
	}
}

func TestValidatePortInvalid(t *testing.T) {
	for _, p := range []int{0, -1, 65536} {
		if err := ValidatePort(intPtr(p)); err == nil {
			t.Errorf("ValidatePort(%d) expected error", p)
		}
	}
}

// --- SplitInlineHost tests ---

func TestSplitInlineHostWithPort(t *testing.T) {
	host, path, port := SplitInlineHost("internal.corp.com:3000/api/*", "")
	if host != "internal.corp.com" {
		t.Fatalf("expected host=internal.corp.com, got %q", host)
	}
	if path != "/api/*" {
		t.Fatalf("expected path=/api/*, got %q", path)
	}
	if port == nil || *port != 3000 {
		t.Fatalf("expected port=3000, got %v", port)
	}
}

func TestSplitInlineHostPortOnly(t *testing.T) {
	host, path, port := SplitInlineHost("internal.corp.com:3000", "")
	if host != "internal.corp.com" {
		t.Fatalf("expected host=internal.corp.com, got %q", host)
	}
	if path != "" {
		t.Fatalf("expected path=\"\", got %q", path)
	}
	if port == nil || *port != 3000 {
		t.Fatalf("expected port=3000, got %v", port)
	}
}

func TestSplitInlineHostNoPort(t *testing.T) {
	host, path, port := SplitInlineHost("api.stripe.com", "")
	if host != "api.stripe.com" {
		t.Fatalf("expected host=api.stripe.com, got %q", host)
	}
	if path != "" {
		t.Fatalf("expected path=\"\", got %q", path)
	}
	if port != nil {
		t.Fatalf("expected port=nil, got %v", port)
	}
}

func TestSplitInlineHostExistingPath(t *testing.T) {
	host, path, port := SplitInlineHost("api.stripe.com:8080", "/v1/*")
	if host != "api.stripe.com" {
		t.Fatalf("expected host=api.stripe.com, got %q", host)
	}
	if path != "/v1/*" {
		t.Fatalf("expected path=/v1/*, got %q", path)
	}
	if port == nil || *port != 8080 {
		t.Fatalf("expected port=8080, got %v", port)
	}
}

// --- MatcherPattern tests ---

func TestMatcherPatternWithPort(t *testing.T) {
	s := Service{Host: "internal.corp.com", Port: intPtr(3000), Path: "/api/*"}
	got := s.MatcherPattern()
	want := "internal.corp.com:3000/api/*"
	if got != want {
		t.Fatalf("MatcherPattern() = %q, want %q", got, want)
	}
}

func TestMatcherPatternWithoutPort(t *testing.T) {
	s := Service{Host: "api.stripe.com", Path: "/v1/*"}
	got := s.MatcherPattern()
	want := "api.stripe.com/v1/*"
	if got != want {
		t.Fatalf("MatcherPattern() = %q, want %q", got, want)
	}
}

// --- Slugify with port ---

func TestSlugifyWithPort(t *testing.T) {
	withPort := Slugify("api.example.com", "/api/*", intPtr(8443))
	withoutPort := Slugify("api.example.com", "/api/*", nil)
	if withPort == withoutPort {
		t.Fatalf("expected distinct slugs, both produced %q", withPort)
	}
	if err := ValidateSlug(withPort); err != nil {
		t.Fatalf("slug with port %q failed ValidateSlug: %v", withPort, err)
	}
}

// --- NormalizePort tests ---

func TestNormalizePortExtractsFromHost(t *testing.T) {
	svc := Service{Host: "internal.corp.com:3000"}
	if err := NormalizePort(&svc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc.Host != "internal.corp.com" {
		t.Fatalf("expected host=internal.corp.com, got %q", svc.Host)
	}
	if svc.Port == nil || *svc.Port != 3000 {
		t.Fatalf("expected port=3000, got %v", svc.Port)
	}
}

func TestNormalizePortConflictErrors(t *testing.T) {
	svc := Service{Host: "internal.corp.com:3000", Port: intPtr(4000)}
	if err := NormalizePort(&svc); err == nil {
		t.Fatal("expected error for conflicting port")
	}
}

func TestNormalizePortAgreementOK(t *testing.T) {
	svc := Service{Host: "internal.corp.com:3000", Port: intPtr(3000)}
	if err := NormalizePort(&svc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc.Port == nil || *svc.Port != 3000 {
		t.Fatalf("expected port=3000, got %v", svc.Port)
	}
}

func TestNormalizePortYAMLPortPreserved(t *testing.T) {
	svc := Service{Host: "internal.corp.com", Port: intPtr(3000)}
	if err := NormalizePort(&svc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc.Port == nil || *svc.Port != 3000 {
		t.Fatalf("expected port=3000 preserved, got %v", svc.Port)
	}
}
