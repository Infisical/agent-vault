package broker

import (
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Config represents a vault's broker configuration as stored in YAML files.
type Config struct {
	Vault    string    `yaml:"vault" json:"vault"`
	Services []Service `yaml:"services" json:"services"`
}

// Service defines a credential-attachment rule scoped by host and an
// optional URL path glob. Name is the canonical per-vault identifier
// (slug) used by the proposal merge index, the HTTP API, and the SDK;
// Host + Path are the matcher key consumed by MatchService.
//
// At every entrypoint (HTTP API, CLI, SDK, YAML config) the matcher is
// set via Host alone — Host accepts a bare hostname, a one-level
// wildcard (`*.github.com`), or an inline path-scoped form
// (`slack.com/api/*`). Ingest splits the inline form into Host + Path
// before validation, so the stored Host never contains "/". Reads
// expose Host and Path separately for inspection.
//
// Path may contain a single greedy `*` glob (cross-`/`); see
// ValidatePath for the format and MatchService for the prioritization
// rules. An empty Path is a catch-all on the host.
//
// Enabled is a nullable toggle. nil means "not set" and is treated as
// enabled so existing persisted services (which predate this field) stay
// live after upgrade. Callers should use IsEnabled() rather than
// dereferencing the pointer.
type Service struct {
	Name          string         `yaml:"name" json:"name"`
	Host          string         `yaml:"host" json:"host"`
	Path          string         `yaml:"path,omitempty" json:"path,omitempty"`
	Enabled       *bool          `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Auth          Auth           `yaml:"auth" json:"auth"`
	Substitutions []Substitution `yaml:"substitutions,omitempty" json:"substitutions,omitempty"`
}

// Substitution declares a placeholder string the broker rewrites with a
// credential value at request time, scanned only on surfaces listed in
// In — that scoping is the security boundary.
type Substitution struct {
	Key         string   `yaml:"key" json:"key"`
	Placeholder string   `yaml:"placeholder" json:"placeholder"`
	In          []string `yaml:"in,omitempty" json:"in,omitempty"`
}

// IsEnabled reports whether the service should serve proxy traffic. A
// nil Enabled field (missing from the stored JSON) is treated as enabled
// so services persisted before this field existed stay live after upgrade.
func (s *Service) IsEnabled() bool {
	return s.Enabled == nil || *s.Enabled
}

// Auth describes how credentials are attached for a broker service.
// Each service must specify a Type and the fields relevant to that type.
//
// The "passthrough" type is a special case: no credential is looked up
// and no credential is injected. The host is allowlisted, and the
// client's request headers flow through (minus broker-scoped headers
// like X-Vault and Proxy-Authorization, and hop-by-hop headers).
type Auth struct {
	Type string `yaml:"type" json:"type"` // "bearer", "basic", "api-key", "custom", "passthrough"

	// type: bearer — token credential key
	Token string `yaml:"token,omitempty" json:"token,omitempty"`

	// type: basic — username (required), password (optional, defaults to empty)
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	Password string `yaml:"password,omitempty" json:"password,omitempty"`

	// type: api-key — key credential, header name (default "Authorization"), optional prefix
	Key    string `yaml:"key,omitempty" json:"key,omitempty"`
	Header string `yaml:"header,omitempty" json:"header,omitempty"`
	Prefix string `yaml:"prefix,omitempty" json:"prefix,omitempty"`

	// type: custom — arbitrary header templates with {{ CREDENTIAL }} placeholders
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
}

// SupportedAuthTypes lists the valid auth type values.
var SupportedAuthTypes = []string{"bearer", "basic", "api-key", "custom", "passthrough"}

// CredentialKeyPattern validates credential key names: UPPER_SNAKE_CASE.
var CredentialKeyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// SubstitutionSurfaces lists the surfaces a substitution may declare in
// its In list. "body" is reserved for a future version.
var SubstitutionSurfaces = []string{"path", "query", "header"}

// DefaultSubstitutionSurfaces is applied when a substitution omits In.
// "header" is a deliberate opt-in (CRLF guard required) so it is not
// in the default set.
var DefaultSubstitutionSurfaces = []string{"path", "query"}

// placeholderCharAllowed reports whether c may appear inside a
// substitution placeholder. Restricted to RFC 3986 unreserved
// characters so encoded and decoded forms are identical — the runtime
// can match on the wire-encoded path without encoding round-trips.
func placeholderCharAllowed(c byte) bool {
	return placeholderWordChar(c) || c == '-' || c == '.' || c == '~'
}

// placeholderWordChar reports whether c is a word-class character
// inside a placeholder: alphanumeric or underscore. Used by the
// boundary check in validatePlaceholder.
func placeholderWordChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

// Validate checks that an Auth configuration is well-formed and returns
// descriptive errors that help agents self-correct.
func (a *Auth) Validate() error {
	if a.Type == "" {
		return fmt.Errorf("auth: type is required (supported: %s)", strings.Join(SupportedAuthTypes, ", "))
	}

	switch a.Type {
	case "bearer":
		if a.Token == "" {
			return fmt.Errorf("auth: \"token\" is required for bearer auth")
		}
		if err := checkUnexpectedFields(a, "bearer", "token"); err != nil {
			return err
		}
		return validateCredentialKey("token", a.Token)

	case "basic":
		if a.Username == "" {
			return fmt.Errorf("auth: \"username\" is required for basic auth")
		}
		if err := checkUnexpectedFields(a, "basic", "username", "password"); err != nil {
			return err
		}
		if err := validateCredentialKey("username", a.Username); err != nil {
			return err
		}
		if a.Password != "" {
			if err := validateCredentialKey("password", a.Password); err != nil {
				return err
			}
		}
		return nil

	case "api-key":
		if a.Key == "" {
			return fmt.Errorf("auth: \"key\" is required for api-key auth")
		}
		if err := checkUnexpectedFields(a, "api-key", "key", "header", "prefix"); err != nil {
			return err
		}
		return validateCredentialKey("key", a.Key)

	case "custom":
		if len(a.Headers) == 0 {
			return fmt.Errorf("auth: \"headers\" is required for custom auth")
		}
		if err := checkUnexpectedFields(a, "custom", "headers"); err != nil {
			return err
		}
		// Validate header names and placeholder references.
		headerNamePattern := regexp.MustCompile(`^[a-zA-Z0-9-]+$`)
		for name, val := range a.Headers {
			if !headerNamePattern.MatchString(name) {
				return fmt.Errorf("auth: invalid header name %q — only letters, digits, and hyphens allowed", name)
			}
			// Validate that {{ KEY }} placeholders reference valid UPPER_SNAKE_CASE keys.
			matches := CredentialRef.FindAllStringSubmatch(val, -1)
			for _, m := range matches {
				if len(m) >= 2 {
					if !CredentialKeyPattern.MatchString(m[1]) {
						return fmt.Errorf("auth: invalid credential key %q in header %q — must be UPPER_SNAKE_CASE", m[1], name)
					}
				}
			}
		}
		return nil

	case "passthrough":
		// Passthrough forwards client headers unchanged and injects nothing.
		// No credential fields are permitted.
		return checkUnexpectedFields(a, "passthrough")

	default:
		return fmt.Errorf("auth: unsupported type %q (supported: %s)", a.Type, strings.Join(SupportedAuthTypes, ", "))
	}
}

// validateCredentialKey checks that a credential key name is UPPER_SNAKE_CASE.
func validateCredentialKey(field, key string) error {
	if !CredentialKeyPattern.MatchString(key) {
		return fmt.Errorf("auth: %s %q must be UPPER_SNAKE_CASE (e.g. STRIPE_KEY)", field, key)
	}
	return nil
}

// checkUnexpectedFields reports if fields not belonging to this auth type are set.
func checkUnexpectedFields(a *Auth, authType string, allowed ...string) error {
	allowedSet := make(map[string]bool, len(allowed))
	for _, f := range allowed {
		allowedSet[f] = true
	}

	type fieldCheck struct {
		name  string
		isSet bool
	}
	checks := []fieldCheck{
		{"token", a.Token != ""},
		{"username", a.Username != ""},
		{"password", a.Password != ""},
		{"key", a.Key != ""},
		{"header", a.Header != ""},
		{"prefix", a.Prefix != ""},
		{"headers", len(a.Headers) > 0},
	}

	for _, c := range checks {
		if c.isSet && !allowedSet[c.name] {
			if len(allowed) == 0 {
				return fmt.Errorf("auth: unexpected field %q for %s auth (no credential fields are permitted)",
					c.name, authType)
			}
			return fmt.Errorf("auth: unexpected field %q for %s auth (only %s)",
				c.name, authType, strings.Join(allowed, ", "))
		}
	}
	return nil
}

// CredentialKeys returns all credential key names referenced by this auth config.
// Passthrough services reference no credentials and return nil.
func (a *Auth) CredentialKeys() []string {
	switch a.Type {
	case "bearer":
		return []string{a.Token}
	case "basic":
		keys := []string{a.Username}
		if a.Password != "" {
			keys = append(keys, a.Password)
		}
		return keys
	case "api-key":
		return []string{a.Key}
	case "custom":
		return credentialKeysFromHeaders(a.Headers)
	case "passthrough":
		return nil
	default:
		return nil
	}
}

// credentialKeysFromHeaders extracts credential key names from {{ KEY }} templates in header values.
func credentialKeysFromHeaders(headers map[string]string) []string {
	seen := make(map[string]bool)
	var keys []string
	for _, v := range headers {
		matches := CredentialRef.FindAllStringSubmatch(v, -1)
		for _, m := range matches {
			if len(m) >= 2 && !seen[m[1]] {
				keys = append(keys, m[1])
				seen[m[1]] = true
			}
		}
	}
	return keys
}

// Resolve resolves the auth config into a map of HTTP headers ready for attachment.
// The getCredential function retrieves decrypted credential values by key name.
func (a *Auth) Resolve(getCredential func(key string) (string, error)) (map[string]string, error) {
	switch a.Type {
	case "bearer":
		val, err := getCredential(a.Token)
		if err != nil {
			return nil, err
		}
		return map[string]string{"Authorization": "Bearer " + val}, nil

	case "basic":
		user, err := getCredential(a.Username)
		if err != nil {
			return nil, err
		}
		pass := ""
		if a.Password != "" {
			pass, err = getCredential(a.Password)
			if err != nil {
				return nil, err
			}
		}
		encoded := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		return map[string]string{"Authorization": "Basic " + encoded}, nil

	case "api-key":
		val, err := getCredential(a.Key)
		if err != nil {
			return nil, err
		}
		header := a.Header
		if header == "" {
			header = "Authorization"
		}
		return map[string]string{header: a.Prefix + val}, nil

	case "custom":
		return resolveHeaders(a.Headers, getCredential)

	case "passthrough":
		// Passthrough injects nothing. Callers should branch on the service
		// type before reaching Resolve; this return is defensive.
		return nil, nil

	default:
		return nil, fmt.Errorf("unsupported auth type %q", a.Type)
	}
}

// Validate checks that a broker config is well-formed. Name is required
// and unique per vault; callers that accept input without a name must
// run NormalizeServices first to backfill from Slugify(Host, Path).
func Validate(cfg *Config) error {
	if cfg.Vault == "" {
		return fmt.Errorf("vault is required")
	}
	nameSet := make(map[string]int, len(cfg.Services))
	for i, s := range cfg.Services {
		if s.Host == "" {
			return fmt.Errorf("service %d: host is required", i)
		}
		if strings.Contains(s.Host, "/") {
			return fmt.Errorf("service %d: host %q must not contain %q after ingest (entry should have been split into host + path)", i, s.Host, "/")
		}
		if s.Name == "" {
			return fmt.Errorf("service %d: name is required", i)
		}
		if err := ValidateSlug(s.Name); err != nil {
			return fmt.Errorf("service %d: %w", i, err)
		}
		if prev, dup := nameSet[s.Name]; dup {
			return fmt.Errorf("service %d: duplicate name %q (also at service %d)", i, s.Name, prev)
		}
		nameSet[s.Name] = i
		if err := ValidatePath(s.Path); err != nil {
			return fmt.Errorf("service %d: %w", i, err)
		}
		if err := s.Auth.Validate(); err != nil {
			return fmt.Errorf("service %d: %w", i, err)
		}
		if err := s.ValidateSubstitutions(); err != nil {
			return fmt.Errorf("service %d: %w", i, err)
		}
	}
	return nil
}

// ValidateSubstitutions checks each substitution for length, character
// set, surface allowlist, and intra-service uniqueness. Errors recommend
// the __name__ convention by example.
func (s *Service) ValidateSubstitutions() error {
	if len(s.Substitutions) == 0 {
		return nil
	}
	seen := make(map[string]int, len(s.Substitutions))
	for i, sub := range s.Substitutions {
		if sub.Key == "" {
			return fmt.Errorf("substitution %d: \"key\" is required", i)
		}
		if err := validateCredentialKey("key", sub.Key); err != nil {
			return fmt.Errorf("substitution %d: %w", i, err)
		}
		if err := validatePlaceholder(sub.Placeholder); err != nil {
			return fmt.Errorf("substitution %d: %w", i, err)
		}
		if prev, dup := seen[sub.Placeholder]; dup {
			return fmt.Errorf("substitution %d: placeholder %q already declared by substitution %d", i, sub.Placeholder, prev)
		}
		seen[sub.Placeholder] = i
		if err := validateSubstitutionSurfaces(sub.In); err != nil {
			return fmt.Errorf("substitution %d: %w", i, err)
		}
	}
	return nil
}

// validatePlaceholder enforces length, character set, a boundary
// requirement (either "__" or a non-word character) so bare identifiers
// like "account_sid" — which legitimately appear as URL path segments —
// cannot be picked as placeholders, and at least one alphanumeric so
// all-symbol strings like "____" or "~~~~" are rejected.
func validatePlaceholder(p string) error {
	if p == "" {
		return fmt.Errorf("\"placeholder\" is required (recommended convention: __name__)")
	}
	if len(p) < 4 {
		return fmt.Errorf("placeholder %q is too short — must be at least 4 characters (recommended convention: __name__)", p)
	}
	hasBoundary := false
	hasAlnum := false
	for i := 0; i < len(p); i++ {
		c := p[i]
		if !placeholderCharAllowed(c) {
			return fmt.Errorf("placeholder %q contains disallowed character %q — only RFC 3986 unreserved characters [A-Za-z0-9_-.~] are permitted (recommended convention: __name__)", p, c)
		}
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			hasAlnum = true
		}
		if !placeholderWordChar(c) {
			hasBoundary = true
		} else if c == '_' && i+1 < len(p) && p[i+1] == '_' {
			hasBoundary = true
		}
	}
	if !hasAlnum {
		return fmt.Errorf("placeholder %q must contain at least one alphanumeric character (recommended convention: __name__)", p)
	}
	if !hasBoundary {
		return fmt.Errorf("placeholder %q must contain a delimiter — either \"__\" or a character outside [A-Za-z0-9_] — to avoid matching legitimate URL words (recommended convention: __name__)", p)
	}
	return nil
}

// validateSubstitutionSurfaces checks that every entry of in is a known
// surface. Empty is accepted (runtime applies DefaultSubstitutionSurfaces).
func validateSubstitutionSurfaces(in []string) error {
	allowed := map[string]bool{}
	for _, s := range SubstitutionSurfaces {
		allowed[s] = true
	}
	seen := make(map[string]bool, len(in))
	for _, surface := range in {
		if surface == "body" {
			return fmt.Errorf("substitution surface \"body\" is reserved for a future version — pick from %s", strings.Join(SubstitutionSurfaces, ", "))
		}
		if !allowed[surface] {
			return fmt.Errorf("invalid substitution surface %q — must be one of %s", surface, strings.Join(SubstitutionSurfaces, ", "))
		}
		if seen[surface] {
			return fmt.Errorf("substitution surface %q listed more than once", surface)
		}
		seen[surface] = true
	}
	return nil
}

// NormalizedIn returns the surfaces this substitution applies to,
// applying DefaultSubstitutionSurfaces when In is empty. Callers must
// treat the returned slice as read-only.
func (s *Substitution) NormalizedIn() []string {
	if len(s.In) == 0 {
		return DefaultSubstitutionSurfaces
	}
	return s.In
}

// CredentialKeys returns the union of credential keys referenced by
// auth and substitutions, deduplicated, auth keys first.
func (s *Service) CredentialKeys() []string {
	authKeys := s.Auth.CredentialKeys()
	if len(s.Substitutions) == 0 {
		return authKeys
	}
	seen := make(map[string]bool, len(authKeys)+len(s.Substitutions))
	out := make([]string, 0, len(authKeys)+len(s.Substitutions))
	for _, k := range authKeys {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	for _, sub := range s.Substitutions {
		if !seen[sub.Key] {
			seen[sub.Key] = true
			out = append(out, sub.Key)
		}
	}
	return out
}

// CredentialRef matches {{ credential_name }} placeholders in header values.
var CredentialRef = regexp.MustCompile(`\{\{\s*(\w+)\s*\}\}`)

// MatchScore is the deterministic priority tuple emitted by MatchService.
// Returned alongside the matched service so callers (e.g. the debug log
// line in brokercore.Inject) can audit which rule won and why without
// recomputing the comparison.
type MatchScore struct {
	HostTier       int // 2 = exact host, 1 = "*.x.y" wildcard, 0 = no match
	PathLiteralLen int // characters in Path before the first '*'; empty Path scores 0
	DeclOrder      int // index of the matched service in the input slice
}

// Better reports whether s outranks other under MatchService's
// prioritization rules: HostTier first, then PathLiteralLen.
// DeclOrder is intentionally not compared — MatchService relies on
// declaration-order iteration to keep first-match-wins as the implicit
// final tiebreak.
func (s MatchScore) Better(other MatchScore) bool {
	if s.HostTier != other.HostTier {
		return s.HostTier > other.HostTier
	}
	return s.PathLiteralLen > other.PathLiteralLen
}

// HostTierName returns "exact" or "wildcard" for the matched service's
// host tier, or "" when no match was made. Used as a log-friendly
// alternative to the raw int.
func (s MatchScore) HostTierName() string {
	switch s.HostTier {
	case HostTierExact:
		return "exact"
	case HostTierWildcard:
		return "wildcard"
	default:
		return ""
	}
}

// HostTierExact and HostTierWildcard are the only positive HostTier
// values — exposed as named constants for matcher tests and log lines.
const (
	HostTierWildcard = 1
	HostTierExact    = 2
)

// MatchService returns the most specific service matching (host, path),
// or nil when nothing matches. Selection is deterministic:
//
//  1. Host tier first. An exact-host rule always beats a wildcard
//     ("*.x.y") rule, even when the wildcard rule has a longer path.
//  2. Path specificity within a host tier. The longest literal path
//     prefix (characters before the first '*') wins. An empty Path
//     scores 0 (catch-all).
//  3. Declaration order is the final tiebreak — the rule appearing
//     first in services wins on otherwise-equal scores.
//
// host should already be port-stripped by the caller; service Host
// patterns are also compared port-stripped to handle legacy entries.
// path is the request URL path (always begins with "/" — caller
// normalizes). The returned MatchScore is meaningful only when the
// returned *Service is non-nil.
func MatchService(host, path string, services []Service) (*Service, MatchScore) {
	var best *Service
	var bestScore MatchScore
	for i := range services {
		hostTier, hostOK := matchHostPattern(services[i].Host, host)
		if !hostOK {
			continue
		}
		pathLen, pathOK := matchPathGlob(services[i].Path, path)
		if !pathOK {
			continue
		}
		score := MatchScore{HostTier: hostTier, PathLiteralLen: pathLen, DeclOrder: i}
		if best == nil || score.Better(bestScore) {
			best = &services[i]
			bestScore = score
		}
	}
	return best, bestScore
}

// matchHostPattern reports whether pattern matches host and which tier
// the match falls into (HostTierExact > HostTierWildcard). Patterns
// starting with "*." match exactly one subdomain level (e.g.
// "*.github.com" matches "api.github.com" but not "a.b.github.com" or
// the bare "github.com").
func matchHostPattern(pattern, host string) (tier int, ok bool) {
	if h, _, err := net.SplitHostPort(pattern); err == nil {
		pattern = h
	}
	if pattern == host {
		return HostTierExact, true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".github.com"
		if strings.HasSuffix(host, suffix) {
			prefix := strings.TrimSuffix(host, suffix)
			if prefix != "" && !strings.Contains(prefix, ".") {
				return HostTierWildcard, true
			}
		}
	}
	return 0, false
}

// matchPathGlob reports whether pattern matches path and returns the
// literal-prefix length (characters before the first '*'). An empty
// pattern is a catch-all and scores 0. The glob splits on '*' — the
// first segment must prefix path, each interior segment must appear
// in order, and the last segment must suffix what remains. '*' is
// greedy across '/'; see ValidatePath for accepted syntax.
func matchPathGlob(pattern, path string) (literalLen int, ok bool) {
	if pattern == "" {
		return 0, true
	}
	parts := strings.Split(pattern, "*")
	literalLen = len(parts[0])

	if len(parts) == 1 {
		// No glob — pattern must equal path exactly.
		return literalLen, path == pattern
	}

	if !strings.HasPrefix(path, parts[0]) {
		return literalLen, false
	}
	rest := path[len(parts[0]):]
	for j := 1; j < len(parts)-1; j++ {
		idx := strings.Index(rest, parts[j])
		if idx < 0 {
			return literalLen, false
		}
		rest = rest[idx+len(parts[j]):]
	}
	if !strings.HasSuffix(rest, parts[len(parts)-1]) {
		return literalLen, false
	}
	return literalLen, true
}

// ValidateSlug enforces the per-vault identifier rule shared by vault
// names, agent names, and service names: 3–64 chars, lowercase ASCII
// alphanumeric and hyphens only, no leading/trailing hyphen, no
// consecutive hyphens. Slugify enforces the same shape internally via
// trim+collapse, but user/agent-supplied names bypass Slugify and would
// otherwise smuggle in malformed slugs that fail downstream lookups.
func ValidateSlug(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if len(name) < 3 {
		return fmt.Errorf("name %q must be at least 3 characters", name)
	}
	if len(name) > 64 {
		return fmt.Errorf("name %q must be at most 64 characters", name)
	}
	if name[0] == '-' || name[len(name)-1] == '-' {
		return fmt.Errorf("name %q must not start or end with a hyphen", name)
	}
	if strings.Contains(name, "--") {
		return fmt.Errorf("name %q must not contain consecutive hyphens", name)
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return fmt.Errorf("name %q must contain only lowercase letters, digits, and hyphens", name)
		}
	}
	return nil
}

// ValidatePath enforces the path-glob format. An empty path is a
// catch-all (legacy host-only behavior). Non-empty paths must begin
// with "/", be at most 256 characters, contain no "**", "?", control
// characters, whitespace, or other tokens that suggest regex/HTML
// semantics that the matcher does not implement.
func ValidatePath(p string) error {
	if p == "" {
		return nil
	}
	if len(p) > 256 {
		return fmt.Errorf("path %q is too long (max 256 characters)", p)
	}
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("path %q must start with %q", p, "/")
	}
	if strings.Contains(p, "**") {
		return fmt.Errorf("path %q must not contain %q (segment-bounded globs are not supported)", p, "**")
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("path %q must not contain control characters", p)
		}
		switch r {
		case ' ', '?', '#', '[', ']', '\\', '|', '<', '>', '"':
			return fmt.Errorf("path %q must not contain %q", p, r)
		}
	}
	return nil
}

// SplitInlineHost splits a user-friendly inline form like
// `slack.com/api/*` into bare host + path. Returns the inputs unchanged
// when host has no `/` or when path is already populated. Shared by
// every ingest path (CLI flags, YAML loader, HTTP API, proposal flow)
// so writes always normalize to the same (host, path) shape.
func SplitInlineHost(host, path string) (string, string) {
	if path != "" {
		return host, path
	}
	if i := strings.IndexByte(host, '/'); i > 0 {
		return host[:i], host[i:]
	}
	return host, path
}

// Slugify produces a deterministic candidate name from (host, path)
// that satisfies ValidateSlug. Used for auto-naming when a service is
// created without an explicit name and for backfilling legacy services.
// Collision resolution (suffixing -2, -3, ...) is the caller's job —
// see NormalizeServices.
//
// A non-empty path always produces a slug distinct from the empty-path
// (catch-all) slug for the same host: when the path's literal portion
// has no alphanumeric content (e.g. "/" or "/*"), the marker "root" is
// appended so root-literal services don't collide with catch-alls.
func Slugify(host, path string) string {
	h := strings.ToLower(strings.TrimPrefix(host, "*."))

	literal := path
	if star := strings.IndexByte(path, '*'); star >= 0 {
		literal = path[:star]
	}
	hasPathContent := false
	for i := 0; i < len(literal); i++ {
		c := literal[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			hasPathContent = true
			break
		}
	}
	combined := h + literal
	if path != "" && !hasPathContent {
		combined += "root"
	}

	var raw strings.Builder
	raw.Grow(len(combined))
	for i := 0; i < len(combined); i++ {
		c := combined[i]
		switch {
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			raw.WriteByte(c)
		case c >= 'A' && c <= 'Z':
			raw.WriteByte(c + ('a' - 'A'))
		default:
			raw.WriteByte('-')
		}
	}

	// Collapse runs of '-'.
	var collapsed strings.Builder
	collapsed.Grow(raw.Len())
	prevHyphen := false
	for _, c := range raw.String() {
		if c == '-' {
			if !prevHyphen {
				collapsed.WriteRune(c)
			}
			prevHyphen = true
		} else {
			collapsed.WriteRune(c)
			prevHyphen = false
		}
	}

	s := strings.Trim(collapsed.String(), "-")
	if len(s) < 3 {
		s = strings.Trim(s+"-svc", "-")
	}
	if len(s) > 64 {
		s = strings.TrimRight(s[:64], "-")
	}
	if s == "" {
		return "service"
	}
	return s
}

// NormalizeServices returns services with empty Name fields backfilled
// from Slugify(Host, Path), with collision suffixing applied so the
// result has unique names. Idempotent: services that already have a
// name are left untouched (and reserve their name first so
// auto-generated slugs can't collide with user-chosen ones). Pure;
// callers persist the result only when they were already going to write.
//
// Returns the input slice unchanged when every service already has a
// name — the common steady-state path through Inject. Allocates a copy
// only when at least one Name is empty.
func NormalizeServices(services []Service) []Service {
	if services == nil {
		return nil
	}
	needs := false
	for i := range services {
		if services[i].Name == "" {
			needs = true
			break
		}
	}
	if !needs {
		return services
	}

	out := make([]Service, len(services))
	copy(out, services)

	used := make(map[string]bool, len(out))
	for i := range out {
		if out[i].Name != "" {
			used[out[i].Name] = true
		}
	}
	for i := range out {
		if out[i].Name != "" {
			continue
		}
		out[i].Name = EnsureUniqueName(Slugify(out[i].Host, out[i].Path), used)
		used[out[i].Name] = true
	}
	return out
}

// EnsureUniqueName appends -2, -3, ... to candidate until the result is
// not present in used, preserving the 64-char ValidateSlug ceiling.
// Caller-owned mutation: this does not insert into used; the caller
// records the chosen name so subsequent calls observe it.
//
// Bounded at n=10000 — beyond that we return candidate-overflow rather
// than spinning, since the caller's downstream Validate will catch the
// duplicate cleanly.
func EnsureUniqueName(candidate string, used map[string]bool) string {
	if !used[candidate] {
		return candidate
	}
	for n := 2; n <= 10000; n++ {
		suffix := fmt.Sprintf("-%d", n)
		base := candidate
		if len(base)+len(suffix) > 64 {
			base = strings.TrimRight(base[:64-len(suffix)], "-")
		}
		next := base + suffix
		if !used[next] {
			return next
		}
	}
	return candidate
}

// resolveHeaders renders {{ credential_name }} placeholders in header values
// by calling getCredential for each referenced name. Returns a new map with
// all placeholders replaced, or an error if any credential lookup fails.
func resolveHeaders(headers map[string]string, getCredential func(key string) (string, error)) (map[string]string, error) {
	resolved := make(map[string]string, len(headers))
	for k, v := range headers {
		var resolveErr error
		out := CredentialRef.ReplaceAllStringFunc(v, func(match string) string {
			if resolveErr != nil {
				return ""
			}
			sub := CredentialRef.FindStringSubmatch(match)
			if len(sub) < 2 {
				return match
			}
			val, err := getCredential(sub[1])
			if err != nil {
				resolveErr = err
				return ""
			}
			return val
		})
		if resolveErr != nil {
			return nil, resolveErr
		}
		resolved[k] = out
	}
	return resolved, nil
}
