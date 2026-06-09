package broker

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Config represents a vault's broker configuration as stored in YAML files.
type Config struct {
	Vault    string    `yaml:"vault" json:"vault"`
	Services []Service `yaml:"services" json:"services"`
}

// Service defines a credential-attachment rule. Name is the canonical
// per-vault identifier; Host + Path are the matcher key consumed by
// MatchService. JSON callers see a single Host field carrying the
// joined inline form (`slack.com/api/*`); ingest splits it back into
// Host + Path before validation. YAML retains the split form.
//
// Enabled is nullable so persisted services from before the field
// existed stay live after upgrade — use IsEnabled() rather than
// dereferencing the pointer.
type Service struct {
	Name          string         `yaml:"name" json:"name"`
	Host          string         `yaml:"host" json:"host"`
	Path          string         `yaml:"path,omitempty" json:"path,omitempty"`
	Port          *int           `yaml:"port,omitempty" json:"-"`
	Enabled       *bool          `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Auth          Auth           `yaml:"auth" json:"auth"`
	Substitutions []Substitution `yaml:"substitutions,omitempty" json:"substitutions,omitempty"`
}

// MatcherPattern returns the joined inline form (`slack.com/api/*`),
// or just Host when Path is empty.
func (s Service) MatcherPattern() string {
	host := s.Host
	if s.Port != nil {
		host = net.JoinHostPort(s.Host, strconv.Itoa(*s.Port))
	}
	if s.Path == "" {
		return host
	}
	return host + s.Path
}

func (s Service) MarshalJSON() ([]byte, error) {
	type alias Service // strip MarshalJSON to avoid recursion
	a := alias(s)
	a.Host = s.MatcherPattern()
	a.Path = ""
	a.Port = nil
	return json.Marshal(a)
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
// its In list.
var SubstitutionSurfaces = []string{"path", "query", "header", "body", "websocket"}

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
// and unique per vault — callers must supply it explicitly.
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
		if err := ValidateHost(s.Host); err != nil {
			return fmt.Errorf("service %d: %w", i, err)
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
		if err := ValidatePort(s.Port); err != nil {
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

// MatchScore is the deterministic priority tuple emitted by MatchService,
// returned alongside the match so callers can log which rule won.
type MatchScore struct {
	HostTier       int  // 2 = exact host, 1 = "*.x.y" wildcard, 0 = no match
	PortSpecific   bool // true when the matched service declares a specific Port
	PathLiteralLen int  // characters in Path before the first '*'; empty Path scores 0
	DeclOrder      int  // index of the matched service in the input slice
}

// Better compares HostTier, then PortSpecific, then PathLiteralLen;
// DeclOrder is excluded so MatchService's iteration order provides the
// final tiebreak.
func (s MatchScore) Better(other MatchScore) bool {
	if s.HostTier != other.HostTier {
		return s.HostTier > other.HostTier
	}
	if s.PortSpecific != other.PortSpecific {
		return s.PortSpecific
	}
	return s.PathLiteralLen > other.PathLiteralLen
}

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

const (
	HostTierWildcard = 1
	HostTierExact    = 2
)

// MatchService returns the most specific service matching (host, targetPort, path).
// Selection: (1) exact host beats wildcard, even if wildcard has a
// longer path; (2) port-specific service beats port-nil within the same
// host tier; (3) longest literal path prefix wins within a host+port
// tier; (4) earlier declaration order breaks ties. host and service Host
// patterns are both port-stripped. A service with Port=nil matches any
// targetPort; a service with a specific Port matches only that port.
// The MatchScore is meaningful only when the returned *Service is non-nil.
func MatchService(host string, targetPort int, path string, services []Service) (*Service, MatchScore) {
	var best *Service
	var bestScore MatchScore
	for i := range services {
		hostTier, hostOK := matchHostPattern(services[i].Host, host)
		if !hostOK {
			continue
		}
		// Port filtering: a service with a specific Port must match
		// the request's targetPort exactly; Port=nil is a wildcard.
		portSpecific := false
		if services[i].Port != nil {
			if targetPort != *services[i].Port {
				continue
			}
			portSpecific = true
		}
		pathLen, pathOK := matchPathGlob(services[i].Path, path)
		if !pathOK {
			continue
		}
		score := MatchScore{HostTier: hostTier, PortSpecific: portSpecific, PathLiteralLen: pathLen, DeclOrder: i}
		if best == nil || score.Better(bestScore) {
			best = &services[i]
			bestScore = score
		}
	}
	return best, bestScore
}

// matchHostPattern reports the tier and whether pattern matches host.
// "*." matches exactly one subdomain level (e.g. "*.github.com" matches
// "api.github.com" but not "a.b.github.com" or the bare "github.com").
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

// AnyHostMatches reports whether any service's host pattern matches
// host, ignoring paths. Used to filter discovered hosts against the
// current service list so hosts that are already covered by a
// configured service (even path-scoped or disabled) are excluded.
func AnyHostMatches(host string, services []Service) bool {
	for i := range services {
		if _, ok := matchHostPattern(services[i].Host, host); ok {
			return true
		}
	}
	return false
}

// matchPathGlob reports whether pattern matches path and returns the
// literal-prefix length. Empty pattern is a catch-all. '*' is greedy
// across '/'.
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

// Slugify derives a ValidateSlug-conformant identifier from host+path+port.
// Distinct inputs can collide (e.g. `*.github.com` and `github.com` both
// yield `github-com`); callers dedupe via DisambiguateSlug.
func Slugify(host, path string, port *int) string {
	var b strings.Builder
	write := func(s string) {
		for _, r := range strings.ToLower(s) {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
				b.WriteRune(r)
			default:
				b.WriteByte('-')
			}
		}
	}
	write(host)
	if port != nil {
		write(strconv.Itoa(*port))
	}
	write(path)
	raw := b.String()
	for strings.Contains(raw, "--") {
		raw = strings.ReplaceAll(raw, "--", "-")
	}
	raw = strings.Trim(raw, "-")
	if len(raw) > 64 {
		raw = strings.TrimRight(raw[:64], "-")
	}
	if len(raw) < 3 {
		if raw == "" {
			return "svc"
		}
		return raw + "-svc"
	}
	return raw
}

// AssignSlugNames is AssignSlugNamesAvoiding with no existing-state
// context — intra-slice disambiguation only. Use this on read paths
// or full-replace writes where no pre-existing services are merged
// against.
func AssignSlugNames(services []Service) {
	AssignSlugNamesAvoiding(services, nil)
}

// AssignSlugNamesAvoiding fills empty Names with awareness of an
// existing vault state:
//
//  1. An empty-Name entry whose (Host, Path) uniquely matches an
//     existing service adopts that service's Name.
//  2. Remaining empties auto-slug via Slugify + DisambiguateSlug,
//     reserving existing Names alongside in-slice Names so a cross-
//     host slug collision lands on a -2 suffix.
//
// Pass nil existing for intra-slice disambiguation only.
//
// Server write paths route through handle_services.adoptByHost
// instead — that helper rejects empty Names with no unique host
// match rather than auto-slugging. The (2) reservation branch here
// is therefore defensive: production callers (read-path heals via
// AssignSlugNames(svcs)) pass nil existing, so it isn't reached.
// Kept for documentation + the broker-level unit tests that pin the
// semantics if a future caller wants the full adopt-then-slug heal.
func AssignSlugNamesAvoiding(services, existing []Service) {
	anyEmpty := false
	for _, s := range services {
		if s.Name == "" {
			anyEmpty = true
			break
		}
	}
	if !anyEmpty {
		return
	}

	type hp struct{ host, path string }
	hpCount := make(map[hp]int, len(existing))
	hpName := make(map[hp]string, len(existing))
	for _, e := range existing {
		k := hp{e.Host, e.Path}
		hpCount[k]++
		if hpCount[k] == 1 {
			hpName[k] = e.Name
		}
	}
	for i := range services {
		svc := &services[i]
		if svc.Name != "" {
			continue
		}
		k := hp{svc.Host, svc.Path}
		if hpCount[k] == 1 {
			svc.Name = hpName[k]
		}
	}

	taken := make(map[string]bool, len(services)+len(existing))
	for _, e := range existing {
		if e.Name != "" {
			taken[e.Name] = true
		}
	}
	for _, s := range services {
		if s.Name != "" {
			taken[s.Name] = true
		}
	}
	for i := range services {
		svc := &services[i]
		if svc.Name != "" {
			continue
		}
		svc.Name = DisambiguateSlug(Slugify(svc.Host, svc.Path, svc.Port), taken)
		taken[svc.Name] = true
	}
}

// DisambiguateSlug returns the lowest `base-<n>` (n≥2) not in taken,
// truncating base to stay within the 64-char ValidateSlug cap.
func DisambiguateSlug(base string, taken map[string]bool) string {
	name := base
	for n := 2; taken[name]; n++ {
		suffix := fmt.Sprintf("-%d", n)
		trunc := base
		if len(trunc)+len(suffix) > 64 {
			trunc = strings.TrimRight(trunc[:64-len(suffix)], "-")
		}
		name = trunc + suffix
	}
	return name
}

// ValidateSlug enforces the per-vault identifier rule shared by vault,
// agent, and service names: 3–64 chars, lowercase ASCII alphanumeric
// and hyphens, no leading/trailing or consecutive hyphens.
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

// ValidatePath enforces the path-glob format. Empty is a catch-all;
// non-empty paths must start with "/", be ≤256 chars, and contain no
// "**", "?", control characters, whitespace, or regex/HTML tokens.
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
		if unicode.IsControl(r) {
			return fmt.Errorf("path %q must not contain control characters", p)
		}
		switch r {
		case ' ', '?', '#', '[', ']', '\\', '|', '<', '>', '"':
			return fmt.Errorf("path %q must not contain %q", p, r)
		}
	}
	return nil
}

// ValidatePort checks that port, when set, is in the valid TCP range 1-65535.
func ValidatePort(port *int) error {
	if port == nil {
		return nil
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("port %d is out of range (must be 1-65535)", *port)
	}
	return nil
}

// hostLabelPattern matches a valid hostname (RFC 952 / RFC 1123 style).
var hostLabelPattern = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// internalHosts are blocked by default to dodge SSRF against
// cloud-metadata and Kubernetes-internal endpoints; AGENT_VAULT_DEV_MODE
// opens them for localhost development.
var internalHosts = []string{
	"localhost", "localhost.localdomain", "internal",
	"kubernetes", "kubernetes.default",
	"metadata.google.internal", "metadata.google",
	"instance-data",
}

// ValidateHost accepts bare hostnames and one-level wildcards
// (`*.github.com`). Rejects IPs, internal names (see internalHosts),
// bare wildcards, and characters that would break URL parsing.
func ValidateHost(host string) error {
	h := strings.TrimSpace(host)
	if h == "" {
		return fmt.Errorf("host is empty")
	}

	for _, ch := range h {
		if ch == '@' || ch == '?' || ch == '#' || ch == ' ' || unicode.IsControl(ch) {
			return fmt.Errorf("host %q contains invalid character %q", host, ch)
		}
	}

	if net.ParseIP(h) != nil {
		return fmt.Errorf("host %q must be a hostname, not an IP address", host)
	}

	if strings.HasPrefix(h, "*") {
		if h == "*" {
			return fmt.Errorf("host %q: bare wildcard is not allowed", host)
		}
		if !strings.HasPrefix(h, "*.") {
			return fmt.Errorf("host %q: wildcard must be in the form *.example.com", host)
		}
		suffix := h[2:]
		// Require at least one dot in the suffix so *.com / *.co.uk
		// (which would shadow whole TLDs) are rejected.
		if !strings.Contains(suffix, ".") {
			return fmt.Errorf("host %q: wildcard must have at least two domain levels (e.g. *.example.com)", host)
		}
		if !hostLabelPattern.MatchString(suffix) {
			return fmt.Errorf("host %q: invalid hostname in wildcard pattern", host)
		}
		return nil
	}

	devMode := strings.EqualFold(os.Getenv("AGENT_VAULT_DEV_MODE"), "true")
	if !devMode {
		lower := strings.ToLower(h)
		for _, internal := range internalHosts {
			if lower == internal {
				return fmt.Errorf("host %q is a local/internal name and is not allowed (set AGENT_VAULT_DEV_MODE=true to override)", host)
			}
		}
	}

	if !hostLabelPattern.MatchString(h) {
		return fmt.Errorf("host %q is not a valid hostname", host)
	}

	return nil
}

// SplitInlineHost splits an inline host like `internal.corp.com:3000/api/*`
// into bare host, path, and optional port. Returns the inputs unchanged when
// host has no `/` or path is already populated, so callers can pipeline
// split-form and inline-form alike.
func SplitInlineHost(host, path string) (string, string, *int) {
	if path != "" {
		h, port := splitHostPort(host)
		return h, path, port
	}
	if i := strings.IndexByte(host, '/'); i > 0 {
		h, port := splitHostPort(host[:i])
		return h, host[i:], port
	}
	h, port := splitHostPort(host)
	return h, path, port
}

// splitHostPort extracts a numeric port from "host:port", returning the bare
// host and a *int port (nil when no port is present or the port is not
// numeric). It does NOT use net.SplitHostPort so that wildcard hosts like
// *.github.com:8080 work without bracket syntax.
func splitHostPort(host string) (string, *int) {
	idx := strings.LastIndexByte(host, ':')
	if idx < 0 {
		return host, nil
	}
	portStr := host[idx+1:]
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return host, nil // non-numeric -- not a port
	}
	return host[:idx], &p
}

// NormalizePort calls SplitInlineHost on svc.Host/svc.Path and reconciles the
// extracted port with svc.Port. It returns an error when a YAML-level Port
// conflicts with a port embedded in Host (e.g. host: "foo.com:3000" + port: 4000).
func NormalizePort(svc *Service) error {
	host, path, inlinePort := SplitInlineHost(svc.Host, svc.Path)
	svc.Host = host
	svc.Path = path

	if inlinePort != nil && svc.Port != nil && *inlinePort != *svc.Port {
		return fmt.Errorf("host %q embeds port %d but port field is %d", svc.Host, *inlinePort, *svc.Port)
	}
	if inlinePort != nil {
		svc.Port = inlinePort
	}
	return nil
}

// PortVal returns the port value or 0 for a nil pointer. Useful as a
// map-key component where nil needs a zero-value sentinel.
func PortVal(p *int) int {
	if p == nil {
		return 0
	}
	return *p
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
