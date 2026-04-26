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

// Service defines a host-matching service with credential attachment.
//
// Enabled is a nullable toggle. nil means "not set" and is treated as
// enabled so existing persisted services (which predate this field) stay
// live after upgrade. Callers should use IsEnabled() rather than
// dereferencing the pointer.
type Service struct {
	Host          string         `yaml:"host" json:"host"`
	Description   *string        `yaml:"description,omitempty" json:"description"`
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

// Validate checks that a broker config is well-formed.
func Validate(cfg *Config) error {
	if cfg.Vault == "" {
		return fmt.Errorf("vault is required")
	}
	for i, s := range cfg.Services {
		if s.Host == "" {
			return fmt.Errorf("service %d: host is required", i)
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

// MatchHost returns the first service whose Host pattern matches the given host,
// or nil if no service matches. Supports exact match and wildcard prefix (e.g.
// "*.github.com" matches "api.github.com"). The host parameter should already
// have its port stripped by the caller; service hosts are also compared port-stripped.
func MatchHost(host string, services []Service) *Service {
	for i := range services {
		pattern := services[i].Host
		// Strip port from service host for comparison (services should be bare
		// hostnames, but handle legacy entries that include a port).
		if h, _, err := net.SplitHostPort(pattern); err == nil {
			pattern = h
		}
		if pattern == host {
			return &services[i]
		}
		if strings.HasPrefix(pattern, "*.") {
			// *.github.com → match exactly one subdomain level (e.g. api.github.com but not a.b.github.com)
			suffix := pattern[1:] // ".github.com"
			if strings.HasSuffix(host, suffix) {
				// Ensure only one subdomain level: no dots in the part before the suffix.
				prefix := strings.TrimSuffix(host, suffix)
				if prefix != "" && !strings.Contains(prefix, ".") {
					return &services[i]
				}
			}
		}
	}
	return nil
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
