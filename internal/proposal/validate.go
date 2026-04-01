package proposal

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"unicode"
)

const (
	MaxRules   = 10
	MaxCredentials = 10

	MaxMessageLen            = 2000
	MaxUserMessageLen        = 5000
	MaxDescriptionLen        = 500
	MaxObtainLen             = 500
	MaxObtainInstructionsLen = 1000
)

// CredentialKeyPattern validates credential key names: UPPER_SNAKE_CASE (e.g. STRIPE_KEY, GITHUB_TOKEN).
// Must start with an uppercase letter, contain only uppercase letters, digits, and underscores.
var CredentialKeyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// hostLabelPattern matches a valid hostname (RFC 952 / RFC 1123 style).
var hostLabelPattern = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// internalHosts are names blocked unless AGENT_VAULT_DEV_MODE=true.
var internalHosts = []string{
	"localhost", "localhost.localdomain", "internal",
	"kubernetes", "kubernetes.default",
	"metadata.google.internal", "metadata.google",
	"instance-data",
}

// ValidateHost checks that a host string is safe and well-formed.
func ValidateHost(host string) error {
	h := strings.TrimSpace(host)
	if h == "" {
		return fmt.Errorf("host is empty")
	}

	// Reject forbidden characters.
	for _, ch := range h {
		if ch == '@' || ch == '?' || ch == '#' || ch == ' ' || unicode.IsControl(ch) {
			return fmt.Errorf("host %q contains invalid character %q", host, ch)
		}
	}

	// Reject raw IP addresses.
	if net.ParseIP(h) != nil {
		return fmt.Errorf("host %q must be a hostname, not an IP address", host)
	}

	// Handle wildcard patterns.
	if strings.HasPrefix(h, "*") {
		if h == "*" {
			return fmt.Errorf("host %q: bare wildcard is not allowed", host)
		}
		if !strings.HasPrefix(h, "*.") {
			return fmt.Errorf("host %q: wildcard must be in the form *.example.com", host)
		}
		suffix := h[2:] // after "*."
		// Must have at least 2 dots in the suffix to avoid *.com or *.co.uk style patterns.
		// e.g. *.example.com → suffix is "example.com" which has 1 dot → OK
		// *.com → suffix is "com" which has 0 dots → reject
		// *.co.uk → suffix is "co.uk" which has 1 dot → reject (need 2+ labels before TLD)
		// We require at least one dot in the suffix (i.e. suffix must be a multi-label domain).
		if !strings.Contains(suffix, ".") {
			return fmt.Errorf("host %q: wildcard must have at least two domain levels (e.g. *.example.com)", host)
		}
		// Validate the suffix as a hostname.
		if !hostLabelPattern.MatchString(suffix) {
			return fmt.Errorf("host %q: invalid hostname in wildcard pattern", host)
		}
		return nil
	}

	// Block internal hostnames unless dev mode.
	devMode := strings.EqualFold(os.Getenv("AGENT_VAULT_DEV_MODE"), "true")
	if !devMode {
		lower := strings.ToLower(h)
		for _, internal := range internalHosts {
			if lower == internal {
				return fmt.Errorf("host %q is a local/internal name and is not allowed (set AGENT_VAULT_DEV_MODE=true to override)", host)
			}
		}
	}

	// Validate as a proper hostname.
	if !hostLabelPattern.MatchString(h) {
		return fmt.Errorf("host %q is not a valid hostname", host)
	}

	return nil
}

// ValidateMessages checks length limits for proposal-level message fields.
func ValidateMessages(message, userMessage string) error {
	if len(message) > MaxMessageLen {
		return fmt.Errorf("message too long (max %d characters)", MaxMessageLen)
	}
	if len(userMessage) > MaxUserMessageLen {
		return fmt.Errorf("user_message too long (max %d characters)", MaxUserMessageLen)
	}
	return nil
}

// Validate checks that a proposal is well-formed.
func Validate(rules []Rule, credentials []CredentialSlot) error {
	if len(rules) == 0 && len(credentials) == 0 {
		return fmt.Errorf("at least one rule or credential is required")
	}
	if len(rules) > MaxRules {
		return fmt.Errorf("too many rules (max %d)", MaxRules)
	}
	if len(credentials) > MaxCredentials {
		return fmt.Errorf("too many credential slots (max %d)", MaxCredentials)
	}

	for i, r := range rules {
		if r.Action != ActionSet && r.Action != ActionDelete {
			return fmt.Errorf("rule %d: invalid action %q (must be %q or %q)", i, r.Action, ActionSet, ActionDelete)
		}
		if r.Host == "" {
			return fmt.Errorf("rule %d: host is required", i)
		}
		if err := ValidateHost(r.Host); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
		if len(r.Description) > MaxDescriptionLen {
			return fmt.Errorf("rule %d: description too long (max %d characters)", i, MaxDescriptionLen)
		}
		if r.Action == ActionSet {
			if r.Auth == nil {
				return fmt.Errorf("rule %d: auth is required for set action", i)
			}
			if err := r.Auth.Validate(); err != nil {
				return fmt.Errorf("rule %d: %w", i, err)
			}
		}
	}

	// Collect all credential references from set-action rules.
	refs := make(map[string]bool)
	for _, r := range rules {
		if r.Action != ActionSet || r.Auth == nil {
			continue
		}
		for _, key := range r.Auth.CredentialKeys() {
			refs[key] = true
		}
	}

	// Validate credential slots.
	seenKeys := make(map[string]bool)
	for _, s := range credentials {
		if s.Action != ActionSet && s.Action != ActionDelete {
			return fmt.Errorf("credential slot: invalid action %q (must be %q or %q)", s.Action, ActionSet, ActionDelete)
		}
		if s.Key == "" {
			return fmt.Errorf("credential slot key is required")
		}
		if !CredentialKeyPattern.MatchString(s.Key) {
			return fmt.Errorf("credential slot key %q must be UPPER_SNAKE_CASE (e.g. STRIPE_KEY, GITHUB_TOKEN)", s.Key)
		}
		if seenKeys[s.Key] {
			return fmt.Errorf("duplicate credential slot key %q", s.Key)
		}
		seenKeys[s.Key] = true

		// Validate field lengths.
		if len(s.Description) > MaxDescriptionLen {
			return fmt.Errorf("credential slot %q: description too long (max %d characters)", s.Key, MaxDescriptionLen)
		}
		if len(s.Obtain) > MaxObtainLen {
			return fmt.Errorf("credential slot %q: obtain too long (max %d characters)", s.Key, MaxObtainLen)
		}
		if s.Obtain != "" {
			u, err := url.Parse(s.Obtain)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				return fmt.Errorf("credential slot %q: obtain must be a valid https:// or http:// URL", s.Key)
			}
		}
		if len(s.ObtainInstructions) > MaxObtainInstructionsLen {
			return fmt.Errorf("credential slot %q: obtain_instructions too long (max %d characters)", s.Key, MaxObtainInstructionsLen)
		}

		// If rules exist, set-action slots must be referenced by a rule auth config.
		// Credential-only proposals (no rules) are allowed for storing credentials back.
		if len(rules) > 0 && s.Action == ActionSet && !refs[s.Key] {
			return fmt.Errorf("credential slot %q is not referenced by any rule auth config", s.Key)
		}
	}

	return nil
}

// ValidateCredentialRefs checks that every credential key referenced in set-action
// rule auth configs resolves to either a credential slot in the proposal or an
// existing credential key in the vault.
func ValidateCredentialRefs(rules []Rule, slots []CredentialSlot, existingKeys []string) error {
	// Build set of available keys: set-action proposal slots + existing store keys.
	available := make(map[string]bool, len(slots)+len(existingKeys))
	for _, s := range slots {
		if s.Action == ActionSet {
			available[s.Key] = true
		}
	}
	for _, k := range existingKeys {
		available[k] = true
	}

	// Check every credential key ref in set-action rule auth configs resolves.
	for _, r := range rules {
		if r.Action != ActionSet || r.Auth == nil {
			continue
		}
		for _, key := range r.Auth.CredentialKeys() {
			if !available[key] {
				return fmt.Errorf("credential %q referenced in rule for %q is not provided in this proposal and does not exist in the vault", key, r.Host)
			}
		}
	}
	return nil
}
