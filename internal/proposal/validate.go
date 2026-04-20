package proposal

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"unicode"

	"github.com/Infisical/agent-vault/internal/broker"
)

const (
	MaxServices    = 10
	MaxCredentials = 10

	MaxMessageLen            = 2000
	MaxUserMessageLen        = 5000
	MaxDescriptionLen        = 500
	MaxObtainLen             = 500
	MaxObtainInstructionsLen = 1000
)

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
func Validate(services []Service, credentials []CredentialSlot) error {
	if len(services) == 0 && len(credentials) == 0 {
		return fmt.Errorf("at least one service or credential is required")
	}
	if len(services) > MaxServices {
		return fmt.Errorf("too many services (max %d)", MaxServices)
	}
	if len(credentials) > MaxCredentials {
		return fmt.Errorf("too many credential slots (max %d)", MaxCredentials)
	}

	for i, s := range services {
		if s.Action != ActionSet && s.Action != ActionDelete {
			return fmt.Errorf("service %d: invalid action %q (must be %q or %q)", i, s.Action, ActionSet, ActionDelete)
		}
		if s.Host == "" {
			return fmt.Errorf("service %d: host is required", i)
		}
		if err := ValidateHost(s.Host); err != nil {
			return fmt.Errorf("service %d: %w", i, err)
		}
		if len(s.Description) > MaxDescriptionLen {
			return fmt.Errorf("service %d: description too long (max %d characters)", i, MaxDescriptionLen)
		}
		if s.Action == ActionSet {
			if s.Auth == nil && s.Enabled == nil {
				return fmt.Errorf("service %d: set action requires auth or enabled change", i)
			}
			if s.Auth != nil {
				if err := s.Auth.Validate(); err != nil {
					return fmt.Errorf("service %d: %w", i, err)
				}
			}
		}
	}

	// Collect all credential references from set-action services.
	refs := make(map[string]bool)
	for _, s := range services {
		if s.Action != ActionSet || s.Auth == nil {
			continue
		}
		for _, key := range s.Auth.CredentialKeys() {
			refs[key] = true
		}
	}

	// Validate credential slots.
	seenKeys := make(map[string]bool)
	for _, c := range credentials {
		if c.Action != ActionSet && c.Action != ActionDelete {
			return fmt.Errorf("credential slot: invalid action %q (must be %q or %q)", c.Action, ActionSet, ActionDelete)
		}
		if c.Key == "" {
			return fmt.Errorf("credential slot key is required")
		}
		if !broker.CredentialKeyPattern.MatchString(c.Key) {
			return fmt.Errorf("credential slot key %q must be UPPER_SNAKE_CASE (e.g. STRIPE_KEY, GITHUB_TOKEN)", c.Key)
		}
		if seenKeys[c.Key] {
			return fmt.Errorf("duplicate credential slot key %q", c.Key)
		}
		seenKeys[c.Key] = true

		// Validate field lengths.
		if len(c.Description) > MaxDescriptionLen {
			return fmt.Errorf("credential slot %q: description too long (max %d characters)", c.Key, MaxDescriptionLen)
		}
		if len(c.Obtain) > MaxObtainLen {
			return fmt.Errorf("credential slot %q: obtain too long (max %d characters)", c.Key, MaxObtainLen)
		}
		if c.Obtain != "" {
			u, err := url.Parse(c.Obtain)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				return fmt.Errorf("credential slot %q: obtain must be a valid https:// or http:// URL", c.Key)
			}
		}
		if len(c.ObtainInstructions) > MaxObtainInstructionsLen {
			return fmt.Errorf("credential slot %q: obtain_instructions too long (max %d characters)", c.Key, MaxObtainInstructionsLen)
		}

		// If services exist, set-action slots must be referenced by a service auth config.
		// Credential-only proposals (no services) are allowed for storing credentials back.
		if len(services) > 0 && c.Action == ActionSet && !refs[c.Key] {
			return fmt.Errorf("credential slot %q is not referenced by any service auth config", c.Key)
		}
	}

	return nil
}

// ValidateCredentialRefs checks that every credential key referenced in set-action
// service auth configs resolves to either a credential slot in the proposal or an
// existing credential key in the vault.
func ValidateCredentialRefs(services []Service, slots []CredentialSlot, existingKeys []string) error {
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

	// Check every credential key ref in set-action service auth configs resolves.
	for _, svc := range services {
		if svc.Action != ActionSet || svc.Auth == nil {
			continue
		}
		for _, key := range svc.Auth.CredentialKeys() {
			if !available[key] {
				return fmt.Errorf("credential %q referenced in service for %q is not provided in this proposal and does not exist in the vault", key, svc.Host)
			}
		}
	}
	return nil
}
