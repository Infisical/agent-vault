package proposal

import (
	"fmt"
	"net/url"
	"strings"

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

	nameSet := make(map[string]int, len(services))
	for i, s := range services {
		if s.Action != ActionSet && s.Action != ActionDelete {
			return fmt.Errorf("service %d: invalid action %q (must be %q or %q)", i, s.Action, ActionSet, ActionDelete)
		}
		if s.Host == "" {
			return fmt.Errorf("service %d: host is required", i)
		}
		if strings.Contains(s.Host, "/") {
			return fmt.Errorf("service %d: host %q must not contain %q after ingest (entry should have been split into host + path)", i, s.Host, "/")
		}
		if err := broker.ValidateHost(s.Host); err != nil {
			return fmt.Errorf("service %d: %w", i, err)
		}
		if s.Name == "" {
			return fmt.Errorf("service %d: name is required", i)
		}
		if err := broker.ValidateSlug(s.Name); err != nil {
			return fmt.Errorf("service %d: %w", i, err)
		}
		if prev, dup := nameSet[s.Name]; dup {
			return fmt.Errorf("service %d: duplicate name %q (also at service %d)", i, s.Name, prev)
		}
		nameSet[s.Name] = i
		if err := broker.ValidatePath(s.Path); err != nil {
			return fmt.Errorf("service %d: %w", i, err)
		}
		if err := broker.ValidatePort(s.Port); err != nil {
			return fmt.Errorf("service %d: %w", i, err)
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
			if len(s.Substitutions) > 0 {
				// Coupled to Auth here (not in broker.Validate) because
				// broker.Service.Auth is non-pointer — the direct write
				// path can't express "substitutions without auth", but
				// proposals can via Auth==nil enable-only updates.
				if s.Auth == nil {
					return fmt.Errorf("service %d: substitutions require auth — to change substitutions on an existing service, re-supply the auth config", i)
				}
				synthetic := broker.Service{Host: s.Host, Substitutions: s.Substitutions}
				if err := synthetic.ValidateSubstitutions(); err != nil {
					return fmt.Errorf("service %d: %w", i, err)
				}
			}
		}
	}

	// Collect all credential references from set-action services (auth + substitutions).
	refs := make(map[string]bool)
	for _, s := range services {
		if s.Action != ActionSet || s.Auth == nil {
			continue
		}
		for _, key := range s.Auth.CredentialKeys() {
			refs[key] = true
		}
		for _, sub := range s.Substitutions {
			refs[sub.Key] = true
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

		if c.Type != "" && c.Type != "static" && c.Type != "oauth" {
			return fmt.Errorf("credential slot %q: unsupported type %q (supported: static, oauth)", c.Key, c.Type)
		}
		if c.Type == "oauth" {
			if c.OAuth == nil {
				return fmt.Errorf("credential slot %q: \"oauth\" config is required when type is \"oauth\"", c.Key)
			}
			if c.OAuth.TokenURL == "" {
				return fmt.Errorf("credential slot %q: oauth.token_url is required", c.Key)
			}
			if c.OAuth.AuthorizationURL != "" {
				u, err := url.Parse(c.OAuth.AuthorizationURL)
				if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
					return fmt.Errorf("credential slot %q: oauth.authorization_url must be an https:// or http:// URL", c.Key)
				}
			}
			{
				u, err := url.Parse(c.OAuth.TokenURL)
				if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
					return fmt.Errorf("credential slot %q: oauth.token_url must be an https:// or http:// URL", c.Key)
				}
			}
			if c.Value != nil {
				return fmt.Errorf("credential slot %q: \"value\" must not be set for oauth credentials (tokens are obtained via the connect flow)", c.Key)
			}
			if c.OAuth.TokenAuthMethod != "" {
				switch c.OAuth.TokenAuthMethod {
				case "client_secret_post", "client_secret_basic":
				default:
					return fmt.Errorf("credential slot %q: oauth.token_auth_method must be \"client_secret_post\" or \"client_secret_basic\"", c.Key)
				}
			}
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

	// Check every credential key ref in set-action service auth configs and
	// substitutions resolves to either a proposal slot or an existing key.
	for _, svc := range services {
		if svc.Action != ActionSet || svc.Auth == nil {
			continue
		}
		ref := svc.Name
		if ref == "" {
			ref = svc.Host
		}
		for _, key := range svc.Auth.CredentialKeys() {
			if !available[key] {
				return fmt.Errorf("credential %q referenced in service %q is not provided in this proposal and does not exist in the vault", key, ref)
			}
		}
		for _, sub := range svc.Substitutions {
			if !available[sub.Key] {
				return fmt.Errorf("credential %q referenced in substitution for %q is not provided in this proposal and does not exist in the vault", sub.Key, ref)
			}
		}
	}
	return nil
}
