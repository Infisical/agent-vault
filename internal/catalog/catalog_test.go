package catalog

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
)

// serviceFromTemplate mirrors what the add-service form's applyPreset builds
// from a template, so validating it here catches a preset that would produce
// an unsubmittable form or a rejected proposal.
func serviceFromTemplate(t Template) broker.Service {
	auth := broker.Auth{Type: t.AuthType}
	switch t.AuthType {
	case "bearer":
		auth.Token = t.SuggestedCredentialKey
	case "basic":
		// The form seeds the token into the password slot; the username
		// (AccountSID, Jira email) is user-specific, so stand one in here.
		auth.Username = "USERNAME"
		auth.Password = t.SuggestedCredentialKey
	case "api-key":
		auth.Key = t.SuggestedCredentialKey
		auth.Header = t.Header
		auth.Prefix = t.Prefix
	case "custom":
		auth.Headers = t.Headers
	}

	host, path, port := broker.SplitInlineHost(t.Host, "")
	return broker.Service{
		Name:          t.ID,
		Host:          host,
		Path:          path,
		Port:          port,
		Auth:          auth,
		Substitutions: t.Substitutions,
	}
}

func TestCatalogTemplatesAreValidServices(t *testing.T) {
	seen := make(map[string]bool)
	for _, tpl := range GetAll() {
		t.Run(tpl.ID, func(t *testing.T) {
			// GetByID returns the first match, so a duplicate would silently
			// shadow the later template.
			if seen[tpl.ID] {
				t.Fatalf("duplicate template id %q", tpl.ID)
			}
			seen[tpl.ID] = true

			if !broker.CredentialKeyPattern.MatchString(tpl.SuggestedCredentialKey) {
				t.Errorf("suggested_credential_key %q must be UPPER_SNAKE_CASE", tpl.SuggestedCredentialKey)
			}
			// aws-s3 needs SigV4 request signing, which no auth type can
			// express, so it ships without headers and is skipped here.
			if tpl.ID == "aws-s3" {
				return
			}
			cfg := broker.Config{Vault: "default", Services: []broker.Service{serviceFromTemplate(tpl)}}
			if err := broker.Validate(&cfg); err != nil {
				t.Errorf("template does not produce a valid service: %v", err)
			}
		})
	}
}

// The Telegram bot token travels as a path segment, and its real
// `<id>:<token>` shape must survive path escaping intact.
func TestTelegramTemplateRewritesPath(t *testing.T) {
	tpl := GetByID("telegram")
	if tpl == nil {
		t.Fatal("telegram template missing")
	}
	subs := make([]brokercore.ResolvedSubstitution, 0, len(tpl.Substitutions))
	for _, sub := range tpl.Substitutions {
		subs = append(subs, brokercore.ResolvedSubstitution{
			Placeholder: sub.Placeholder,
			Value:       "123456789:AAH-abc_DEF",
			In:          sub.NormalizedIn(),
		})
	}

	u, err := url.Parse("https://api.telegram.org/bot__TELEGRAM_BOT_TOKEN__/sendMessage")
	if err != nil {
		t.Fatal(err)
	}
	if err := brokercore.ApplySubstitutions(u, http.Header{}, subs); err != nil {
		t.Fatalf("ApplySubstitutions: %v", err)
	}
	const want = "https://api.telegram.org/bot123456789:AAH-abc_DEF/sendMessage"
	if got := u.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
