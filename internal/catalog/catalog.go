package catalog

import "github.com/Infisical/agent-vault/internal/broker"

// Template represents a preconfigured service template in the catalog.
// Header and Prefix seed api-key auth, Headers seeds custom auth, and
// Substitutions seed the substitution editor independent of AuthType.
type Template struct {
	ID                     string                `json:"id"`
	Name                   string                `json:"name"`
	Host                   string                `json:"host"`
	Description            string                `json:"description"`
	AuthType               string                `json:"auth_type"`
	SuggestedCredentialKey string                `json:"suggested_credential_key"`
	Header                 string                `json:"header,omitempty"`
	Prefix                 string                `json:"prefix,omitempty"`
	Headers                map[string]string     `json:"headers,omitempty"`
	Substitutions          []broker.Substitution `json:"substitutions,omitempty"`
}

// catalog is the built-in list of common service templates.
var catalog = []Template{
	{ID: "anthropic", Name: "Anthropic", Host: "api.anthropic.com", Description: "Claude API", AuthType: "api-key", SuggestedCredentialKey: "ANTHROPIC_API_KEY", Header: "x-api-key"},
	{ID: "aws-s3", Name: "AWS S3", Host: "s3.amazonaws.com", Description: "Amazon S3 object storage", AuthType: "custom", SuggestedCredentialKey: "AWS_SECRET_ACCESS_KEY"},
	{ID: "cloudflare", Name: "Cloudflare", Host: "api.cloudflare.com", Description: "Cloudflare API", AuthType: "bearer", SuggestedCredentialKey: "CLOUDFLARE_API_TOKEN"},
	{ID: "cohere", Name: "Cohere", Host: "api.cohere.com", Description: "Cohere language models", AuthType: "bearer", SuggestedCredentialKey: "CO_API_KEY"},
	{ID: "datadog", Name: "Datadog", Host: "api.datadoghq.com", Description: "Monitoring and analytics", AuthType: "api-key", SuggestedCredentialKey: "DATADOG_API_KEY", Header: "DD-API-KEY"},
	{ID: "deepseek", Name: "DeepSeek", Host: "api.deepseek.com", Description: "DeepSeek chat and reasoning models", AuthType: "bearer", SuggestedCredentialKey: "DEEPSEEK_API_KEY"},
	{ID: "discord", Name: "Discord", Host: "discord.com/api/*", Description: "Discord bot and REST API", AuthType: "api-key", SuggestedCredentialKey: "DISCORD_BOT_TOKEN", Header: "Authorization", Prefix: "Bot "},
	{ID: "fireworks", Name: "Fireworks AI", Host: "api.fireworks.ai", Description: "Fast open-model inference", AuthType: "bearer", SuggestedCredentialKey: "FIREWORKS_API_KEY"},
	{ID: "gemini", Name: "Google Gemini", Host: "generativelanguage.googleapis.com", Description: "Google Gemini models", AuthType: "api-key", SuggestedCredentialKey: "GEMINI_API_KEY", Header: "x-goog-api-key"},
	{ID: "github", Name: "GitHub", Host: "api.github.com", Description: "GitHub REST API", AuthType: "bearer", SuggestedCredentialKey: "GITHUB_TOKEN"},
	{ID: "gitlab", Name: "GitLab", Host: "gitlab.com/api/*", Description: "GitLab repos and pipelines", AuthType: "api-key", SuggestedCredentialKey: "GITLAB_TOKEN", Header: "PRIVATE-TOKEN"},
	{ID: "groq", Name: "Groq", Host: "api.groq.com", Description: "Fast model inference from Groq", AuthType: "bearer", SuggestedCredentialKey: "GROQ_API_KEY"},
	{ID: "jira", Name: "Jira", Host: "*.atlassian.net", Description: "Atlassian Jira project tracking", AuthType: "basic", SuggestedCredentialKey: "JIRA_API_TOKEN"},
	{ID: "linear", Name: "Linear", Host: "api.linear.app", Description: "Project management and issue tracking", AuthType: "api-key", SuggestedCredentialKey: "LINEAR_API_KEY", Header: "Authorization"},
	{ID: "mistral", Name: "Mistral AI", Host: "api.mistral.ai", Description: "Mistral chat and embedding models", AuthType: "bearer", SuggestedCredentialKey: "MISTRAL_API_KEY"},
	{ID: "notion", Name: "Notion", Host: "api.notion.com", Description: "Notion workspace API", AuthType: "bearer", SuggestedCredentialKey: "NOTION_TOKEN"},
	{ID: "npm", Name: "NPM", Host: "registry.npmjs.org", Description: "NPM Default registry", AuthType: "bearer", SuggestedCredentialKey: "NPM_TOKEN"},
	{ID: "npmgh", Name: "Github NPM registry", Host: "npm.pkg.github.com", Description: "Github's NPM registry", AuthType: "bearer", SuggestedCredentialKey: "NPM_GH_TOKEN"},
	{ID: "openai", Name: "OpenAI", Host: "api.openai.com", Description: "OpenAI / ChatGPT API", AuthType: "bearer", SuggestedCredentialKey: "OPENAI_API_KEY"},
	{ID: "openrouter", Name: "OpenRouter", Host: "openrouter.ai", Description: "One key for many AI models", AuthType: "bearer", SuggestedCredentialKey: "OPENROUTER_API_KEY"},
	{ID: "pagerduty", Name: "PagerDuty", Host: "api.pagerduty.com", Description: "Incident management", AuthType: "custom", SuggestedCredentialKey: "PAGERDUTY_TOKEN", Headers: map[string]string{
		"Authorization": "Token token={{ PAGERDUTY_TOKEN }}",
	}},
	{ID: "perplexity", Name: "Perplexity", Host: "api.perplexity.ai", Description: "Perplexity answer engine", AuthType: "bearer", SuggestedCredentialKey: "PERPLEXITY_API_KEY"},
	{ID: "postmark", Name: "Postmark", Host: "api.postmarkapp.com", Description: "Transactional email service", AuthType: "api-key", SuggestedCredentialKey: "POSTMARK_SERVER_TOKEN", Header: "X-Postmark-Server-Token"},
	{ID: "resend", Name: "Resend", Host: "api.resend.com", Description: "Email API for developers", AuthType: "bearer", SuggestedCredentialKey: "RESEND_API_KEY"},
	{ID: "sendgrid", Name: "SendGrid", Host: "api.sendgrid.com", Description: "Email delivery API", AuthType: "bearer", SuggestedCredentialKey: "SENDGRID_API_KEY"},
	{ID: "sentry", Name: "Sentry", Host: "sentry.io", Description: "Error tracking and performance monitoring", AuthType: "bearer", SuggestedCredentialKey: "SENTRY_AUTH_TOKEN"},
	{ID: "shopify", Name: "Shopify", Host: "*.myshopify.com", Description: "Shopify e-commerce API", AuthType: "api-key", SuggestedCredentialKey: "SHOPIFY_ACCESS_TOKEN", Header: "X-Shopify-Access-Token"},
	{ID: "slack", Name: "Slack", Host: "slack.com", Description: "Slack Web API", AuthType: "bearer", SuggestedCredentialKey: "SLACK_TOKEN"},
	{ID: "stripe", Name: "Stripe", Host: "api.stripe.com", Description: "Payment processing API", AuthType: "bearer", SuggestedCredentialKey: "STRIPE_SECRET_KEY"},
	{ID: "supabase", Name: "Supabase", Host: "*.supabase.co", Description: "Supabase backend-as-a-service", AuthType: "api-key", SuggestedCredentialKey: "SUPABASE_KEY", Header: "apikey"},
	{ID: "telegram", Name: "Telegram", Host: "api.telegram.org", Description: "Telegram bot API", AuthType: "passthrough", SuggestedCredentialKey: "TELEGRAM_BOT_TOKEN", Substitutions: []broker.Substitution{
		{Key: "TELEGRAM_BOT_TOKEN", Placeholder: "__TELEGRAM_BOT_TOKEN__", In: []string{"path"}},
	}},
	{ID: "together", Name: "Together AI", Host: "api.together.ai", Description: "Open models on Together AI", AuthType: "bearer", SuggestedCredentialKey: "TOGETHER_API_KEY"},
	{ID: "twilio", Name: "Twilio", Host: "api.twilio.com", Description: "Communication APIs (SMS, voice, email)", AuthType: "basic", SuggestedCredentialKey: "TWILIO_AUTH_TOKEN"},
	{ID: "vercel", Name: "Vercel", Host: "api.vercel.com", Description: "Vercel deployment platform", AuthType: "bearer", SuggestedCredentialKey: "VERCEL_TOKEN"},
	{ID: "xai", Name: "xAI (Grok)", Host: "api.x.ai", Description: "Grok models from xAI", AuthType: "bearer", SuggestedCredentialKey: "XAI_API_KEY"},
}

// GetAll returns all available service templates.
func GetAll() []Template {
	return catalog
}

// GetByID returns a template by its ID, or nil if not found.
func GetByID(id string) *Template {
	for i := range catalog {
		if catalog[i].ID == id {
			return &catalog[i]
		}
	}
	return nil
}
