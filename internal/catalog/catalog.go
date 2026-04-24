package catalog

// Template represents a preconfigured service template in the catalog.
type Template struct {
	ID                     string `json:"id"`
	Name                   string `json:"name"`
	Host                   string `json:"host"`
	Description            string `json:"description"`
	AuthType               string `json:"auth_type"`
	SuggestedCredentialKey string `json:"suggested_credential_key"`
	Header                 string `json:"header,omitempty"`
	Prefix                 string `json:"prefix,omitempty"`

	// ExtraPassthroughHeaders is the recommended default for a provider
	// whose API requires non-standard request headers to be forwarded
	// through Agent Vault's broker — most notably Anthropic's mandatory
	// `anthropic-version`. Operators can remove or extend this list when
	// creating a service from the template. Keep these lowercase to match
	// common provider documentation, though matching is case-insensitive.
	ExtraPassthroughHeaders []string `json:"extra_passthrough_headers,omitempty"`
}

// catalog is the built-in list of common service templates.
var catalog = []Template{
	{ID: "stripe", Name: "Stripe", Host: "api.stripe.com", Description: "Payment processing API", AuthType: "bearer", SuggestedCredentialKey: "STRIPE_KEY",
		// Stripe-Version pins the API schema; without it requests fall back
		// to the account's default version which can change silently.
		ExtraPassthroughHeaders: []string{"Stripe-Version"}},
	{ID: "github", Name: "GitHub", Host: "api.github.com", Description: "GitHub REST API", AuthType: "bearer", SuggestedCredentialKey: "GITHUB_TOKEN",
		// X-GitHub-Api-Version pins REST schema per
		// https://docs.github.com/en/rest/overview/api-versions.
		ExtraPassthroughHeaders: []string{"X-GitHub-Api-Version"}},
	{ID: "openai", Name: "OpenAI", Host: "api.openai.com", Description: "OpenAI / ChatGPT API", AuthType: "bearer", SuggestedCredentialKey: "OPENAI_API_KEY",
		// OpenAI-Organization / OpenAI-Project scope the request to a team/
		// project when the API key is a default-scoped sk-... See
		// https://platform.openai.com/docs/api-reference/authentication.
		ExtraPassthroughHeaders: []string{"OpenAI-Organization", "OpenAI-Project", "OpenAI-Beta"}},
	{ID: "anthropic", Name: "Anthropic", Host: "api.anthropic.com", Description: "Claude API", AuthType: "api-key", SuggestedCredentialKey: "ANTHROPIC_API_KEY", Header: "x-api-key",
		// anthropic-version is MANDATORY on every /v1/messages request.
		// anthropic-beta gates opt-in features (prompt caching, tools, etc.).
		ExtraPassthroughHeaders: []string{"anthropic-version", "anthropic-beta"}},
	{ID: "slack", Name: "Slack", Host: "slack.com", Description: "Slack Web API", AuthType: "bearer", SuggestedCredentialKey: "SLACK_TOKEN"},
	{ID: "twilio", Name: "Twilio", Host: "api.twilio.com", Description: "Communication APIs (SMS, voice, email)", AuthType: "basic", SuggestedCredentialKey: "TWILIO_AUTH_TOKEN"},
	{ID: "sendgrid", Name: "SendGrid", Host: "api.sendgrid.com", Description: "Email delivery API", AuthType: "bearer", SuggestedCredentialKey: "SENDGRID_API_KEY"},
	{ID: "aws-s3", Name: "AWS S3", Host: "s3.amazonaws.com", Description: "Amazon S3 object storage", AuthType: "custom", SuggestedCredentialKey: "AWS_SECRET_ACCESS_KEY"},
	{ID: "cloudflare", Name: "Cloudflare", Host: "api.cloudflare.com", Description: "Cloudflare API", AuthType: "bearer", SuggestedCredentialKey: "CLOUDFLARE_API_TOKEN"},
	{ID: "datadog", Name: "Datadog", Host: "api.datadoghq.com", Description: "Monitoring and analytics", AuthType: "api-key", SuggestedCredentialKey: "DATADOG_API_KEY", Header: "DD-API-KEY",
		// DD-APPLICATION-KEY is required by endpoints like /api/v1/query that
		// go beyond simple ingest, alongside the api-key injected by auth.
		ExtraPassthroughHeaders: []string{"DD-APPLICATION-KEY"}},
	{ID: "pagerduty", Name: "PagerDuty", Host: "api.pagerduty.com", Description: "Incident management", AuthType: "bearer", SuggestedCredentialKey: "PAGERDUTY_TOKEN"},
	{ID: "linear", Name: "Linear", Host: "api.linear.app", Description: "Project management and issue tracking", AuthType: "bearer", SuggestedCredentialKey: "LINEAR_API_KEY"},
	{ID: "jira", Name: "Jira", Host: "*.atlassian.net", Description: "Atlassian Jira project tracking", AuthType: "basic", SuggestedCredentialKey: "JIRA_API_TOKEN"},
	{ID: "notion", Name: "Notion", Host: "api.notion.com", Description: "Notion workspace API", AuthType: "bearer", SuggestedCredentialKey: "NOTION_TOKEN",
		// Notion-Version is MANDATORY for every Notion API request.
		ExtraPassthroughHeaders: []string{"Notion-Version"}},
	{ID: "vercel", Name: "Vercel", Host: "api.vercel.com", Description: "Vercel deployment platform", AuthType: "bearer", SuggestedCredentialKey: "VERCEL_TOKEN"},
	{ID: "supabase", Name: "Supabase", Host: "*.supabase.co", Description: "Supabase backend-as-a-service", AuthType: "bearer", SuggestedCredentialKey: "SUPABASE_KEY",
		// apikey is a parallel auth header some Supabase endpoints expect in
		// addition to the bearer (service-role vs anon key distinction).
		ExtraPassthroughHeaders: []string{"apikey", "Prefer"}},
	{ID: "resend", Name: "Resend", Host: "api.resend.com", Description: "Email API for developers", AuthType: "bearer", SuggestedCredentialKey: "RESEND_API_KEY"},
	{ID: "postmark", Name: "Postmark", Host: "api.postmarkapp.com", Description: "Transactional email service", AuthType: "api-key", SuggestedCredentialKey: "POSTMARK_SERVER_TOKEN", Header: "X-Postmark-Server-Token"},
	{ID: "sentry", Name: "Sentry", Host: "sentry.io", Description: "Error tracking and performance monitoring", AuthType: "bearer", SuggestedCredentialKey: "SENTRY_AUTH_TOKEN"},
	{ID: "shopify", Name: "Shopify", Host: "*.myshopify.com", Description: "Shopify e-commerce API", AuthType: "api-key", SuggestedCredentialKey: "SHOPIFY_ACCESS_TOKEN", Header: "X-Shopify-Access-Token"},
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
