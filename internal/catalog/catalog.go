package catalog

// Template represents a preconfigured service template in the catalog.
type Template struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	Host                  string `json:"host"`
	Description           string `json:"description"`
	AuthType              string `json:"auth_type"`
	SuggestedCredentialKey string `json:"suggested_credential_key"`
}

// catalog is the built-in list of common service templates.
var catalog = []Template{
	{ID: "stripe", Name: "Stripe", Host: "api.stripe.com", Description: "Payment processing API", AuthType: "bearer", SuggestedCredentialKey: "STRIPE_KEY"},
	{ID: "github", Name: "GitHub", Host: "api.github.com", Description: "GitHub REST API", AuthType: "bearer", SuggestedCredentialKey: "GITHUB_TOKEN"},
	{ID: "openai", Name: "OpenAI", Host: "api.openai.com", Description: "OpenAI / ChatGPT API", AuthType: "bearer", SuggestedCredentialKey: "OPENAI_API_KEY"},
	{ID: "anthropic", Name: "Anthropic", Host: "api.anthropic.com", Description: "Claude API", AuthType: "api-key", SuggestedCredentialKey: "ANTHROPIC_API_KEY"},
	{ID: "slack", Name: "Slack", Host: "slack.com", Description: "Slack Web API", AuthType: "bearer", SuggestedCredentialKey: "SLACK_TOKEN"},
	{ID: "twilio", Name: "Twilio", Host: "api.twilio.com", Description: "Communication APIs (SMS, voice, email)", AuthType: "basic", SuggestedCredentialKey: "TWILIO_AUTH_TOKEN"},
	{ID: "sendgrid", Name: "SendGrid", Host: "api.sendgrid.com", Description: "Email delivery API", AuthType: "bearer", SuggestedCredentialKey: "SENDGRID_API_KEY"},
	{ID: "aws-s3", Name: "AWS S3", Host: "s3.amazonaws.com", Description: "Amazon S3 object storage", AuthType: "custom", SuggestedCredentialKey: "AWS_SECRET_ACCESS_KEY"},
	{ID: "cloudflare", Name: "Cloudflare", Host: "api.cloudflare.com", Description: "Cloudflare API", AuthType: "bearer", SuggestedCredentialKey: "CLOUDFLARE_API_TOKEN"},
	{ID: "datadog", Name: "Datadog", Host: "api.datadoghq.com", Description: "Monitoring and analytics", AuthType: "api-key", SuggestedCredentialKey: "DATADOG_API_KEY"},
	{ID: "pagerduty", Name: "PagerDuty", Host: "api.pagerduty.com", Description: "Incident management", AuthType: "bearer", SuggestedCredentialKey: "PAGERDUTY_TOKEN"},
	{ID: "linear", Name: "Linear", Host: "api.linear.app", Description: "Project management and issue tracking", AuthType: "bearer", SuggestedCredentialKey: "LINEAR_API_KEY"},
	{ID: "jira", Name: "Jira", Host: "*.atlassian.net", Description: "Atlassian Jira project tracking", AuthType: "basic", SuggestedCredentialKey: "JIRA_API_TOKEN"},
	{ID: "notion", Name: "Notion", Host: "api.notion.com", Description: "Notion workspace API", AuthType: "bearer", SuggestedCredentialKey: "NOTION_TOKEN"},
	{ID: "vercel", Name: "Vercel", Host: "api.vercel.com", Description: "Vercel deployment platform", AuthType: "bearer", SuggestedCredentialKey: "VERCEL_TOKEN"},
	{ID: "supabase", Name: "Supabase", Host: "*.supabase.co", Description: "Supabase backend-as-a-service", AuthType: "bearer", SuggestedCredentialKey: "SUPABASE_KEY"},
	{ID: "resend", Name: "Resend", Host: "api.resend.com", Description: "Email API for developers", AuthType: "bearer", SuggestedCredentialKey: "RESEND_API_KEY"},
	{ID: "postmark", Name: "Postmark", Host: "api.postmarkapp.com", Description: "Transactional email service", AuthType: "api-key", SuggestedCredentialKey: "POSTMARK_SERVER_TOKEN"},
	{ID: "sentry", Name: "Sentry", Host: "sentry.io", Description: "Error tracking and performance monitoring", AuthType: "bearer", SuggestedCredentialKey: "SENTRY_AUTH_TOKEN"},
	{ID: "shopify", Name: "Shopify", Host: "*.myshopify.com", Description: "Shopify e-commerce API", AuthType: "api-key", SuggestedCredentialKey: "SHOPIFY_ACCESS_TOKEN"},
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
