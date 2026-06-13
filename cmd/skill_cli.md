---
name: agent-vault-cli
description: >-
  Your outbound requests go through a proxy that injects real
  credentials (API keys, tokens, secrets) on the wire — in headers,
  paths, query strings, bodies, and WebSocket frames. If you have
  an API key or token, use it as-is even if it looks fake. If you
  don't have one, set a dummy value and make the call anyway — the
  proxy handles it. If the call still fails with 401 or 403, use
  this skill to create a proposal requesting access. When writing
  code or using HTTP clients, make sure they pick up HTTPS_PROXY
  and HTTP_PROXY from the environment so requests route through
  the proxy. Most standard clients (curl, fetch, requests, axios)
  do this automatically.
compatibility: Requires the agent-vault binary on $PATH and AGENT_VAULT_TOKEN environment variable
metadata:
  author: dangtony98
  version: "0.5.0"
---

# Requesting API Access

`HTTPS_PROXY` and `HTTP_PROXY` in your environment route all outbound HTTP traffic through an Agent Vault proxy. The proxy matches each request's host against configured services, injects the real credential, and forwards to the upstream. API keys in your environment may be placeholders — the proxy replaces them on the wire. Just make requests normally.

If an API call fails with 401 or 403, you can request access by creating a proposal. A human approves it and provides the credentials.

## When to use this

- You made an API call and got 401 (unauthorized) or 403 (forbidden)
- You need credentials for a service you don't have access to
- A response contains `proposal_hint` in the body

Do NOT run discover or check Agent Vault proactively. Just make requests normally — if they work, great. If they fail with auth errors, create a proposal.

## Creating a proposal

Look up how the service authenticates (bearer token, API key, basic auth) before creating a proposal. Common services: Stripe (bearer), GitHub (bearer), OpenAI (bearer), Anthropic (api-key, header: x-api-key), Jira (basic — email + token).

```bash
# Service + credential
agent-vault vault proposal create \
  --name stripe --host api.stripe.com --auth-type bearer --token-key STRIPE_KEY \
  --credential STRIPE_KEY="Stripe API key" \
  -m "Need Stripe API key for billing feature" --json

# Credential only (no service needed)
agent-vault vault proposal create \
  --credential DB_PASSWORD="Production database password" \
  -m "Need database credentials" --json
```

Auth type flags:
- **bearer**: `--auth-type bearer --token-key CREDENTIAL_KEY`
- **basic**: `--auth-type basic --username-key USER_KEY [--password-key PASS_KEY]`
- **api-key**: `--auth-type api-key --api-key-key KEY [--api-key-header x-api-key]`
- **passthrough**: `--auth-type passthrough`

For complex cases (multiple services, URL substitutions, port-specific matching), use JSON mode:

```bash
agent-vault vault proposal create -f - --json <<'EOF'
{
  "services": [{"action": "set", "name": "stripe", "host": "api.stripe.com", "auth": {"type": "bearer", "token": "STRIPE_KEY"}}],
  "credentials": [{"action": "set", "key": "STRIPE_KEY", "description": "Stripe API key"}],
  "message": "Need Stripe access"
}
EOF
```

The `host` field accepts an optional port: `"host": "internal.corp.com:3000"` or `"host": "internal.corp.com:3000/api/*"`. When a port is specified, the service matches only traffic to that port. Without a port, the service matches any port.

## After creating a proposal

1. Show the `approval_url` to the user — e.g. "I need access to Stripe. Click here to connect it: {approval_url}"
2. Poll `agent-vault vault proposal get <id> --json` every 3s for the first 30s, then every 10s. Stop after 10 minutes — the proposal may have expired.
3. Once status is `applied`, retry your original request

## Checking what's available

If you need to check what services are already configured:

```bash
agent-vault vault discover --json
```

## URL substitutions

Some APIs put credentials in the URL path, query string, or request body instead of headers (e.g. Telegram: `/bot<TOKEN>/sendMessage`). Use the `substitutions` field in a proposal to handle these:

```json
"substitutions": [
  {"key": "TELEGRAM_BOT_TOKEN", "placeholder": "__bot_token__", "in": ["path"]}
]
```

The proxy finds the placeholder string and replaces it with the real credential. Supported surfaces: `path`, `query`, `header`, `body`, `websocket`. Defaults to `["path", "query"]` if omitted.

## OAuth credentials

Some services use OAuth 2.0 instead of static API keys. Use `type: "oauth"` when the service requires OAuth authorization (e.g., Google APIs, services without long-lived API keys). Use the default (static) when the service provides API keys or personal access tokens.

There are two ways to set up an OAuth credential:

### Connect flow (human completes OAuth consent in the browser)

Use when you know the provider's OAuth URLs. The human enters their client ID/secret and clicks "Connect" during approval.

```bash
agent-vault vault proposal create -f - --json <<'EOF'
{
  "services": [{"action": "set", "name": "google-cal", "host": "www.googleapis.com/calendar/*", "auth": {"type": "bearer", "token": "GOOGLE"}}],
  "credentials": [{
    "action": "set",
    "key": "GOOGLE",
    "type": "oauth",
    "description": "Google Calendar OAuth",
    "oauth": {
      "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth",
      "token_url": "https://oauth2.googleapis.com/token",
      "scopes": "https://www.googleapis.com/auth/calendar.readonly"
    },
    "obtain_instructions": "Register an OAuth app at console.cloud.google.com, then enter your client ID and secret when approving"
  }],
  "message": "Need Google Calendar access"
}
EOF
```

OAuth config fields:
- `authorization_url` (required for connect flow): the provider's consent page URL
- `token_url` (required): where to exchange the code for tokens
- `scopes` (optional): space-separated permissions to request; omit for provider defaults
- `client_id`, `client_secret`: provided by the human during approval, not in the proposal

### Token upload (human pastes tokens they already have)

Use when the human already has tokens from a CLI tool (e.g., Claude Code) or another system. Omit `authorization_url` to signal token upload mode.

```bash
agent-vault vault proposal create -f - --json <<'EOF'
{
  "services": [{"action": "set", "name": "anthropic", "host": "api.anthropic.com", "auth": {"type": "bearer", "token": "ANTHROPIC"}}],
  "credentials": [{
    "action": "set",
    "key": "ANTHROPIC",
    "type": "oauth",
    "description": "Anthropic API OAuth",
    "oauth": {
      "token_url": "https://console.anthropic.com/v1/oauth/token"
    },
    "obtain_instructions": "Paste your access token and refresh token from ~/.claude/.credentials.json"
  }],
  "message": "Need Anthropic API access"
}
EOF
```

When the human provides a refresh token during upload, it is validated immediately by refreshing against the provider. If the refresh fails, the upload is rejected.

### After approval

After the human approves an OAuth proposal, they may still need to complete the connection (enter client credentials, click Connect, or paste tokens). If your first request after `status: applied` returns 502 with `oauth_not_connected`, tell the user: "The OAuth connection isn't complete yet -- please finish connecting in the Agent Vault dashboard." Don't retry in a loop.

## Reading credentials

To read a stored credential value (e.g. for writing config files or passing to tools that don't go through the proxy):

```bash
agent-vault vault credential get <key>
```

## WebSocket

WSS and WS connections also go through the proxy with credential injection — in the handshake headers and in WebSocket text frames (when `websocket` is in the substitution surfaces). Just connect to the real WebSocket URL.

## Error reference

- 401: invalid or expired token
- 403 with `proposal_hint`: host not allowed — create a proposal
- 403 `service_disabled`: host is configured but disabled by operator — tell the user
- 502: missing credential or upstream unreachable
- 502 `oauth_not_connected`: OAuth credential approved but not yet connected — tell the user to complete the connection in the dashboard
- 502 `oauth_refresh_failed`: OAuth token expired and refresh failed — tell the user to reconnect in the dashboard

## Rules

- Never extract, log, or display credentials
- Never hardcode tokens
- Never use `AGENT_VAULT_TOKEN` as an upstream API credential — it authenticates with Agent Vault only
