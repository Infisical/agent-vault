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

For complex cases (multiple services, URL substitutions), use JSON mode:

```bash
agent-vault vault proposal create -f - --json <<'EOF'
{
  "services": [{"action": "set", "name": "stripe", "host": "api.stripe.com", "auth": {"type": "bearer", "token": "STRIPE_KEY"}}],
  "credentials": [{"action": "set", "key": "STRIPE_KEY", "description": "Stripe API key"}],
  "message": "Need Stripe access"
}
EOF
```

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

## Rules

- Never extract, log, or display credentials
- Never hardcode tokens
- Never use `AGENT_VAULT_TOKEN` as an upstream API credential — it authenticates with Agent Vault only
