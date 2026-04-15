# Agent Vault — Agent Protocol

Agent Vault is an HTTP proxy that attaches credentials to your outbound requests. You never see or handle credentials directly — route authenticated requests through Agent Vault and it authenticates on your behalf.

## When to use

1. Check that `AGENT_VAULT_SESSION_TOKEN` is set — if not, Agent Vault is not available
2. Call `/discover` to get the list of brokerable services
3. For requests to hosts listed in the discover response, route through Agent Vault
4. For all other requests, make them directly

## Environment variables

| Variable | Description |
|----------|-------------|
| `AGENT_VAULT_ADDR` | Base URL of the Agent Vault server (e.g. `http://127.0.0.1:14321`) |
| `AGENT_VAULT_SESSION_TOKEN` | Bearer token for authenticating with Agent Vault |
| `AGENT_VAULT_VAULT` | Vault the session is scoped to |

## The X-Vault header

If you received your token via an agent invite (instance-level agent token), you must include `X-Vault: {vault_name}` on all vault-scoped requests (discover, proxy, proposals). If `AGENT_VAULT_VAULT` is set, use that value. Vault-scoped sessions (from `vault run`) do not need this header.

## Discover available services

Always call this first to learn which services have credentials configured:

```
GET {AGENT_VAULT_ADDR}/discover
Authorization: Bearer {AGENT_VAULT_SESSION_TOKEN}
X-Vault: {vault_name}
```

Response includes `vault`, `proxy_url`, `services` (host + description), and `available_credentials` (key names only — values are never exposed). Before creating a proposal, check `available_credentials` to avoid requesting credentials that already exist in the vault.

## Route requests through the proxy

For hosts returned by `/discover`:

```
{AGENT_VAULT_ADDR}/proxy/{target_host}/{path}[?query]
Authorization: Bearer {AGENT_VAULT_SESSION_TOKEN}
```

Agent Vault strips your auth header, attaches real credentials, and forwards over HTTPS.

## Request access to new services via proposals

When you get a `403` for a host not in `/discover`, create a proposal to request access. The 403 response includes a `proposal_hint` with the denied host.

**Before proposing a proposal, look up how the target service authenticates API requests** to choose the correct auth type.

```json
POST {AGENT_VAULT_ADDR}/v1/proposals
Authorization: Bearer {AGENT_VAULT_SESSION_TOKEN}
Content-Type: application/json

{
  "services": [{
    "action": "set",
    "host": "api.stripe.com",
    "description": "Stripe API",
    "auth": {"type": "bearer", "token": "STRIPE_KEY"}
  }],
  "credentials": [{
    "action": "set",
    "key": "STRIPE_KEY",
    "description": "Stripe API key",
    "obtain": "https://dashboard.stripe.com/apikeys",
    "obtain_instructions": "Developers > API Keys > Reveal test key"
  }],
  "message": "Need Stripe API key for billing feature",
  "user_message": "I need access to your Stripe account to build the checkout page."
}
```

### Auth types

| Type | Config | Common services |
|------|--------|----------------|
| `bearer` | `{"type": "bearer", "token": "SECRET_KEY"}` | Stripe, GitHub, OpenAI |
| `basic` | `{"type": "basic", "username": "API_KEY"}` | Ashby, Jira (email + token) |
| `api-key` | `{"type": "api-key", "key": "SECRET", "header": "x-api-key"}` | Anthropic |
| `custom` | `{"type": "custom", "headers": {"X-Key": "{{ SECRET }}"}}` | Anything else |

### After creating a proposal

1. Present the `approval_url` to the user conversationally
2. Poll `GET {AGENT_VAULT_ADDR}/v1/proposals/{id}` every 2 seconds until status is `applied`
3. Retry your original request

## Error handling

| Status | Meaning | Action |
|--------|---------|--------|
| 401 | Invalid or expired token | Check `AGENT_VAULT_SESSION_TOKEN` |
| 403 | Host not allowed | Propose a proposal |
| 429 | Too many pending proposals | Wait for review |
| 502 | Missing credential or upstream unreachable | Tell user a credential may need to be added |

## Rules

- **Never** extract, log, or display credential values
- **Never** hardcode tokens — always read from `AGENT_VAULT_SESSION_TOKEN`
- **Only** request hosts returned by `/discover` — if not listed, propose a proposal
- Do not modify or forge the `Authorization` header beyond using your token
