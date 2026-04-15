---
name: agent-vault-http
description: >-
  Agent Vault HTTP: interact with Agent Vault's authenticated HTTP proxy for
  external services (Linear, GitHub, Stripe, Slack, Jira, etc.) using only
  HTTP requests. Use when the task involves any third-party API or service
  that requires credentials, or when writing code that needs environment
  variables for secrets/API keys.
compatibility: Requires a running Agent Vault server and AGENT_VAULT_SESSION_TOKEN environment variable
metadata:
  author: dangtony98
  version: "0.2.0"
---

# Agent Vault (HTTP)

You have access to Agent Vault, an HTTP proxy that attaches credentials to your outbound requests. You never see or handle credentials directly -- route authenticated requests through Agent Vault and it authenticates on your behalf.

## CRITICAL: Always Check Agent Vault First

**Before telling the user you cannot access an external service, you MUST check Agent Vault.** This applies whenever a task involves any third-party service or API -- project management (Linear, Jira, Asana), source control (GitHub, GitLab), communication (Slack, Discord), payments (Stripe), databases, or any other authenticated service.

**Your workflow for ANY external service interaction:**
1. Check that `AGENT_VAULT_SESSION_TOKEN` is set
2. Call `GET {AGENT_VAULT_ADDR}/discover` to see what services are available
3. If the service is listed, route your request through the Agent Vault proxy -- done
4. If the service is NOT listed, create a proposal (the user can approve and provide credentials)
5. Only tell the user you cannot access a service if Agent Vault is not available at all (no session token)

**Never say "I don't have access to X" without checking /discover first.** Agent Vault may already have credentials configured for the service you need.

**Not every HTTP request needs to go through Agent Vault.** Unauthenticated requests or requests to services not configured in Agent Vault should be made directly.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AGENT_VAULT_ADDR` | Base URL of the Agent Vault server (e.g. `http://127.0.0.1:14321`) |
| `AGENT_VAULT_SESSION_TOKEN` | Bearer token for authenticating with Agent Vault |
| `AGENT_VAULT_VAULT` | Vault name (set for user-scoped sessions via `vault run`; for instance-level agent sessions, use the `X-Vault` header instead) |

## Discover Available Services (Start Here)

**Always call this first** to learn which services have credentials configured:

```
GET {AGENT_VAULT_ADDR}/discover
Authorization: Bearer {AGENT_VAULT_SESSION_TOKEN}
X-Vault: {vault_name}
```

**Note:** If `AGENT_VAULT_VAULT` is set, the server uses it automatically. Instance-level agent sessions (persistent agents) must include the `X-Vault` header on all vault-scoped requests.

Response includes `vault`, `proxy_url`, `services` (host + description), and `available_credentials` (key names only, values are never exposed). Use `available_credentials` to reference existing credentials in proposals instead of creating duplicate slots.

**Browse service templates:**

```
GET {AGENT_VAULT_ADDR}/v1/service-catalog
```

Returns built-in service templates with suggested credential keys and auth types. No auth required.

## Making Requests Through Agent Vault

For hosts returned by `/discover`, route requests through Agent Vault's proxy:

```
{AGENT_VAULT_ADDR}/proxy/{target_host}/{path}[?query]
Authorization: Bearer {AGENT_VAULT_SESSION_TOKEN}
```

Agent Vault strips your auth header, injects the real credentials, and forwards the request over HTTPS.

## Proposals -- Requesting and Storing Credentials

Proposals are the primary way to exchange credentials with a human operator. Use them whenever you:

- **Need a credential supplied by a human** -- create a proposal with a credential slot and the human will provide the value at approval time.
- **Want to store a credential back** -- include the value in a credential slot and the human confirms it at approval.
- **Need proxy access to a new host** -- propose a service with an `auth` config so Agent Vault can authenticate on your behalf.

When you get a `403` for a host not in `/discover`, the response includes a `proposal_hint` with the denied host.

## Choosing the Right Auth Method

**Before creating a proposal for a new service, you MUST look up how that service authenticates API requests.** If you have internet access, fetch the service's API authentication documentation to determine the correct auth type. Do not guess -- incorrect auth wastes the operator's time and will fail at the proxy.

Agent Vault auth types:

```
bearer    -- Authorization: Bearer <token>          {"auth": {"type": "bearer", "token": "SECRET_KEY"}}
basic     -- HTTP Basic (user, optional password)    {"auth": {"type": "basic", "username": "API_KEY"}}
api-key   -- key in a named header, optional prefix  {"auth": {"type": "api-key", "key": "SECRET", "header": "x-api-key"}}
custom    -- freeform header templates               {"auth": {"type": "custom", "headers": {"X-Key": "{{ SECRET }}"}}}
```

Common services: Stripe (bearer), GitHub (bearer), OpenAI (bearer), Ashby (basic -- API key as username), Jira (basic -- email + token), Anthropic (api-key, header: x-api-key). If unlisted, check the API docs.

### Creating a Proposal

```
POST {AGENT_VAULT_ADDR}/v1/proposals
Authorization: Bearer {AGENT_VAULT_SESSION_TOKEN}
Content-Type: application/json

{
  "services": [{"action": "set", "host": "api.stripe.com", "description": "Stripe API", "auth": {"type": "bearer", "token": "STRIPE_KEY"}}],
  "credentials": [{"action": "set", "key": "STRIPE_KEY", "description": "Stripe API key", "obtain": "https://dashboard.stripe.com/apikeys", "obtain_instructions": "Developers -> API Keys -> Reveal test key"}],
  "message": "Need Stripe API key for billing feature",
  "user_message": "I need access to your Stripe account to build the checkout page."
}
```

Key fields:
- `services[].action` -- `"set"` (upsert, needs `host` + `auth`) or `"delete"` (needs `host` only)
- `services[].auth` -- authentication config. Types: `bearer` (`token`), `basic` (`username`, optional `password`), `api-key` (`key` + `header`, optional `prefix`), `custom` (`headers` map with `{{ KEY }}` templates)
- `credentials[].action` -- `"set"` (omit `value` for human to supply; include `value` to store back) or `"delete"`
- `credentials` -- only declare credentials not already in `available_credentials`. Every credential referenced in auth configs must resolve to a slot or existing credential (400 otherwise)
- `message` -- developer-facing explanation; `user_message` -- shown on the browser approval page
- `credentials[].obtain` -- URL where the human can get the credential; `obtain_instructions` -- steps to find it

**After creating a proposal:**
1. Present the `approval_url` to the user conversationally -- e.g. "I need access to your Stripe account. Click here to connect it: -> {approval_url}"
2. Immediately start polling `GET {AGENT_VAULT_ADDR}/v1/proposals/{id}` -- do NOT wait for the user to say "go on" or confirm. Poll every 3s for the first 30s, then every 10s. Stop after 10 minutes (proposal may have expired).
3. Once status is `applied`, automatically retry your original request and continue your task

**Check status:** `GET {AGENT_VAULT_ADDR}/v1/proposals/{id}` with `Authorization: Bearer {AGENT_VAULT_SESSION_TOKEN}` -- returns `pending`, `applied`, `rejected`, or `expired`

**List proposals:** `GET {AGENT_VAULT_ADDR}/v1/proposals?status=pending`

## Building Code That Needs Credentials

When you are writing or modifying application code that requires secrets or API keys (e.g. `process.env.STRIPE_KEY`, `os.Getenv("DB_PASSWORD")`), use Agent Vault to ensure those credentials are tracked and available.

**Workflow:**
1. Write the code referencing the environment variable as normal (e.g. `process.env.STRIPE_KEY`)
2. Call `GET {AGENT_VAULT_ADDR}/discover` and check `available_credentials` for the key
3. If the key exists, you're done -- the credential is already stored in the vault
4. If the key is missing, create a credential-only proposal so the human can provide the value:

```
POST {AGENT_VAULT_ADDR}/v1/proposals
Authorization: Bearer {AGENT_VAULT_SESSION_TOKEN}
Content-Type: application/json

{
  "credentials": [{"action": "set", "key": "STRIPE_KEY", "description": "Stripe secret key for payment processing", "obtain": "https://dashboard.stripe.com/apikeys", "obtain_instructions": "Developers -> API Keys -> Reveal secret key"}],
  "message": "Adding Stripe integration -- need API key",
  "user_message": "The app needs a Stripe secret key to process payments."
}
```

5. Present the `approval_url` to the user and poll until approved (same as service proposals)
6. Update `.env.example` (or equivalent) to document the new variable

**Multiple credentials at once:** Batch them in one proposal:

```json
{
  "credentials": [
    {"action": "set", "key": "DB_HOST", "description": "Database hostname"},
    {"action": "set", "key": "DB_PASSWORD", "description": "Database password"}
  ],
  "message": "Adding database connection -- need credentials"
}
```

**Key points:**
- Use credential-only proposals (no `services` array) when the credential is for the application, not for proxying through Agent Vault
- Always check `available_credentials` first to avoid proposing duplicates
- Include `obtain` and `obtain_instructions` to help the human find the credential

## Instance-Level Agent Sessions

If you were registered as a persistent agent (via an agent invite), your session is instance-level -- it is not scoped to a single vault. You may have access to multiple vaults. Include the `X-Vault` header on all vault-scoped requests (proxy, discover, proposals, credentials) to select which vault to operate on.

If your session has no expiry, the token works indefinitely. If it does expire, contact your operator for a new session.

## Error Handling

- 401: Invalid or expired token -- check `AGENT_VAULT_SESSION_TOKEN` (persistent agents: contact operator for a new session)
- 403: Host not allowed -- create a proposal
- 429: Too many pending proposals -- wait for review
- 502: Missing credential or upstream unreachable, tell user a credential may need to be added

## Rules

- **Never** attempt to extract, log, or display credentials
- **Never** hardcode tokens -- always read from `AGENT_VAULT_SESSION_TOKEN`
- **Only** request hosts returned by `/discover` -- if a host isn't listed, create a proposal
- If you receive a `credential_not_found` error, inform the user which credential is missing
- Do not modify or forge the `Authorization` header beyond using your session token
