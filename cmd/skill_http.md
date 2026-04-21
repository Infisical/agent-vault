---
name: agent-vault-http
description: >-
  Agent Vault HTTP: a transparent HTTPS proxy that injects credentials for
  external services (Linear, GitHub, Stripe, Slack, Jira, etc.). Use when the
  task involves any third-party API or service that requires credentials, or
  when writing code that needs environment variables for secrets/API keys.
compatibility: Requires a running Agent Vault server and AGENT_VAULT_SESSION_TOKEN environment variable
metadata:
  author: dangtony98
  version: "0.4.0"
---

# Agent Vault (HTTP)

You have access to Agent Vault, a transparent HTTPS proxy that injects credentials into your outbound calls. You never see or handle credentials directly -- make API calls to the real host as normal and Agent Vault attaches the real credentials at the proxy boundary.

## CRITICAL: Always Check Agent Vault First

**Before telling the user you cannot access an external service, you MUST check Agent Vault.** This applies whenever a task involves any third-party service or API -- project management (Linear, Jira, Asana), source control (GitHub, GitLab), communication (Slack, Discord), payments (Stripe), databases, or any other authenticated service.

**Your workflow for ANY external service interaction:**
1. Check that `AGENT_VAULT_SESSION_TOKEN` is set
2. Call `GET {AGENT_VAULT_ADDR}/discover` to see which hosts have credentials configured
3. If the host is listed, **just make the request to the real API URL** -- Agent Vault transparently injects the credential
4. If the host is NOT listed, create a proposal (the user approves and provides credentials)
5. Only tell the user you cannot access a service if Agent Vault is not available at all (no session token)

**Never say "I don't have access to X" without checking /discover first.** Agent Vault may already have credentials configured for the service you need.

**Not every HTTP request needs Agent Vault credentials.** Unauthenticated requests or requests to hosts not configured in Agent Vault still pass through the proxy unmodified -- no special handling required.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AGENT_VAULT_ADDR` | Base URL of the Agent Vault server (e.g. `http://127.0.0.1:14321`) |
| `AGENT_VAULT_SESSION_TOKEN` | Bearer token for authenticating with Agent Vault's control-plane endpoints (`/discover`, proposals, etc.) |
| `AGENT_VAULT_VAULT` | Vault name (set for user-scoped sessions via `vault run`) |

`vault run` also pre-configures `HTTPS_PROXY`, `NO_PROXY`, `NODE_USE_ENV_PROXY`, and CA-trust variables (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `DENO_CERT`) so HTTPS calls from your process route through the broker transparently. You don't manage these yourself.

## Discover Available Services (Start Here)

**Always call this first** to learn which hosts have credentials configured:

```
GET {AGENT_VAULT_ADDR}/discover
Authorization: Bearer {AGENT_VAULT_SESSION_TOKEN}
X-Vault: {vault_name}
```

**Note:** If `AGENT_VAULT_VAULT` is set, the server uses it automatically. Instance-level agent tokens (persistent agents) must include the `X-Vault` header on all vault-scoped requests.

Response includes `vault`, `services` (host + description), and `available_credentials` (key names only, values are never exposed). Use `available_credentials` to reference existing credentials in proposals instead of creating duplicate slots.

**Browse service templates:**

```
GET {AGENT_VAULT_ADDR}/v1/service-catalog
```

Returns built-in service templates with suggested credential keys and auth types. No auth required.

## Making Requests

**Just call the real API URL.** When you were launched via `agent-vault vault run`, your HTTPS traffic already routes through Agent Vault transparently — `HTTPS_PROXY` and the broker's CA cert are pre-configured in your environment. Agent Vault intercepts the call, looks up the host in the vault's services, injects the credential, and forwards over HTTPS.

```
GET https://api.stripe.com/v1/charges
GET https://api.github.com/user
```

Your code can leave the upstream auth header blank or set it to a placeholder — Agent Vault attaches the real credential at the proxy boundary, so the value in your env can be anything (or absent). Standard HTTP clients (curl, fetch, requests, axios, the Go stdlib, etc.) honor `HTTPS_PROXY` automatically.

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
bearer      -- Authorization: Bearer <token>          {"auth": {"type": "bearer", "token": "SECRET_KEY"}}
basic       -- HTTP Basic (user, optional password)    {"auth": {"type": "basic", "username": "API_KEY"}}
api-key     -- key in a named header, optional prefix  {"auth": {"type": "api-key", "key": "SECRET", "header": "x-api-key"}}
custom      -- freeform header templates               {"auth": {"type": "custom", "headers": {"X-Key": "{{ SECRET }}"}}}
passthrough -- forward client headers, inject nothing  {"auth": {"type": "passthrough"}}
```

Common services: Stripe (bearer), GitHub (bearer), OpenAI (bearer), Ashby (basic -- API key as username), Jira (basic -- email + token), Anthropic (api-key, header: x-api-key). If unlisted, check the API docs.

**Passthrough** allowlists a host but does not store or inject a credential. Use it only when the operator has decided their client already holds the credential and wants netguard / audit / MITM coverage without putting the secret in the vault. For the default case (agent needs the credential from the vault), use one of the credentialed types above. Passthrough auth entries reject all credential fields (`token`, `username`, `password`, `key`, `header`, `prefix`, `headers`).

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
- `services[].action` -- `"set"` (upsert, needs `host` + `auth` **or** an `enabled` change) or `"delete"` (needs `host` only)
- `services[].auth` -- authentication config. Types: `bearer` (`token`), `basic` (`username`, optional `password`), `api-key` (`key` + `header`, optional `prefix`), `custom` (`headers` map with `{{ KEY }}` templates), `passthrough` (no credential fields)
- `services[].enabled` -- optional boolean. Omitted means "enabled" for new services. A `"set"` proposal may supply `enabled` alone (no `auth`) to flip an existing service's state without replacing its auth config -- useful for staged rollouts where the operator wires credentials before flipping traffic on
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

## Error Handling

- 401: Invalid or expired token -- check `AGENT_VAULT_SESSION_TOKEN`
- 403 `forbidden`: Host not allowed -- create a proposal
- 403 `service_disabled`: Host is configured but currently disabled by an operator. Don't create a new proposal; surface the error to the user so they can re-enable it
- 429: Rate limited. The response carries a `Retry-After` header (seconds) and a JSON body `{"error":"too_many_requests", ...}`. Respect `Retry-After` — wait that many seconds before retrying. Do **not** tight-loop or switch to a different Agent Vault ingress to bypass the limit; the MITM and explicit `/proxy/` paths share one budget. If the limit trips repeatedly on normal work, ask the instance owner to raise the limit in **Manage Instance → Settings → Rate Limiting**.
- 502: Missing credential or upstream unreachable, tell user a credential may need to be added

## Rules

- **Never** attempt to extract, log, or display credentials
- **Never** hardcode tokens -- always read from `AGENT_VAULT_SESSION_TOKEN`
- **Only** request hosts returned by `/discover` -- if a host isn't listed, create a proposal
- If you receive a `credential_not_found` error, inform the user which credential is missing
- Do not modify or forge the `Authorization` header beyond using your token
