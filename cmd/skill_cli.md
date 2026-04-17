---
name: agent-vault-cli
description: >-
  Agent Vault CLI: manage transparent credential injection for external
  services (Linear, GitHub, Stripe, Slack, Jira, etc.) using the agent-vault
  binary. Use when the task involves interacting with any third-party API or
  service that requires credentials, or when writing code that needs
  environment variables for secrets/API keys.
compatibility: Requires a running Agent Vault server, the agent-vault binary on $PATH, and AGENT_VAULT_SESSION_TOKEN environment variable
metadata:
  author: dangtony98
  version: "0.3.0"
---

# Agent Vault (CLI)

You have access to Agent Vault, a transparent HTTPS proxy that injects credentials into your outbound calls. You never see or handle credentials directly -- make API calls to the real host as normal and Agent Vault attaches the real credentials at the proxy boundary.

## CRITICAL: Always Check Agent Vault First

**Before telling the user you cannot access an external service, you MUST check Agent Vault.** This applies whenever a task involves any third-party service or API -- project management (Linear, Jira, Asana), source control (GitHub, GitLab), communication (Slack, Discord), payments (Stripe), databases, or any other authenticated service.

**Your workflow for ANY external service interaction:**
1. Check that `AGENT_VAULT_SESSION_TOKEN` is set (it should be if you were launched via `agent-vault vault run`)
2. Run `agent-vault vault discover --json` to see which hosts have credentials configured
3. If the host is listed, **just make the request to the real API URL** -- Agent Vault transparently injects the credential
4. If the host is NOT listed, create a proposal via CLI (the user approves and provides credentials)
5. Only tell the user you cannot access a service if Agent Vault is not available at all (no session token)

**Never say "I don't have access to X" without checking discover first.** Agent Vault may already have credentials configured for the service you need.

**Not every HTTP request needs Agent Vault credentials.** Unauthenticated requests or requests to hosts not configured in Agent Vault still pass through the proxy unmodified -- no special handling required.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AGENT_VAULT_ADDR` | Base URL of the Agent Vault server (e.g. `http://127.0.0.1:14321`) |
| `AGENT_VAULT_SESSION_TOKEN` | Bearer token for authenticating with Agent Vault's control-plane endpoints (`discover`, proposals, etc.) |
| `AGENT_VAULT_VAULT` | Vault name (set for user-scoped sessions via `vault run`; instance-level agent tokens use `X-Vault` header instead) |

`vault run` also pre-configures `HTTPS_PROXY`, `NO_PROXY`, and CA-trust variables (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`) so HTTPS calls from your process route through the broker transparently. You don't manage these yourself.

## Discover Available Services (Start Here)

**Always run this first** to learn which hosts have credentials configured:

```bash
agent-vault vault discover --json
```

Response includes `vault`, `services` (host + description), `available_credentials` (key names only, values are never exposed), and `proxy_url` (only needed for the explicit-proxy fallback below). Use `available_credentials` to reference existing credentials in proposals instead of creating duplicate slots.

**Browse service templates:** `agent-vault catalog --json` lists built-in service templates with suggested credential keys and auth types. No auth needed.

## Making Requests

**Just call the real API URL.** When you were launched via `agent-vault vault run`, your HTTPS traffic already routes through Agent Vault transparently — `HTTPS_PROXY` and the broker's CA cert are pre-configured in your environment. Agent Vault intercepts the call, looks up the host in the vault's services, injects the credential, and forwards over HTTPS.

```bash
curl https://api.stripe.com/v1/charges
curl https://api.github.com/user
```

Your code can leave the upstream auth header blank or set it to a placeholder — Agent Vault attaches the real credential at the proxy boundary, so the value in your env can be anything (or absent). Standard HTTP clients (curl, fetch, requests, axios, the Go stdlib, etc.) honor `HTTPS_PROXY` automatically.

### Fallback: explicit `/proxy/{host}/{path}`

Use the explicit proxy URL only when transparent MITM isn't viable:

- The HTTP client doesn't honor `HTTPS_PROXY` (rare)
- You weren't launched via `vault run`, so your environment lacks the broker's CA trust
- The operator started the server with `--mitm-port 0`, or you with `--no-mitm`

```
{AGENT_VAULT_ADDR}/proxy/{target_host}/{path}[?query]
Authorization: Bearer {AGENT_VAULT_SESSION_TOKEN}
```

Agent Vault strips your `Authorization` header (it carried your session token), injects the real credentials, and forwards over HTTPS. Same credential injection as the transparent path — just URL-rewritten.

## Managing Services Directly

If you have vault admin role, you can add or remove services directly without proposals:

```bash
# Add or update a service (upsert by host)
agent-vault vault service add \
  --host api.stripe.com --auth-type bearer --token-key STRIPE_KEY \
  --description "Stripe API"

# Add services from a YAML file (upsert, non-destructive)
agent-vault vault service add -f services.yaml

# Remove a specific service
agent-vault vault service remove api.stripe.com --yes

# List all configured services
agent-vault vault service list
```

Use `service add` when you already have credentials stored and just need to configure the proxy rule. Use proposals when the human needs to provide new credentials.

## Proposals -- Requesting and Storing Credentials

Proposals are the primary way to exchange credentials with a human operator. Use them whenever you:

- **Need a credential supplied by a human** -- create a proposal with a credential slot and the human will provide the value at approval time.
- **Want to store a credential back** -- include the value in a credential slot and the human confirms it at approval.
- **Need proxy access to a new host** -- propose a service with an `auth` config so Agent Vault can authenticate on your behalf.

When you get a `403` for a host not in discover, the response includes a `proposal_hint` with the denied host.

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

**Passthrough** allowlists a host but does not store or inject a credential. Use it only when the operator has decided their client already holds the credential and wants netguard / audit / MITM coverage without putting the secret in the vault. For the default case (agent needs the credential from the vault), use one of the credentialed types above.

Header handling on passthrough depends on the ingress the client uses:

- **Transparent MITM (`HTTPS_PROXY`, the default under `vault run`):** hop-by-hop and `Proxy-Authorization` are stripped. `Authorization` and all other client headers flow through unchanged — use this ingress if you need to forward an upstream `Authorization: Bearer <target-token>` through a passthrough service.
- **Explicit `/proxy/{host}/{path}` fallback:** hop-by-hop, `X-Vault`, **and** `Authorization` are stripped before the request is forwarded. `Authorization` carries the Agent Vault session token on this ingress, so clients cannot use it to carry an upstream credential. Client headers the target accepts via `Cookie` or a custom header still flow through.

### Creating a Proposal

**Flag-driven mode (common cases):**

```bash
# Service + credential
agent-vault vault proposal create \
  --host api.stripe.com --auth-type bearer --token-key STRIPE_KEY \
  --credential STRIPE_KEY="Stripe API key" \
  -m "Need Stripe API key for billing feature" --json

# Credential only (no host/service needed)
agent-vault vault proposal create \
  --credential DB_PASSWORD="Production database password" \
  -m "Need database credentials" --json

# Complex/multi-service (JSON mode)
agent-vault vault proposal create -f - --json <<'EOF'
{
  "services": [{"action": "set", "host": "api.stripe.com", "description": "Stripe API", "auth": {"type": "bearer", "token": "STRIPE_KEY"}}],
  "credentials": [{"action": "set", "key": "STRIPE_KEY", "description": "Stripe API key"}],
  "message": "Need Stripe access"
}
EOF
```

Flag-driven auth flags by type:
- **bearer**: `--auth-type bearer --token-key CREDENTIAL_KEY`
- **basic**: `--auth-type basic --username-key USER_KEY [--password-key PASS_KEY]`
- **api-key**: `--auth-type api-key --api-key-key KEY [--api-key-header x-api-key] [--api-key-prefix "ApiKey "]`
- **passthrough**: `--auth-type passthrough` (no credential flags; any credential flag is rejected)

Other flags: `--description` (service description), `--user-message` (shown on browser approval page), `--credential KEY=description` (repeatable).

Key fields (JSON mode):
- `services[].action` -- `"set"` (upsert, needs `host` + `auth`) or `"delete"` (needs `host` only)
- `services[].auth` -- authentication config. Types: `bearer` (`token`), `basic` (`username`, optional `password`), `api-key` (`key` + `header`, optional `prefix`), `custom` (`headers` map with `{{ KEY }}` templates), `passthrough` (no credential fields)
- `credentials[].action` -- `"set"` (omit `value` for human to supply; include `value` to store back) or `"delete"`
- `credentials` -- only declare credentials not already in `available_credentials`. Every credential referenced in auth configs must resolve to a slot or existing credential (400 otherwise)
- `message` -- developer-facing explanation; `user_message` -- shown on the browser approval page
- `credentials[].obtain` -- URL where the human can get the credential; `obtain_instructions` -- steps to find it

**After creating a proposal:**
1. Present the `approval_url` to the user conversationally -- e.g. "I need access to your Stripe account. Click here to connect it: -> {approval_url}"
2. Immediately start polling `GET {AGENT_VAULT_ADDR}/v1/proposals/{id}` -- do NOT wait for the user to say "go on" or confirm. Poll every 3s for the first 30s, then every 10s. Stop after 10 minutes (proposal may have expired).
3. Once status is `applied`, automatically retry your original request and continue your task

**Check status:** `GET {AGENT_VAULT_ADDR}/v1/proposals/{id}` with `Authorization: Bearer {AGENT_VAULT_SESSION_TOKEN}` -- returns `pending`, `applied`, `rejected`, or `expired`

## Building Code That Needs Credentials

When you are writing or modifying application code that requires secrets or API keys (e.g. `process.env.STRIPE_KEY`, `os.Getenv("DB_PASSWORD")`), use Agent Vault to ensure those credentials are tracked and available.

**Workflow:**
1. Write the code referencing the environment variable as normal (e.g. `process.env.STRIPE_KEY`)
2. Run `agent-vault vault discover --json` and check `available_credentials` for the key
3. If the key exists, you're done -- the credential is already stored in the vault
4. If the key is missing, create a credential-only proposal so the human can provide the value:

```bash
agent-vault vault proposal create \
  --credential STRIPE_KEY="Stripe secret key for payment processing" \
  -m "Adding Stripe integration -- need API key" \
  --user-message "The app needs a Stripe secret key to process payments. You can find it at https://dashboard.stripe.com/apikeys" \
  --json
```

5. Present the `approval_url` to the user and poll until approved (same as service proposals)
6. Update `.env.example` (or equivalent) to document the new variable

**Multiple credentials at once:** If your code change introduces several env vars, batch them in one proposal:

```bash
agent-vault vault proposal create \
  --credential DB_HOST="Database hostname" \
  --credential DB_PASSWORD="Database password" \
  -m "Adding database connection -- need credentials" --json
```

**Key points:**
- Use credential-only proposals (no `--host`/`--auth-type`) when the credential is for the application, not for proxying through Agent Vault
- Always check `available_credentials` first to avoid proposing duplicates
- Include `obtain` URLs or `obtain_instructions` in JSON mode proposals to help the human find the credential

## Reading Credentials

To read the decrypted value of a credential (requires member+ vault role):

```bash
agent-vault vault credential get <key>
```

Prints the raw value to stdout (pipe-friendly). Useful for configuration tasks where you need to read a stored value.

## Error Handling

- 401: Invalid or expired token -- check `AGENT_VAULT_SESSION_TOKEN`
- 403: Host not allowed -- create a proposal
- 429: Too many pending proposals -- wait for review
- 502: Missing credential or upstream unreachable, tell user a credential may need to be added

## Rules

- **Never** attempt to extract, log, or display credentials
- **Never** hardcode tokens -- always read from `AGENT_VAULT_SESSION_TOKEN`
- **Only** request hosts returned by discover -- if a host isn't listed, create a proposal
- If you receive a `credential_not_found` error, inform the user which credential is missing
- Do not modify or forge the `Authorization` header beyond using your session token
