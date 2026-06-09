---
name: agent-vault-cli
description: >-
  Agent Vault CLI: manage transparent credential injection for external
  services (Linear, GitHub, Stripe, Slack, Jira, etc.) using the agent-vault
  binary. Use when the task involves interacting with any third-party API or
  service that requires credentials, or when writing code that needs
  environment variables for secrets/API keys.
compatibility: Requires a running Agent Vault server, the agent-vault binary on $PATH, and AGENT_VAULT_TOKEN environment variable
metadata:
  author: dangtony98
  version: "0.4.0"
---

# Agent Vault (CLI)

You have access to Agent Vault, a transparent HTTP/HTTPS proxy that injects credentials into your outbound calls. You never see or handle credentials directly -- make API calls to the real host as normal (over `https://` or `http://`) and Agent Vault attaches the real credentials at the proxy boundary.

## CRITICAL: Always Check Agent Vault First

**Before telling the user you cannot access an external service, you MUST check Agent Vault.** This applies whenever a task involves any third-party service or API -- project management (Linear, Jira, Asana), source control (GitHub, GitLab), communication (Slack, Discord), payments (Stripe), databases, or any other authenticated service.

**Your workflow for ANY external service interaction:**
1. Check that `AGENT_VAULT_TOKEN` is set (it should be if you were launched via `agent-vault run` — `agent-vault vault run` is the long form)
2. Run `agent-vault vault discover --json` to see which hosts have credentials configured
3. If the host is listed, **just make the request to the real API URL** -- Agent Vault transparently injects the credential
4. If the host is NOT listed, create a proposal via CLI (the user approves and provides credentials)
5. Only tell the user you cannot access a service if Agent Vault is not available at all (no session token)

**Never say "I don't have access to X" without checking discover first.** Agent Vault may already have credentials configured for the service you need.

**Not every HTTP request needs Agent Vault credentials.** Unauthenticated requests or requests to hosts not configured in Agent Vault still pass through the proxy unmodified -- no special handling required.

By default each vault forwards unmatched hosts as plain proxy traffic (no credential injection). An operator may flip a vault into **strict deny mode** (`unmatched_host_policy=deny`), in which case requests to hosts that aren't in discover return `403 forbidden` with a `proposal_hint`. If you see that error, propose the service rather than retrying.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AGENT_VAULT_ADDR` | Base URL of the Agent Vault server (e.g. `http://127.0.0.1:14321`) |
| `AGENT_VAULT_TOKEN` | Bearer token for authenticating with Agent Vault's control-plane endpoints (`discover`, proposals, etc.). Either a vault-scoped session token or a long-lived agent token. |
| `AGENT_VAULT_VAULT` | Vault name. Set automatically by `agent-vault run` in admin mode; supplied by the operator in agent mode. |

`agent-vault run` also pre-configures `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`, `NODE_USE_ENV_PROXY`, and CA-trust variables (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `DENO_CERT`) so HTTP and HTTPS calls from your process both route through the broker transparently. You don't manage these yourself.

Under `--isolation=container`, the same env shape is injected inside a Docker container, but the proxy URL host is `host.docker.internal` instead of `127.0.0.1` and egress to any other destination is blocked by iptables. From your perspective nothing changes — standard HTTP clients pick up the envvars as normal.

### Scoped session tokens

You almost never need to mint your own token — `agent-vault run` already provides one. But if you must hand a separate token to a child process, run:

```bash
agent-vault vault token --ttl 3600
```

Flag: `--ttl` (seconds, 300–604800; default 24h). Tokens are minted with vault role `proxy`. The token is printed to stdout — pipe it into `AGENT_VAULT_TOKEN` for the child process. Operators can list/revoke tokens from each vault's **Tokens** tab in the UI.

### Containerized agent deployment

For unattended deployments (k8s/Fly/ECS, where there's no human to `auth login`), supply the token via env. `agent-vault run` then skips the mint step and treats the env-supplied token as the credential:

```dockerfile
FROM node:20-slim
COPY --from=infisical/agent-vault:latest /usr/local/bin/agent-vault /usr/local/bin/agent-vault
WORKDIR /app
COPY . .
RUN npm ci
ENTRYPOINT ["agent-vault", "run", "--", "npm", "start"]
```

Set three env vars at deploy time:

```
AGENT_VAULT_ADDR=https://vault.example.com
AGENT_VAULT_TOKEN=av_agt_xxx
AGENT_VAULT_VAULT=production
```

The token is either a vault-scoped session token (mint via `agent-vault vault token`) or — more commonly for production — a long-lived agent token issued out-of-band by an operator (see [Agents](https://docs.agent-vault.dev/agents/overview)). `agent-vault run` validates the token against the broker once at startup; bad/expired tokens fail fast with a clear error rather than producing 401s on every proxied call. `--ttl` is rejected in this mode since the token's lifetime is fixed at mint time.

## Discover Available Services (Start Here)

**Always run this first** to learn which hosts have credentials configured:

```bash
agent-vault vault discover --json
```

Response includes `vault`, `services` (each with `name` and `host`), and `available_credentials` (key names only, values are never exposed). Use `available_credentials` to reference existing credentials in proposals instead of creating duplicate slots. `host` is the single matcher field on every surface (read and write): it returns the joined inline form, so a path-scoped service shows up as e.g. `slack.com/api/*`. When two services share the same bare host but scope to different paths (e.g. `slack.com/api/*` vs `slack.com/api/apps.connections.*`), distinguish them by `name` in subsequent operations.

**Browse service templates:** `agent-vault catalog --json` lists built-in service templates with suggested credential keys and auth types. No auth needed.

### Managing Services Directly (vault admin only)

Most agents should raise a [proposal](#proposals----requesting-and-storing-credentials) instead — proposals get a human approval before any service or credential change lands. The CLI commands below mutate the vault directly and require an interactive vault admin login (not an agent token). Use them only when the user explicitly asks you to skip the proposal flow:

```bash
# Add a service (non-destructive upsert by name; --host is required, --name optional —
# when omitted the server slugifies host+path, e.g. api.stripe.com → api-stripe-com)
agent-vault vault service add --name stripe --host api.stripe.com --auth-type bearer --token-key STRIPE_KEY
agent-vault vault service add --name slack-bot --host 'slack.com/api/*' --auth-type bearer --token-key SLACK_BOT_TOKEN

# Toggle enabled/disabled (accepts service name OR host)
agent-vault vault service enable <name-or-host>
agent-vault vault service disable <name-or-host>

# Remove (accepts service name OR host)
agent-vault vault service remove <name-or-host>
```

When two services share a host, pass the canonical `name` from `/discover` — passing the bare host returns 409 `multiple services match host …` with a `candidates` array.

## Making Requests

**Just call the real API URL.** When you were launched via `agent-vault run` (or the long form `agent-vault vault run`), your HTTP and HTTPS traffic already route through Agent Vault transparently — `HTTPS_PROXY`, `HTTP_PROXY`, and the broker's CA cert are pre-configured in your environment. Agent Vault intercepts the call, looks up the host in the vault's services, injects the credential, and forwards to the upstream.

```bash
curl https://api.stripe.com/v1/charges
curl https://api.github.com/user
curl http://internal.example/api/v1/items   # plain http:// works the same way
```

Your code can leave the upstream auth header blank or set it to a placeholder — Agent Vault attaches the real credential at the proxy boundary, so the value in your env can be anything (or absent). Standard HTTP clients (curl, fetch, requests, axios, the Go stdlib, etc.) honor `HTTPS_PROXY`/`HTTP_PROXY` automatically.

### WebSocket / Streaming

`wss://` and `ws://` URLs are brokered through the same proxy mechanism as regular HTTP/HTTPS. Credentials are injected into the WebSocket handshake (`Authorization`, `Sec-WebSocket-Protocol`) the same way as on a normal request — point your client at the real WebSocket URL and Agent Vault attaches the real credential at the proxy boundary.

```
wss://api.openai.com/v1/realtime?model=gpt-realtime
```

Constraints:
- HTTP/1.1 only at the MITM ingress today. HTTP/2 traffic is forwarded but not intercepted, so it bypasses credential injection — pin clients to HTTP/1.1 if you need brokered auth on a streaming endpoint.
- Streaming HTTP responses (SSE, chunked) work transparently; no special handling needed.

For a worked example of OpenAI Realtime over Agent Vault inside a locked-down container, see [`examples/daytona-openai-realtime`](https://github.com/Infisical/agent-vault/tree/main/examples/daytona-openai-realtime).

## Proposals -- Requesting and Storing Credentials

Proposals are the primary way to exchange credentials with a human operator. Use them whenever you:

- **Need a credential supplied by a human** -- create a proposal with a credential slot and the human will provide the value at approval time.
- **Want to store a credential back** -- include the value in a credential slot and the human confirms it at approval.
- **Need proxy access to a new host** -- propose a service with an `auth` config so Agent Vault can authenticate on your behalf.

When you get a `403` for a host not in discover (only happens under strict deny mode), the response includes a `proposal_hint` with the denied host.

## Choosing the Right Auth Method

**Before creating a proposal for a new service, you MUST look up how that service authenticates API requests.** If you have internet access, fetch the service's API authentication documentation to determine the correct auth type. Do not guess -- incorrect auth wastes the operator's time and will fail at the proxy.

Agent Vault auth types:

```
bearer      -- Authorization: Bearer <token>          {"auth": {"type": "bearer", "token": "SECRET_KEY"}}
basic       -- HTTP Basic (user, optional password)    {"auth": {"type": "basic", "username": "API_KEY"}}
api-key     -- key in a named header, optional prefix  {"auth": {"type": "api-key", "key": "SECRET", "header": "x-api-key"}}
custom      -- freeform header templates               {"auth": {"type": "custom", "headers": {"X-Key": "{{ SECRET }}"}}}
passthrough -- allowlist host only, no credential   {"auth": {"type": "passthrough"}}
```

Common services: Stripe (bearer), GitHub (bearer), OpenAI (bearer), Ashby (basic -- API key as username), Jira (basic -- email + token), Anthropic (api-key, header: x-api-key). If unlisted, check the API docs.

**Header forwarding.** Agent Vault forwards your request headers to the upstream unchanged, except for hop-by-hop headers (RFC 7230, including `Proxy-Connection`), broker-scoped headers (`X-Vault`, `Proxy-Authorization`), and the specific header(s) the configured auth type manages. With `auth.type: bearer`, for example, the broker overrides `Authorization` and leaves all other client headers untouched — so vendor headers like `anthropic-version` and `OpenAI-Beta` reach the upstream. Custom auth strips every header listed in `auth.headers` and replaces them with the resolved values.

**Passthrough** allowlists a host but does not store or inject a credential. Use it only when the operator has decided their client already holds the credential and wants netguard / audit / MITM coverage without putting the secret in the vault. For the default case (agent needs the credential from the vault), use one of the credentialed types above.

### URL Substitutions

Some APIs want a credential-derived value in the URL path or query string (Twilio's `/Accounts/{AccountSID}/Messages.json`, legacy `?api_key=` services). Auth types only inject headers, so for these you add a `substitutions` field to the service. The broker rewrites a placeholder string in declared surfaces only.

```json
"substitutions": [
  {"key": "TWILIO_ACCOUNT_SID", "placeholder": "__account_sid__", "in": ["path"]}
]
```

How it works:
- The operator declares the exact `placeholder` string (e.g. `__account_sid__`). The broker matches it case-sensitively as a literal — no auto-wrapping, no transformations.
- Your request must embed the placeholder verbatim: `GET https://api.twilio.com/2010-04-01/Accounts/__account_sid__/Messages.json`. The broker resolves `key` from the vault, URL-encodes the value, and substitutes it in.
- `in` declares which surfaces the broker is allowed to scan: subset of `["path", "query", "header"]`. Defaults to `["path", "query"]` if omitted. `header` must be explicit. `body` is not supported.
- **Scoping is the security boundary.** The broker only scans surfaces in `in`. Embedding the placeholder anywhere else (a non-declared surface, a body) means the literal string passes through unmodified — there is no way to coerce the broker into substituting somewhere the operator did not authorize.
- When `header` is in `in`, the broker scans **every outbound header** for the placeholder, not a specific named header. Pick a unique placeholder so it can only appear where you intended.
- Substitutions compose with auth: a Twilio service uses both `auth: basic` (header injection) and a substitution for the path SID.
- Placeholder safety: must be ≥4 characters, contain at least one alphanumeric character, contain a `__` boundary or non-`[A-Za-z0-9_]` character (so bare words like `account_sid` are rejected — they would match legitimate URL words), and use only RFC 3986 unreserved characters `[A-Za-z0-9_-.~]`. The recommended convention is `__name__`.
- Updating an existing service: a `set` proposal that omits `substitutions` (or sends an empty list) preserves the service's existing substitutions, even when `auth` is replaced. To change the list, supply the new non-empty list. To clear all substitutions, delete and recreate the service.

Substitutions are configured via JSON only — no flag form. Place a `substitutions` array under any `services[]` entry in `proposal create -f file.json` or `agent-vault service set -f services.yaml`.

### Vaults backed by an external credential store

Run `agent-vault vault credential-store show <name>` to check the kind. `builtin` is writable; anything else is read-only on the Agent Vault side (manage credentials upstream).

For read-only vaults:
- `vault credential set/delete` return `409 external_credential_store`.
- `vault proposal create` rejects `--credential` / `credentials[]` blocks. Service-only proposals work and may reference existing upstream keys.

Creating an external-store vault (`vault create --credential-store=infisical ...`) is owner-only: the broker's machine identity, not the caller's, authorizes the upstream fetch. Upstream secret names must match `^[A-Z][A-Z0-9_]*$` or create/sync fails with `external_store_invalid_key` naming the offending key.

Refresh on demand with `agent-vault vault credential-store sync <name>` (or `POST {AGENT_VAULT_ADDR}/v1/vaults/{name}/sync`; any vault member). Returns the post-refresh `credential_store` summary; conflicts with an in-flight refresh return `409`. The periodic syncer keeps the vault fresh otherwise, so manual sync is for "I just rotated a secret upstream" cases.

### Creating a Proposal

**Flag-driven mode (common cases). When `--host` is provided, `--name` is optional — when omitted, the server slugifies `host`+`path` (e.g. `api.stripe.com` → `api-stripe-com`):**

```bash
# Service + credential
agent-vault vault proposal create \
  --name stripe --host api.stripe.com --auth-type bearer --token-key STRIPE_KEY \
  --credential STRIPE_KEY="Stripe API key" \
  -m "Need Stripe API key for billing feature" --json

# Credential only (no host/service needed)
agent-vault vault proposal create \
  --credential DB_PASSWORD="Production database password" \
  -m "Need database credentials" --json

# Path-scoped service: Slack needs different credentials at different paths
agent-vault vault proposal create -f - --json <<'EOF'
{
  "services": [
    {"action": "set", "name": "slack-bot", "host": "slack.com/api/*", "auth": {"type": "bearer", "token": "SLACK_BOT_TOKEN"}},
    {"action": "set", "name": "slack-conn", "host": "slack.com/api/apps.connections.*", "auth": {"type": "bearer", "token": "SLACK_CONNECTION_TOKEN"}}
  ],
  "credentials": [
    {"action": "set", "key": "SLACK_BOT_TOKEN", "description": "Slack Bot User token"},
    {"action": "set", "key": "SLACK_CONNECTION_TOKEN", "description": "Slack Socket Mode connection token"}
  ],
  "message": "Slack needs two credentials: Bot token for /api/* and Socket Mode token for /api/apps.connections.*"
}
EOF

# Complex/multi-service (JSON mode)
agent-vault vault proposal create -f - --json <<'EOF'
{
  "services": [{"action": "set", "name": "stripe", "host": "api.stripe.com", "auth": {"type": "bearer", "token": "STRIPE_KEY"}}],
  "credentials": [{"action": "set", "key": "STRIPE_KEY", "description": "Stripe API key"}],
  "message": "Need Stripe access"
}
EOF

# Service with URL substitution (Twilio: SID in path + auth header)
agent-vault vault proposal create -f - --json <<'EOF'
{
  "services": [{
    "action": "set",
    "name": "twilio",
    "host": "api.twilio.com",
    "auth": {"type": "basic", "username": "TWILIO_ACCOUNT_SID", "password": "TWILIO_AUTH_TOKEN"},
    "substitutions": [
      {"key": "TWILIO_ACCOUNT_SID", "placeholder": "__account_sid__", "in": ["path"]}
    ]
  }],
  "credentials": [
    {"action": "set", "key": "TWILIO_ACCOUNT_SID", "description": "Twilio Account SID"},
    {"action": "set", "key": "TWILIO_AUTH_TOKEN", "description": "Twilio Auth Token"}
  ],
  "message": "Twilio messaging — agent embeds __account_sid__ in the URL path"
}
EOF
```

Flag-driven auth flags by type:
- **bearer**: `--auth-type bearer --token-key CREDENTIAL_KEY`
- **basic**: `--auth-type basic --username-key USER_KEY [--password-key PASS_KEY]`
- **api-key**: `--auth-type api-key --api-key-key KEY [--api-key-header x-api-key] [--api-key-prefix "ApiKey "]`
- **passthrough**: `--auth-type passthrough` (no credential flags; any credential flag is rejected)

Other flags: `--user-message` (shown on browser approval page), `--credential KEY=description` (repeatable).

Key fields (JSON mode):
- `services[].action` -- `"set"` (upsert, needs `host` + `auth` **or** an `enabled` change) or `"delete"`
- `services[].name` -- canonical identifier (slug, 3–64 lowercase alphanumeric/hyphen chars). **Required for `"set"`** when creating a new service — pick a deliberate name. May be omitted only when `host` + `path` uniquely matches an existing service in the vault: the server adopts that entry's name, the same pattern as `"delete"` by host. `"delete"` may also omit `name` to fall back to host-based resolution: when the host is shared by multiple services the server returns 409 with the candidate names so the caller can retry by `name`.
- `services[].host` -- single matcher field. Accepts a bare hostname (e.g. `api.stripe.com`), a one-level wildcard (e.g. `*.github.com`), or an inline path-scoped form (e.g. `slack.com/api/*`). The server splits the path off the host on ingest and resolves overlapping rules deterministically (exact-host beats wildcard, then longer literal path prefix wins, then declaration order). Path globs use `*` as a greedy glob (cross-`/`); `**`, `?`, regex, and bare `*` are rejected.
- `services[].auth` -- authentication config. Types: `bearer` (`token`), `basic` (`username`, optional `password`), `api-key` (`key` + `header`, optional `prefix`), `custom` (`headers` map with `{{ KEY }}` templates), `passthrough` (no credential fields)
- `services[].substitutions` -- optional list of URL/header rewrites. Each entry has `key` (UPPER_SNAKE_CASE credential reference), `placeholder` (the exact wire string the broker matches case-sensitively, e.g. `__account_sid__`), and optional `in` (subset of `["path", "query", "header"]`; defaults to `["path", "query"]`). Surfaces not in `in` are not scanned. Must be paired with an `auth` change in the same proposal — substitutions cannot be added on an enable/disable-only update.
- `services[].enabled` -- optional boolean. Omitted means "enabled" for new services. A `"set"` proposal may supply `enabled` alone (no `auth`) to toggle an existing service's state without replacing its auth config -- useful for staged rollouts
- `credentials[].action` -- `"set"` (omit `value` for human to supply; include `value` to store back) or `"delete"`
- `credentials` -- only declare credentials not already in `available_credentials`. Every credential referenced in auth configs must resolve to a slot or existing credential (400 otherwise)
- `message` -- developer-facing explanation; `user_message` -- shown on the browser approval page
- `credentials[].obtain` -- URL where the human can get the credential; `obtain_instructions` -- steps to find it

**After creating a proposal:**
1. Present the `approval_url` to the user conversationally -- e.g. "I need access to your Stripe account. Click here to connect it: -> {approval_url}"
2. Immediately start polling `GET {AGENT_VAULT_ADDR}/v1/proposals/{id}` -- do NOT wait for the user to say "go on" or confirm. Poll every 3s for the first 30s, then every 10s. Stop after 10 minutes (proposal may have expired).
3. Once status is `applied`, automatically retry your original request and continue your task

**Check status:** `GET {AGENT_VAULT_ADDR}/v1/proposals/{id}` with `Authorization: Bearer {AGENT_VAULT_TOKEN}` -- returns `pending`, `applied`, `rejected`, or `expired`

## Request Logs

Agent Vault keeps a per-vault audit log of proxied requests (method, host, path, status, latency -- never bodies or query strings). The CLI does not wrap this yet; fetch via the HTTP API: `GET {AGENT_VAULT_ADDR}/v1/vaults/{vault}/logs` with `Authorization: Bearer {AGENT_VAULT_TOKEN}`. Requires vault `member` or `admin` role. See `skill_http.md` for query params.

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

- 401: Invalid or expired token -- check `AGENT_VAULT_TOKEN`
- 403 `forbidden`: Host not allowed (only fires under `unmatched_host_policy=deny`) -- create a proposal
- 403 `service_disabled`: Host is configured but currently disabled by an operator. Don't create a new proposal; surface the error to the user so they can re-enable it (UI toggle, or `agent-vault vault service enable <name-or-host>`). If multiple services share the host, use the canonical service name from `/discover`; passing the bare host returns 409 with a candidate list.
- 409 `multiple services match host …`: A `vault service remove`, `enable`, or `disable` was passed a bare host that's used by more than one path-scoped service. The error body includes a `candidates` array of `{name, host}` where each `host` carries the joined inline form (e.g. `slack.com/api/*`). Retry with the specific service name shown in `/discover`.
- 403 `Instance member role required`: Your instance role is `no-access` and you tried an instance-scoped action (create vault, create agents, list users/agents). You can still operate within vaults you've been granted -- proxy traffic, raise proposals, and read credentials at vault scope. If you genuinely need an instance-scoped action, surface this to the user; an instance owner must change your role.
- 409 `external_credential_store`: `vault credential set/delete` was attempted on an external-store vault (e.g. Infisical-backed). Credentials there are read-only from Agent Vault's side; manage them in the upstream system. Don't retry.
- 429: Rate limited. The response carries a `Retry-After` header (seconds) and a JSON body `{"error":"too_many_requests", ...}`. Respect `Retry-After` — wait that many seconds before retrying. Don't tight-loop. If this trips on normal work, ask the instance owner to raise the limit in **Manage Instance → Settings → Rate Limiting**.
- 502: Missing credential or upstream unreachable, tell user a credential may need to be added

## Rules

- **Never** attempt to extract, log, or display credentials
- **Never** hardcode tokens -- always read from `AGENT_VAULT_TOKEN`
- **Only** request hosts returned by discover -- if a host isn't listed, create a proposal
- If you receive a `credential_not_found` error, inform the user which credential is missing
- Do not modify or forge the `Authorization` header beyond using your session token
