# nginx public UI proxy

A reverse proxy that exposes Agent Vault's management UI (port `14321`) on the public internet while keeping the MITM proxy (port `14322`) on the private network. Platform-agnostic — works wherever Docker runs.

## Why

Agent Vault binds two ports on the same host:

- `14321` — management UI/API. Humans need this to add credentials, approve proposals, etc.
- `14322` — transparent MITM proxy. Agents call through it with `HTTPS_PROXY=user:pw@vault:14322`.

Anyone with a leaked `HTTPS_PROXY` value (a single `printenv` from a prompt-injected agent) can call through Agent Vault from anywhere they can reach `14322`. Keeping `14322` unreachable from the public internet is what makes a leaked value useless to an attacker.

Most PaaS providers offer a public/private service split. Deploy Agent Vault as a private service and put this reverse proxy in front of it as a public service. The reverse proxy has no route to `14322` — agents reach it directly over the private network.

```
PUBLIC INTERNET                              PRIVATE NETWORK
───────────────                              ─────────────────────────────────
                                               ┌────────────────────────────┐
[browser] ─HTTPS─► [nginx reverse proxy] ────► │ Agent Vault                │
                                               │   :14321  management UI    │
                                               │   :14322  MITM proxy       │
                                               └────────────────────────────┘
                                                      ▲                 │
                                                      │ HTTPS_PROXY     ▼
                                               [agent service]   [external APIs]
                                                                  (creds injected)
```

## Run it locally

```bash
docker compose up
```

Visit `http://localhost:8080` to reach the management UI through the reverse proxy. Agent Vault stays on the compose-internal network only.

## Configure

### On the reverse proxy

| Var | Default | Description |
|-----|---------|-------------|
| `PORT` | `8080` | Port the reverse proxy listens on. Most PaaS providers inject this automatically. |
| `AV_UPSTREAM` | (required) | `host:port` of Agent Vault's management API on the private network. |

Examples for `AV_UPSTREAM`:

- Render: `agent-vault-ab12:14321`
- Fly.io: `agent-vault.internal:14321`
- Docker Compose: `agent-vault:14321`

### On the Agent Vault side

Set these on the upstream Agent Vault service so it behaves correctly behind a reverse proxy (see [environment-variables.mdx](../../docs/self-hosting/environment-variables.mdx)):

| Var | Why it matters |
|-----|----------------|
| `AGENT_VAULT_ADDR` | Public URL of the reverse proxy. Drives the `av_session` cookie's `Secure` flag and external links in notification emails. If unset, defaults to the bind addr — wrong for public exposure. |
| `AGENT_VAULT_TRUSTED_PROXIES` | CIDR(s) the reverse proxy sits on. Without it, audit logs record the reverse proxy's IP for every request instead of the real client's. |

## What this protects

| Attack | What stops it |
|--------|---------------|
| Public traffic to port `14322` | The reverse proxy has no route there. The `proxy_pass` only ever points at `14321`. |
| `CONNECT` tunneling through the reverse proxy | Explicit `return 405` on `CONNECT`. |
| oauth2-proxy-style header spoofing | `X-Forwarded-User` and `X-Auth-Request-User` are stripped. |

## What this does NOT protect

- **In-network traffic encryption.** Reverse proxy → Agent Vault is plain HTTP. Most PaaS private networks are isolated; if your threat model needs in-network encryption, terminate TLS at the upstream too.
- **A compromised reverse proxy host.** If the reverse proxy VM is rooted, the attacker can reach the upstream. This reverse proxy is one layer of defense in depth, not the only one.

## Why we don't strip `Authorization`

Most reverse-proxy guides tell you to strip `Authorization` so a client can't arrive pre-authed. That advice assumes the reverse proxy *injects* auth on the client's behalf. This config is passthrough — Agent Vault's management API uses `Authorization: Bearer <token>` for its CLI and any non-browser caller, and validates the token against its own session store. A forged Authorization gets a 401. Stripping it would break the CLI and any agent that hits the management API.

## Verify

```bash
# Reverse proxy is alive
curl -fsS http://localhost:8080/healthz       # → ok

# Agent Vault's /health forwards through
curl -fsS http://localhost:8080/health        # → {"status":"ok"}

# CONNECT is refused
curl -i -X CONNECT http://localhost:8080/     # → 405
```

To verify trust-header stripping in isolation, uncomment the `echo` service in `docker-compose.yml`, change the reverse proxy's `AV_UPSTREAM` to `echo:8080`, then send a request with `X-Forwarded-User: attacker` and `Authorization: Bearer should-pass-through`. The echoed headers should show `Authorization` present and `X-Forwarded-User` absent.

## Adapt

Change ports, add rate limits (`limit_req_zone`), restrict source IPs (`allow`/`deny`), or swap nginx for Caddy — see the [nginx docs](https://nginx.org/en/docs/). Keep `proxy_pass` pointed at the management port only.
