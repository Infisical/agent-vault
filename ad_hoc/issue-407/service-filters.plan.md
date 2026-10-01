# Per-service request filters

This file is the implementation contract for per-service MITM request filters.
After a service matches, Agent Vault reverse-proxies the live request to an operator-configured URL without resolving destination credentials.
The sidecar may return any HTTP response, or continue through Agent Vault with short-lived JWTs.

This is a local working spec, not upstream docs.
Canonical issue: [RFC: per-service MITM request filter](https://github.com/Infisical/agent-vault/issues/407).
Do not include `ad_hoc/` in the pull request.

## The seam

This is the design.
Later sections specify tokens, validation, and tests.
They do not add a second access-control plane.

Rows 1 and 2 are today's broker.
Rows 3 and 4 are the hop.
Rows 5 and 6 are the continuation.

A continuation is minted on the hop (rows 3 and 4).
It records two things.
Neither is the destination secret or the request body.

**Bind.** The identity of the request the sidecar saw: method, scheme, authority, escaped path, and raw query.
Rows 5 and 6 compare the inbound request to that bind, byte for byte.
The sidecar may send a new body.
It may not change the URL.
A changed path is row 6, not a rewrite to the old path.

**Frozen match.** Which service won, and the non-secret inject shape (auth type, key names, substitutions).
Row 5 uses that to Resolve.
It does not run Match again.

| | When | What happens |
| --- | --- | --- |
| 1 | No service matches | Honor the vault's `unmatched_host_policy`. Same for an agent token or a policy token. |
| 2 | Match, no `filter` | Inject the destination credential and forward. Same for an agent token or a policy token. |
| 3 | Match, `filter` set, `policy_vault` omitted | Do not Resolve. Mint a continuation. Reverse-proxy the live request to `filter.url` with that continuation, the callback proxy URL, and the CA. No policy token. |
| 4 | Match, `filter` set, `policy_vault` set | Do not Resolve. Mint a continuation. Mint a policy token for the vault that field names. Reverse-proxy the live request with both tokens, the callback proxy URL, and the CA. |
| 5 | Continuation, bind still holds | Skip the sidecar. Resolve the frozen match. Inject onto this inbound request. Forward. |
| 6 | Continuation, bind does not hold | Do not rewrite the URL, inject, or forward. Respond 403 (or 400), not 500. The JWT stays valid until `exp`. |

A disabled service is today's deny.
That is not a hop.

## Problem

Today a service is: this host, path, and port get this credential.
That is all the matcher can do.

Some policies need to look at the actual request first, while the destination secret is still locked.
Examples: read a git push body to see the branch, call GitHub's protection API, send the call to a different host, or change an OpenAI model name.

Agent Vault cannot ship a rules engine complete enough for those cases.
A filter might need the first 100 bytes of the body, or an external API call whose URL comes from a query param.
That is the consumer's policy, not the broker's.

Agent Vault's job is to keep credential management, and to offer a seam so a downstream consumer can run that logic anyway.
A Java servlet-style request filter is that seam:

1. Match the service (no decrypt).
2. Hop the live request to the sidecar.
3. The sidecar decides: reject, rewrite, or continue.

The straw man (not the only consumer) is HTTPS `git push`.
The sidecar sees `git-receive-pack`, checks whether the branch is protected, and either returns 403 (secret never used) or continues so Agent Vault can attach the PAT and talk to GitHub.

## Non-goals

- In-process plugins, WASM, Go `.so`, or a new rules language.
- A second client-facing proxy.
  Clients keep talking to Agent Vault.
  How the vault calls the sidecar, and whether the sidecar calls back, is specified in [section 4](#4-continuation-and-policy-tokens) and [section 7](#7-the-reverse-proxy-hop).
- The sidecar is not an Agent Vault agent and does not get a long-lived token.
  How it may call back is specified in [section 4](#4-continuation-and-policy-tokens).
- RFC 9457 Problem Details.
  A nicer error shape, but not how Agent Vault reports proxy errors today.
  This change does not adopt it.
  The existing envelope is specified in [section 7](#7-the-reverse-proxy-hop).
- A dashboard, `--filter-*` flags, or a `vault service filter` subcommand.
  Admin YAML is enough for v1.
- Changing global matcher semantics.
  Which service wins a request stays as it is today.
  How proposals may not shadow a filtered service is specified in [section 3.1](#31-proposals-cannot-shadow-a-filtered-matcher).
- Changing how ordinary unfiltered CONNECT tunnels are revoked.
  `agent revoke` still takes effect on the next CONNECT, not an already-open one.
- A TTL flag or env override.
  Hop tokens last 30 seconds, specified in [section 4](#4-continuation-and-policy-tokens).
  Making that configurable is out of this change.
- Hiding filtered services from `/discover`.
  The service stays visible.
  The filter block and hop JWTs do not.

## 1. Placement in the pipeline

The request path is [The seam](#the-seam).
This section only states when the destination secret is opened.

Today every proxied request does this:

authenticate -> rate limit -> Inject (match the service and decrypt the dest secret) -> maybe substitutions -> origin (or a WebSocket).

Unfiltered services stay on that path (seam row 2).
No sidecar, no hop JWT.
If the filter machinery is down, ordinary proxying must still work.

Filtered services split Inject in two (seam rows 3 and 4):

authenticate -> rate limit -> Match (which service? no decrypt) -> hop the live request to `filter.url` -> whatever the sidecar returns is what the client sees.

Decrypt (Resolve) happens only later, if the continuation bind holds (seam row 5), or immediately on the unfiltered path as today.

If the sidecar says no, times out, or cannot be reached, Agent Vault must not have opened the dest secret at all.
A 403 that still decrypted the PAT in the background is a failed design.

A disabled service or no match is unchanged (seam rows 1 and today's deny).
Do not call the sidecar.

Fail-closed errors, required Match/Resolve interfaces, and how tests prove the no-decrypt invariant are specified in [section 5](#5-enforcement-is-mandatory) and [section 10](#10-tests).

## 2. Config

`filter` is an optional block on `broker.Service`.
Operators write it in service YAML, the same way they write substitutions.
There is no dashboard, flag, or `vault service filter` subcommand.

```yaml
services:
  - name: github-push
    host: github.com/*/git-receive-pack
    auth:
      type: bearer
      token: GITHUB_TOKEN
    filter:
      url: https://policy.example.com/github-push
      policy_vault: policy
```

| Field | Required | Meaning |
| --- | --- | --- |
| `url` | yes if `filter` present | URL of the sidecar, the origin server for this hop. `https` normally. Literal-loopback `http` is allowed without a flag. Non-loopback `http` requires `allow_insecure_private_http: true`. |
| `policy_vault` | no | Vault the policy token is scoped to. Omitted means none. Why you would name the source vault or another vault is explained in [section 2.1](#21-choosing-policy_vault). |
| `allow_insecure_private_http` | no | Opt-in for cleartext HTTP to a private sidecar that is not a literal loopback IP. Literal loopback HTTP does not need it. Weaker than TLS. Document it as such. |
| `ca` | no | PEM certificate(s) used as the only TLS roots for this hop. Omit it when `https` uses a public CA. Pin it when the sidecar is a compose or other private name with a self-signed cert. |

The named policy vault is an ordinary vault.
Agent Vault does not constrain which services live there.

Clear the block with `filter: null` on `vault service add`.
Who may set or clear it, and how YAML `null` survives JSON, is specified in [section 3](#3-who-may-change-a-filter).

A Compose sidecar on the same Docker network is not loopback.
Prefer HTTPS and pin the sidecar CA.
YAML anchors may repeat that PEM across many filters in the operator file.
Agent Vault stores an expanded copy on each service and does not provide a named CA catalog.
`vault service list` prints the expanded PEM.

```yaml
services:
  - name: github-push
    host: github.com/*/git-receive-pack
    auth:
      type: bearer
      token: GITHUB_TOKEN
    filter:
      url: https://filter:12345
      policy_vault: dev
      ca: &sidecar_ca |
        -----BEGIN CERTIFICATE-----
        (sidecar CA PEM)
        -----END CERTIFICATE-----
  - name: openai
    host: api.openai.com
    auth:
      type: bearer
      token: OPENAI_KEY
    filter:
      url: https://filter:12345
      policy_vault: dev
      ca: *sidecar_ca
```

Cleartext HTTP on that network remains available with `allow_insecure_private_http: true` and no `ca`.

### 2.1 Choosing `policy_vault`

Omit it for a body-or-headers hop (seam row 3).
Set it to mint a 30-second policy token for that vault (seam row 4).
The hop does not change based on which name you write.
The choice is what that token can reach.
Worked YAML is in [section 8](#8-worked-example).

**Name the source vault** when the sidecar should call other services in the same vault (the GitHub protection API next to the push row).
Write the name explicitly.
Omit is not this.

**Name a different vault** when you want that extra access on a smaller vault (read API only).
The person writing the config must be vault admin of both.

A holder of the policy token can use the named vault the way the agent can, until `exp`.
Which services that vault contains is the operator's choice.

### 2.2 `filter.url` and `ca`

The URL must be absolute `http` or `https` and must include a host.
A path prefix is allowed.
The original request path and query are appended after that prefix.

Reject:

- userinfo (it would smuggle sidecar credentials past `allow_insecure_private_http`, and secrets are not in URLs)
- a fragment
- a configured query or `ForceQuery` (the hop replaces the query with the original request query, so leftover query is unused and can hide secrets in config and logs)
- any scheme other than `http` or `https`
- non-loopback `http` without `allow_insecure_private_http: true`
- `ca` on an `http` URL
- empty, non-PEM, or private-key material in `ca`

When `ca` is set, the value must parse as at least one `CERTIFICATE` PEM.
The hop verifies using only those roots, not the system pool.
The URL hostname must match the certificate.
There is no `ca_file`, `tls_server_name`, or skip-verify flag.

### 2.3 `AGENT_VAULT_MITM_ADDR`

This is the MITM analogue of `AGENT_VAULT_ADDR`.
It does not bind a listener and is not checked against `--host` or `--mitm-port` at startup.
It is the URL advertised for the proxy door: hop headers, and `vault run`'s `HTTPS_PROXY` when set.
The hostname is a SAN on MITM leaf certs when clients TLS-verify the proxy's own name (same role `AGENT_VAULT_ADDR` has today).
It is not filter-specific except that hop headers carry it.

It must be a base URL: scheme `http` (the MITM is a plain HTTP proxy), host, optional port, no userinfo, path, query, or fragment.
An explicit invalid value is fatal at startup so hops never advertise junk.
A mismatch with `--host` is not fatal.
Clients that trust the advertised URL fail to connect, same as a wrong `AGENT_VAULT_ADDR`.

Unset: hostname from `AGENT_VAULT_ADDR`, port from the MITM listener, scheme `http`, matching `vault run` today.
If `AGENT_VAULT_ADDR` is unset, or its host is missing or a wildcard (`0.0.0.0`, `::`), advertise loopback.
Compose with only `AGENT_VAULT_ADDR=http://agent-vault:14321` still yields `http://agent-vault:14322`.
Set `AGENT_VAULT_MITM_ADDR` when the proxy must be advertised under a different name than the control plane (public UI vs docker DNS).
`vault run` dials that host only when the variable is set.
When it is unset, the CA response omits `X-Agent-Vault-MITM-Addr`, and `vault run` keeps the host it used to reach the API plus the port from `X-MITM-Port`.
Hop headers still carry the derived callback URL.

Document in [`.env.example`](../../.env.example), [environment variables](../../docs/self-hosting/environment-variables.mdx), and the env table in [CLI reference](../../docs/reference/cli.mdx), next to `AGENT_VAULT_ADDR`.

## 3. Who may change a filter

| Actor | Action | Outcome |
| --- | --- | --- |
| Agent | Proposal that sets or clears `filter` (object or `null`) | Reject 400 |
| Agent | Proposal that deletes a filtered service | Reject at create and apply |
| Agent | Proposal whose effective `set` matcher can win or tie an existing filtered matcher | Reject 400 at create, 409 at apply ([section 3.1](#31-proposals-cannot-shadow-a-filtered-matcher)) |
| Agent | Proposal that updates auth of a filtered service and leaves host, path, and port unchanged | Preserve `filter` |
| Agent | Proposal that changes host, path, or port of a filtered service | Reject at create and apply |
| Agent | Proposal with `enabled: false` on a filtered service | Allow |
| Admin | `vault service add` / POST upsert, `filter` omitted | Preserve |
| Admin | `vault service add` with `filter:` or `filter: null` | Set or clear |
| Admin | `vault credential set` | Does not touch services |
| Admin | `vault service set` (replace list) / `clear` | Not preserved. Document this. |
| Admin | Interactive `service set` "Replace all" | Same as `set` (wipe). No wizard prompt for filter in v1. |
| Admin | Delete service | Allowed |
| Admin | YAML or upsert of an overlapping unfiltered exception | Allowed |

An explicit `filter` key in proposal JSON, including `filter: null`, is 400.
Silently dropping the unknown key is not enough.
The agent would believe it had configured a policy hop.

`enabled: false` on a filtered service is fail-closed denial (`ErrServiceDisabled`), not a bypass.
Delete is rejected because it can drop the request to unmatched-host passthrough.
Disable does not.
Document that asymmetry.

`vault service add` with omitted vs explicit-null both decode to a nil pointer in ordinary JSON.
Key presence must survive YAML -> JSON -> API (`FilterOp`).

Admin `vault service list` must include `url`, `policy_vault`, `allow_insecure_private_http`, and `ca` when set.
A list-then-set round trip must not silently strip a filter.
Never print hop JWTs.

The filter block is operator-only.
`/discover` and the agent skill omit it.
Proxy-role callers read services without the filter block, matching `/discover`.

### 3.1 Proposals cannot shadow a filtered matcher

`MatchScore.Better` ranks host tier, then port specificity, then path literal length.
It ignores declaration order.

An agent can propose unfiltered `github.com/acme/app.git/git-receive-pack` over an admin's filtered `github.com/*/git-receive-pack`, reference a PAT already in the vault, and win the match.
The filter never runs.
The human approving the proposal sees "add a service".

Rule: at proposal create, and again at apply against then-current config, reject a proposed effective service that is unfiltered and whose matcher can win or tie an existing filtered service for any request.
Create returns 400.
A conflict introduced between create and apply returns 409 and the proposal is not applied.
The error names both the proposed and the filtered service.

The comparison runs on the effective merge.
Updating a filtered service's auth, which preserves its filter, is not rejected.
Changing its host, path, or port is rejected.
Normalize inline host, path, and port forms first.

Implement a reusable overlap helper using real matching semantics:

- Host languages overlap for equal exact hosts, equal one-label wildcards, or an exact host matched by the other's one-label wildcard.
- Port languages overlap when explicit ports agree or either side omits a port.
- Path languages overlap per the existing `*` glob language.
  Use an exact intersection (DP or NFA), not a string-prefix approximation.
- On a shared witness request, compare the real priority tuple (host tier, port specificity, literal path-prefix length).
  Reject when the proposed tuple is better or equal.

Equal priority is rejected so safety does not depend on declaration order or later serialization.

This restriction is proposal-only.
A vault admin may still author an overlapping unfiltered exception through YAML or direct upsert.
Do not change `MatchScore` so that any overlapping filtered matcher always hops.
That would remove deliberate admin exceptions and change semantics for unfiltered traffic.

## 4. Continuation and policy tokens

A filtered hop may mint two JWTs: a continuation, and if `policy_vault` is set, a policy token.

They are ordinary JWTs: three base64url segments, `header.payload.signature`, signed `HS256`.

The credential string is that JWT with a prefix glued on the front, the same idea as `av_sess_` / `av_agt_`:

- `av_cont_` plus the JWT: continuation
- `av_pol_` plus the JWT: policy token

Example: `av_cont_eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3...signature`.

Ingress looks at the prefix first.
`av_sess_` / `av_agt_` stay on today's hash lookup.
`av_cont_` / `av_pol_` strip the prefix, then verify the remainder as a JWT.
A JWT library never sees the prefix.
The prefix is not a JWT claim or header.

That dispatch needs no crypto.
It also gives log redaction a stable match (`av_cont_`, `av_pol_`).

In practice the hop to the sidecar is ordinary HTTP (not CONNECT).
The JWT is a header, never a URL:

```http
POST /git-receive-pack HTTP/1.1
Host: github.com
X-Agent-Vault-Original-URL: https://github.com/acme/app.git/git-receive-pack
X-Agent-Vault-Continuation-Proxy: http://127.0.0.1:14322
X-Agent-Vault-Continuation-Token: av_cont_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJraW5kIjoiY29udCIsImV4cCI6MTc3NDA0MDAzMH0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

The sidecar continues with that credential as `Proxy-Authorization` against the credential-less proxy URL.
`Bearer` is the natural form. `Basic` with the same string as userinfo (no vault hint) also works, because today's parser already accepts both:

```http
CONNECT github.com:443 HTTP/1.1
Host: github.com:443
Proxy-Authorization: Bearer av_cont_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJraW5kIjoiY29udCIsImV4cCI6MTc3NDA0MDAzMH0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

MITM takes the token from `ParseProxyAuth`, sees `av_cont_`, strips it, and verifies:

```text
av_cont_ eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 . eyJraW5kIjoiY29udCIsImV4cCI6MTc3NDA0MDAzMH0 . dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
prefix   header {alg:HS256,typ:JWT}          payload {kind:cont, exp:...}              HMAC
```

Those three segments are a complete toy JWT (only `kind` and `exp` in the payload) so the traces stay readable.
A real continuation JWT is the same shape, just a longer payload segment, because it also carries `iat`, `invocation_id`, vault and actor ids, the exact bind, and the frozen match envelope.

Sign with an HMAC key derived from the DEK (HKDF, info `agent-vault hop jwt v1`).
Each replica already loads that DEK from `master_key` at unlock, the same way it decrypts credentials.
HKDF is deterministic, so every replica that unlocked the same DEK verifies the same tokens.
The HMAC key is derived after unlock. It is not a new stored secret.

No credential values in claims.
No raw agent or session tokens in claims.

Audit and rate-limit attribution stay with the initiating actor, not the sidecar.
Minting happens only on the filtered path.

Every filtered hop also receives a random, non-authorizing `invocation_id` claim.
The continuation and optional policy JWT share it.
It is correlation metadata for logs.
It is never a bearer.

Hop JWTs authorize the MITM data plane only.
They are accepted only as proxy credentials.
They are never bearer sessions on `/discover`, proposals, vault administration, or any other control-plane endpoint.
Their effective vault role is always `proxy`.
Never copy an initiating actor's `member`, `admin`, or instance-level authority into hop-JWT scope.

### 4.1 Continuation

Bound in claims to `{method, scheme, authority, escaped path, raw query}` plus the frozen match.
Escaped path and raw query are compared verbatim.
Two different wire requests can decode to the same path.
Only one of them is the request the filter saw.

The sidecar opens a new MITM request to that exact target.
It sends `Proxy-Authorization` set to the prefixed continuation credential against `X-Agent-Vault-Continuation-Proxy`.
Agent Vault strips `av_cont_`, verifies the JWT, checks the bind, skips this service's filter, Resolves the frozen match, injects those destination credentials, and forwards whatever body the sidecar sent.

A continuation cannot retarget the host.
Retargeting (GitLab to GitHub) is a new request with the policy token (seam rows 1 through 4).

`exp` is 30 seconds from mint.
After a successful bind, ordinary origin body, first-header, and WebSocket idle budgets apply.
The 30-second deadline does not kill the established stream.

The JWT stays valid until `exp`.
A failed bind rejects that request only.
A second matching request before `exp` also succeeds.

### 4.2 Bind check at admission

This check is only for a continuation credential on the way back from the sidecar.
The agent's own token is ordinary session auth and has no bind.
A policy token follows [The seam](#the-seam) like an agent session, not this check.

On CONNECT, verify signature, `exp`, kind, and bound authority before hijack, leaf mint, or tunnel setup, so a real HTTP status can still be written.
On absolute-form HTTP, verify the full bind before processing that request.

Without the authority check, a stolen continuation admits a tunnel to any host.
Agent Vault would mint a leaf certificate before the method and path bind is compared.
That is a cert-minting and tunnel-resource oracle, even though the inner request still fails before an origin dial or credential attachment.

Wrong authority: 403 (or 400), no hijack.
Wrong method, scheme, escaped path, or raw query on the inner request: 403 (or 400), no inject, no origin.

Resolve is permitted only after the full bind holds.

### 4.3 Policy token

Exists only when `policy_vault` is set.
Claims carry that vault's immutable id.
Retain the name only for display and audit.
A rename does not retarget it.
A deleted vault fails closed at verify (lookup by id).

Used for side-channel calls and for a new request to a different service.
That new request follows [The seam](#the-seam) in the named vault, including a filtered hop.

The policy token does not carry the continuation's frozen match.
Sending it does not inject the credential of the request that started the hop.
A credential is injected only when a service in the named vault matches, the same way an agent token works.
`exp` is 30 seconds from mint.

A policy token is a short lease of the initiating actor on the named vault.
It honors that vault's `unmatched_host_policy`.
It is not a second access-control plane.

Policy CONNECT uses the same pre-hijack rules as an agent session in that vault.
Continuation CONNECT still binds authority before hijack ([section 4.2](#42-bind-check-at-admission)).

A holder of the policy token can use the named vault the way the agent can, until `exp`.
Naming a smaller vault shrinks that.
See [section 2.1](#21-choosing-policy_vault).

### 4.4 Lifetime

`exp` is 30 seconds from mint.

An already-minted hop JWT is valid until then.
`agent revoke`, session expiry, user deactivation, and grant removal do not change that.

Ordinary unfiltered CONNECT is unchanged: `agent revoke` takes effect on the next CONNECT, not inside an established tunnel.

### 4.5 Claims and signing

Ordinary JWT, `HS256`.
Wire form: `av_cont_` or `av_pol_` immediately followed by `header.payload.signature`.
No extra dots or separators between the prefix and the JWT.

The left column is the JSON key in the payload.

| Claim | Notes |
| --- | --- |
| `kind` | `cont` or `pol`. Must match the prefix. |
| `iat`, `exp` | `exp` is `iat` plus 30 seconds. |
| `invocation_id` | Random, shared by the pair. Logs only. Never a bearer. |
| `source_vault_id` | Vault the filtered request was authenticated against. Audit and rate-limit attribution. Not the policy vault. |
| `actor_id` | Initiating actor. Audit. Verify does not look up the session. |
| `bind` | Continuation only. Object: method, scheme, authority, escaped path, raw query. |
| `match` | Continuation only. Frozen match envelope. See [section 4.6](#46-frozen-match). |
| `policy_vault_id` | Policy only. Immutable id of the named vault. |

Do not put credential values, raw tokens, or `Filter` in claims.

Verify: matching prefix, strip it, HMAC, `exp`, kind (must match the prefix), then bind or policy-vault lookup.
A continuation JWT presented with an `av_pol_` prefix fails.
A policy JWT presented with an `av_cont_` prefix fails.
Unknown envelope version, malformed claims, or a vault id that no longer exists fails closed before any credential-store read.

The signing key is derived from the DEK after unlock.

### 4.6 Frozen match

This is the `match` claim from [section 4.5](#45-claims-and-signing).
It is a versioned, non-secret projection of the matched service.
Agent Vault reconstructs an immutable match at verify time.
It must not re-run service matching against current config.
It must not include `Filter`.
A continuation must never re-enter the hop.

Use this projection, not `json.Marshal` of `broker.Service`.
`Service.MarshalJSON` folds host, path, and port into one `host` string, and a raw service object would include `Filter`.

The left column is the JSON key. These are everything Resolve needs, and nothing used only to decide whether to enter the filter:

| Field | Notes |
| --- | --- |
| `v` | Envelope format version. Validated before the rest of the object is decoded. |
| `name` | Matched service name. |
| `host` | Host pattern. Not the joined inline form. |
| `path` | Path pattern. Empty when the service has none. |
| `port` | Set when the service has a port. Omitted otherwise. |
| `auth` | Same JSON keys as `broker.Auth`: `type`, `token`, `username`, `password`, `key`, `header`, `prefix`, `headers`. `token`, `username`, `password`, and `key` are credential key names. `headers` is the whole template map. |
| `substitutions` | Each entry has `key`, `placeholder`, and `in`. |

Decode in two stages: validate `v`, then decode that version's typed payload.
Unknown `v`, unknown required semantics, malformed or incomplete data, credential-key disagreement, or invalid service config all fail closed before any credential-store read.
Bump `v` whenever a field that affects injection is added.
`encoding/json` drops unknown fields silently, so a mixed-version token would otherwise resolve a subtly different request.

`auth.headers` templates are arbitrary operator text and may contain literals, the same as they already may in `broker_config.services_json`.
Copy them as written.
Credential values never go in claims.

If the credential provider cannot Resolve from a frozen snapshot, fail closed.
No fallback to live Inject or re-match.

| Admin change during the window | Continuation |
| --- | --- |
| Host, path, name, auth key, or substitutions | Frozen. Cannot retarget the slot. |
| Credential value (`vault credential set KEY=...`) | Not frozen. Resolve uses the current value for the frozen key. |
| Filter block | Irrelevant. Continuation does not re-enter the filter. |
| Key deleted from the vault | Fail closed, no origin. |

### 4.7 Minting

When `policy_vault` is set, resolve that vault's immutable id and confirm it exists, then mint the continuation and the policy JWT with the same `invocation_id`.
When it is omitted, mint only the continuation.

The sidecar returns its decision as the HTTP response to the hop.
That response completes the call.
A policy token presented again before `exp` still verifies.

### 4.8 Rate limits and request logs

The initiating filtered request is charged once under the initiating actor and source vault.
Each continuation MITM admission is also charged.
A leaked continuation must not become a 30-second rate-limit bypass.
Policy-token calls are new outbound requests.
They are rate-limited normally under the initiating actor and policy vault.

Logging follows the same distinction:

- The initial filter-hop row records matched service identity but no credential keys, because no credential was resolved.
- The continuation origin row is attributed to the initiator and records the frozen service and key names that were actually resolved, correlated through the non-secret `invocation_id`.
- Policy calls are attributed to the initiator in the policy vault and record their own matched service and key names.
- Raw session tokens, hop JWTs, and credential values never enter logs, spans, metrics labels, or error text.

## 5. Enforcement is mandatory

A filtered request must Match, mint hop JWTs, and look up `policy_vault` when that field is set.
A continuation must verify the JWT and thaw the frozen match.
Those are ordinary required calls.

Match and Resolve stay required interface members.
Test doubles implement the same surface.
Do not hide a missing method behind `ok` and continue.

Any error from those calls fails closed.
A Match error must never fall through to ordinary Inject.
A continuation must never fall back to a live re-match if thaw fails.

A service configured with a filter, on a proxy that cannot hop, returns `502 filter_misconfigured`.
That is never "skip the filter and inject."

## 6. Skip or deny on the way back

This is [The seam](#the-seam) rows 5 and 6.
It applies only to a continuation credential.

- Bind holds: skip this service's filter, Resolve the frozen match, inject onto this request, forward.
- Bind does not hold: 403 (or 400), no inject, no forward.
  The JWT stays valid until `exp`.

An agent token uses its own vault.
A policy token uses the vault named by `policy_vault_id`.
Either one then follows rows 1 through 4 in that vault.
A filtered match on that path is another hop, not this section.

## 7. The reverse-proxy hop

The sidecar is the origin server for this hop, the way a servlet container calls a filter.
`filter.url` is that server's URL.
Agent Vault is the client and sends a normal request to that origin server.
This is not `CONNECT`, and it is not an absolute-form proxy request.
Those forms are how a client talks to a forward proxy, not to an origin server.

Elsewhere in this plan, origin means the upstream the client was calling.
On this hop the sidecar is the origin server instead.

The sidecar does not have to call back through Agent Vault.
It may return a response, or call some other host with its own credentials.
If it wants vault-managed secrets, it calls Agent Vault's MITM as a client ([section 4](#4-continuation-and-policy-tokens)).

Preserve method, path (joined with any path prefix on `filter.url`), original request query, streaming body, and the original `Host`.
Overwrite hop headers.
Never trust client copies of those headers.
Secrets are not in URLs.

### 7.1 Hop headers

Ordering is strip-then-set.

Before the sidecar request, delete untrusted headers ([section 7.2](#72-destination-credential-header-slots)), then set:

| Header | Purpose |
| --- | --- |
| `X-Agent-Vault-Original-URL` | Exact original destination URL. |
| `X-Agent-Vault-Continuation-Proxy` | Reachable MITM proxy base URL, no credentials. |
| `X-Agent-Vault-Continuation-Token` | 30s continuation credential: `av_cont_` plus the JWT. |
| `X-Agent-Vault-Policy-Proxy` | Optional policy proxy base URL, no credentials. |
| `X-Agent-Vault-Policy-Token` | Optional 30s policy credential: `av_pol_` plus the JWT. |
| `X-Agent-Vault-CA` | Agent Vault MITM root, base64. The sidecar is not `vault run`. |
| `X-Agent-Vault-Service` | Matched service name. |

The sidecar sends the matching token as `Proxy-Authorization` when using that proxy URL.
Tokens must not be logged or persisted.

On the sidecar response, strip its reserved namespace first, then set Agent Vault's own `X-Agent-Vault-Proxy-Error` on hop-failure envelopes.
Otherwise the strip rule eats its own header.

On the continuation request to origin, strip `X-Agent-Vault-*` again.
That request is assembled by a sidecar that was just handed hop-JWT headers.

### 7.2 Destination credential header slots

Before sending to `filter.url`, derive the header names the frozen service would overwrite during Resolve.
This is computable with no credential read:

- bearer / basic -> `Authorization`
- api-key -> the configured `header`, or `Authorization` by default
- custom -> every configured output header name
- passthrough -> none

Delete exactly those client-supplied headers, along with `Proxy-Authorization`, `X-Vault`, hop-by-hop headers, and the reserved `X-Agent-Vault-*` namespace.

The continuation overwrites that slot with the vault credential, so the origin server does not need the client value removed for correctness.
The sidecar still must not see it.
A client can put a real secret in the configured header, and the sidecar may call the origin server itself instead of using the continuation.
Leaving the header in place lets the sidecar log or use that secret.

Do not unconditionally strip `Authorization`.
When the service authenticates through a different slot, `Authorization` is ordinary application data that the continuation must preserve and deliver to the origin.
Stripping it blindly loses that data and still leaks the slot that actually matters.

Continuation resolution still writes each injected header with `Set`, not `Add`, so injected values win over client-supplied duplicates.

### 7.3 WebSocket

Reverse-proxy the upgrade and byte stream to the sidecar, preserving `Upgrade` / `Connection` on this hop, including a `101` response back to the client.
The sidecar either rejects, or opens a new WebSocket via the exact continuation and bridges.

Agent Vault verifies the continuation bind, then Resolve and the origin dial.
A denied sidecar upgrade yields zero Resolve.

After a successful origin upgrade, the existing 10-minute WS idle budget governs the bridge.
Unfiltered services keep today's direct origin WS path.

### 7.4 Dial policy

A dedicated per-request transport, closed (`CloseIdleConnections`) when the hop returns so idle connections are not left open.
It is not reused across requests.
It does not consult `AGENT_VAULT_ALLOW_PRIVATE_RANGES`.
Where an origin may live has no bearing on where a policy sidecar may live.

- `https` without `ca`: normal TLS verification against system roots, public allowed, metadata endpoints blocked.
- `https` with `ca`: verify against that PEM pool only, not the system store.
  The URL hostname must match the certificate.
  Metadata endpoints stay blocked.
  A verify failure fails the hop.
  Do not fall back to system roots or skip verify.
- `http` to a literal loopback IP: allowed.
  A name that resolves to loopback (`localhost`) is not.
  Resolution is not part of the config.
- `http` to anything else: requires `allow_insecure_private_http: true`.
  Then every resolved address must be loopback or RFC1918 (or the IPv6 equivalents).
  Dial the validated IP so a rebind cannot slip between check and connect.
  Public, link-local, CGN, and metadata addresses stay blocked.

Redirects are not followed.
Implement the property, do not merely assert it.
`http.Transport.RoundTrip` (and `httputil.ReverseProxy` over it) does not follow redirects, which satisfies the requirement.
An `http.Client` must set `CheckRedirect` to return `http.ErrUseLastResponse`.
State in the code which mechanism provides it.

### 7.5 Failure and success

| Failure | Response |
| --- | --- |
| Dial, TLS, reset, or JWT mint failure | `502` `filter_unreachable` (or `filter_misconfigured` for state or config) |
| No response headers before the budget expires | `504` `filter_timeout` |

Envelope: `Content-Type: application/json`, `{"error":"<code>","message":"..."}`, `X-Agent-Vault-Proxy-Error: true`.
None of these resolves a credential or reaches the origin.

Success: copy status, headers (minus hop-by-hop, reserved broker headers, the reserved namespace, and `Set-Cookie` under the existing proxy response policy), and body to the client, at whatever status the sidecar chose.
Agent Vault does not map "deny" to a fixed 403.
Bodies stream.
A sidecar that reads a non-replayable body must buffer it before sending the continuation.

Request-log rows for a filter hop carry the matched service identity and no credential keys.

## 8. Worked example

The sidecar listens on `:12345`.
It is not a vault object and not an agent.
Policy lives in the sidecar.

`policy_vault` may name the source vault.
That is allowed.
The hop is the same as naming any other vault: the policy token follows [The seam](#the-seam) in the vault it names.

`git-upload-pack` (clone and fetch) never matches the push row.
The protection API is a different, unfiltered service.

The operator never types agent names, tokens, or `--filter-*` flags.

```yaml
# dev-services.yaml
services:
  - name: github-api
    host: api.github.com
    auth:
      type: bearer
      token: GITHUB_TOKEN

  - name: github-push
    host: github.com/*/git-receive-pack
    auth:
      type: bearer
      token: GITHUB_TOKEN
    filter:
      url: http://127.0.0.1:12345
      policy_vault: dev
```

Loopback HTTP needs no `allow_insecure_private_http`.
A Compose sidecar should use `https://filter:12345` plus `ca` ([section 2](#2-config)).
Cleartext `url: http://filter:12345` with `allow_insecure_private_http: true` remains available.

This is one push. The last two rows are the two ways it can end.

| Order | Caller | Authentication | Message | What Agent Vault does |
| --- | --- | --- | --- | --- |
| 1 | coding agent | agent session (`av_sess_` or `av_agt_`) | `POST .../git-receive-pack` | Match `github-push`. No PAT decrypt. Hop to the sidecar. |
| 2 | sidecar | policy token (`av_pol_`) | `GET .../protection` | Match `github-api`. No filter. Inject `GITHUB_TOKEN`. |
| 3, allowed | sidecar | continuation (`av_cont_`) | `POST .../git-receive-pack` | Bind holds. Resolve the frozen match. Inject. Forward to GitHub. |
| 3, denied | sidecar | none | any HTTP response on the hop from step 1 | Copy that response to the agent. No PAT decrypt. No origin. |

Any other request that carries the policy token is [The seam](#the-seam) rows 1 through 4 in `dev`, until `exp`.

`TestSmoke_FilterSameVault` (`make test-smoke`) must use `store.Open` (real SQLite) for vault state, the JWT hop, and both directions:

- denial reaches neither origin nor credential store
- allow reaches origin with the injected destination credential

## 9. Implementation seam

- `broker.Service`: `Filter {url, policy_vault, allow_insecure_private_http, ca}`, validation per [section 2.2](#22-filterurl-and-ca), a presence tri-state so `filter: null` survives the CLI -> API hop.
- `proposal`: preserve `filter`, reject an explicit `filter` key, reject delete of a filtered service, reject shadowing matchers at create and apply ([section 3.1](#31-proposals-cannot-shadow-a-filtered-matcher)).
- `brokercore`: Match vs Resolve as required interface members, frozen match freeze and thaw with a version envelope, no dest decrypt on the filter path, hop credentials are `av_cont_` / `av_pol_` plus an `HS256` JWT (HMAC from the DEK; strip prefix then verify), policy token follows [The seam](#the-seam) in the named vault.
- `mitm`: reverse-proxy to `filter.url`, admission-time bind check on both ingress shapes, token vs proxy-URL headers, strip-then-set both directions, dedicated per-service dialer, filtered WS reverse-proxy plus continuation bridge, hop JWTs accepted on the data plane only.
- `server` / `cmd`: dual-admin when `policy_vault` differs, omitted `policy_vault` mints nothing, `AGENT_VAULT_MITM_ADDR` per [section 2.3](#23-agent_vault_mitm_addr).
- CLI: none beyond YAML parse and print.
- Docs: `docs/learn/services.mdx`, `docs/reference/cli.mdx`, `docs/self-hosting/environment-variables.mdx`, `.env.example`, `README.md`, `CLAUDE.md`, and `cmd/skill_cli.md`.
  Skill docs cover filter error codes.
  A filter denial is the operator's policy and is relayed, not worked around.

## 10. Tests

Test behavior that is easy to get wrong.
Do not add a test that restates the code, mocks the unit under test, walks every config value, or covers a rule another package already tests.

Doubles may stand in for the sidecar and the origin server.
They may not stand in for Match, Resolve, or the credential store when the assertion is about decrypt or injection.
`TestSmoke_FilterSameVault` uses `store.Open` (real SQLite).

Worth testing:

- Denial reaches neither the origin server nor the credential store.
  Allow reaches the origin server with the injected destination credential.
  Count credential reads.
  A status code is not that proof.
  A Match error, or a filtered service with no filter engine, does not fall through to Inject.
  Hop JWTs and credential values do not appear in the logs of that run.
- Wrong CONNECT authority fails before hijack and leaf mint.
  The same continuation still injects on a later correct request before `exp`.
  One encoded-slash path is compared byte for byte.
- A host or auth-key edit does not retarget a frozen match.
  A new value for the frozen key is used.
  Deleting that key fails closed, with no origin.
- The configured credential header does not reach the sidecar.
  `Authorization` on a service that injects a different header does.
- A policy token honors one `unmatched_host_policy` setting in the named vault.
  It does not inject the continuation's destination credential.
  Omitted `policy_vault` does not mint a policy token.
- A proposal that overlaps a filtered matcher is rejected at create and at apply.
  One non-overlapping service is accepted.
  Admin YAML may add the overlapping service.
- A bad signature, an expired JWT, and an unknown match `v` fail before any credential read.
- `agent revoke` does not stop a hop JWT before `exp`.
- A denied WebSocket upgrade does not Resolve.
  An allowed bridge delivers the injected credential.
- A sidecar 302 is returned to the client.
  Pinned `ca` does not fall back to system roots.
  `AGENT_VAULT_ALLOW_PRIVATE_RANGES` does not widen the sidecar dial.
- A hop JWT presented to a control-plane route is rejected.
- The filtered request, the continuation, and each policy request are charged separately.

Not a dedicated test: HMAC as a library round-trip, every blocked address class, every rejected `filter.url`, substitution field round-trip, compile-time interface assertions, unfiltered WebSocket, `Set-Cookie`, or "`GetSession` was not called."
Revoke behavior covers that last one.

## 11. Out of scope

[Non-goals](#non-goals) is the list.
This section does not restate the design.

## 12. Locked decisions

1. Reverse-proxy to the sidecar, not a chained forward-proxy, not in-process.
2. Per matched service only.
3. Match without destination decrypt.
   Resolve only after a continuation bind holds, or on the unfiltered path.
   Frozen match in the continuation JWT.
   Match and Resolve are required interface members.
4. Optional 30s policy JWT plus a continuation JWT, minted together with one `invocation_id`.
5. Continuation binds exact method, scheme, authority, escaped path, and raw query.
   Bind is checked at admission, including CONNECT authority before hijack.
   After a successful bind, the stream runs on origin budgets.
   Body comes from the sidecar.
   It cannot retarget the host.
   A failed bind is 403 (or 400) for that request.
   A second matching request before `exp` succeeds.
6. `policy_vault` omitted means no policy token.
   Set means a 30s JWT for that vault.
   Naming a vault other than the source requires admin of both.
7. A policy token does not carry the continuation's frozen match.
   Sending it does not inject the credential of the request that started the hop.
   It follows [The seam](#the-seam) in the named vault: unmatched policy, unfiltered inject, filtered hop.
   Hop JWTs are data-plane-only, proxy-role authority.
   Audit as the initiator.
8. Fail closed on hop, JWT mint or verify, Match, snapshot, or missing-engine failure.
   502/504 with the existing JSON envelope.
   A configured filter that cannot be run is never a bypass.
9. Reserved headers as listed in [section 7](#7-the-reverse-proxy-hop), per-kind token prefixes (`av_cont_`, `av_pol_`), strip-then-set in both directions, tokens never in URLs.
10. `filter.url` and `filter.ca` validated per [section 2.2](#22-filterurl-and-ca).
    `AGENT_VAULT_MITM_ADDR` per [section 2.3](#23-agent_vault_mitm_addr): advertise only, not a bind.
    An invalid explicit value is fatal at startup.
    Dedicated dialer per [section 7.4](#74-dial-policy), including pinned `ca` roots and no skip-verify.
    Redirects implemented as not-followed.
11. Filtered WebSocket upgrades hop to the sidecar.
    Agent Vault verifies the continuation bind, then Resolve and origin dial.
12. Hidden from `/discover` and the skill topology.
    Proposals cannot set, clear, or delete filters or filtered services, and an explicit `filter` key is rejected rather than ignored.
    `enabled: false` remains allowed.
    Proxy-role service reads omit the filter block.
13. Preserve on `service add` omit.
    Wipe on `set`/`clear`.
    Admin list prints `filter`.
14. YAML only, following the substitutions precedent.
    `FilterOp` omit, set, or clear so `filter: null` survives encoding.
15. Hop tokens are ordinary JWTs (`HS256`) with `av_cont_` or `av_pol_` glued on the front.
    Ingress strips the prefix, then verifies.
    HMAC key derived from the DEK after unlock (same `master_key` every replica already loads).
    Bind and frozen match live in claims.
    Mint only on the filtered path.
16. `exp` is 30 seconds from mint.
    An already-minted hop JWT is valid until then, including after `agent revoke` ([section 4.4](#44-lifetime)).
    Ordinary CONNECT revocation is unchanged.
17. The frozen projection carries matcher identity and complete non-secret auth and substitution shape, never credential values, and excludes `Filter`.
    Do not re-run the matcher.
    Resolve current values for frozen key names.
    Version-first decode.
    Unknown version fails closed before any credential read.
18. No RFC 9457 in this change.
19. Proposals may not introduce a matcher that wins or ties an existing filtered service, checked at create and apply with exact matcher-language overlap ([section 3.1](#31-proposals-cannot-shadow-a-filtered-matcher)).
    Proposal-only.
    Admin YAML may author exceptions.
20. A policy token is a short lease of the initiating actor on the named vault and follows [The seam](#the-seam).
    Policy CONNECT uses the same pre-hijack rules as an agent session in that vault ([section 4.3](#43-policy-token)).
21. Continuations check bound authority at admission, before hijack ([section 4.2](#42-bind-check-at-admission)).
    Wrong bind is 403 (or 400) for that request.
22. Claims may carry actor and vault ids for audit.
    Verify does not look up the session ([section 4.5](#45-claims-and-signing)).
23. Security enforcement is mandatory, and every error on the filter path fails closed.
    No optional type assertions, no fall-through to Inject ([section 5](#5-enforcement-is-mandatory)).
24. Destination credential header slots, derived from the frozen auth configuration without reading values, are removed before the sidecar.
    `Authorization` is not stripped unconditionally ([section 7.2](#72-destination-credential-header-slots)).
25. A continuation and its optional policy JWT are minted with one non-authorizing `invocation_id`.
    The sidecar returns its decision as the HTTP response to the hop.
    A policy token presented again before `exp` still verifies ([section 4.7](#47-minting)).
26. Filtered ingress is rate-limited once.
    The concurrency slot is released before the sidecar round trip so the continuation can acquire its own.
    Each continuation admission is charged.
    Every policy request is charged.
    Logs retain initiator, service, and key-name attribution without raw tokens or values ([section 4.8](#48-rate-limits-and-request-logs)).
