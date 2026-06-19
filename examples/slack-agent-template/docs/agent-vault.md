# Agent Vault Setup

Agent Vault should hold production credentials and inject them into outbound requests from this Slack agent. The agent process receives placeholders, not raw secrets.

## Runtime Contract

Hosted agents need these variables:

```text
AGENT_VAULT_ADDR=http://<agent-vault-host>:14321
AGENT_VAULT_TOKEN=<agent-token>
AGENT_VAULT_VAULT=<vault-name>
```

Then run the process through:

```bash
agent-vault run -- node dist/slack.js
```

The Dockerfile already does this.

`agent-vault run` validates the token, configures `HTTPS_PROXY` and `HTTP_PROXY`, sets CA trust variables, and starts the child process. The app should call real upstream URLs while omitting credentials or using placeholders.

## Minimum Services

Most deployments need these services in Agent Vault:

| Service | Host Pattern | Credential | Why |
|---|---|---|---|
| Anthropic | `api.anthropic.com` | `ANTHROPIC_API_KEY` | Claude Agent SDK model calls |
| Slack Web API | `slack.com/api/*` | `SLACK_BOT_TOKEN` | Slack API calls from Bolt/Web API |
| Slack Socket Mode | Slack app-level token service, if configured through Agent Vault | `SLACK_APP_TOKEN` | Socket Mode connection |
| Your service | `api.example.com` | service-specific credential | Tools you add on top of the template |

Exact auth type and host-pattern support may change as Agent Vault evolves. Check the current Agent Vault service UI/docs before publishing a public walkthrough.

## Placeholder Convention

Use lowercase placeholder names wrapped in double underscores:

```text
ANTHROPIC_API_KEY=__anthropic_api_key__
SLACK_BOT_TOKEN=__slack_bot_token__
SLACK_APP_TOKEN=__slack_app_token__
SERVICE_API_TOKEN=__service_api_token__
```

Placeholders are safe to commit in docs and examples. Raw credentials are not.

## Local Development Options

For fast local iteration, either:

- put real throwaway development credentials in a local `.env`, or
- run the local process through Agent Vault with placeholders.

Never commit `.env`.

## Verification

After deployment:

1. Open the service health check at `/health`.
2. DM the Slack app a simple prompt.
3. Confirm Agent Vault request logs show calls to the expected upstream services.
4. Confirm no hosted environment variable contains a raw production credential.

## Common Issues

`agent token rejected by broker`: rotate or recreate the Agent Vault agent token and verify it has access to `AGENT_VAULT_VAULT`.

`vault is required in agent mode`: set `AGENT_VAULT_VAULT` in the hosted environment.

Slack API calls do not appear in Agent Vault logs: keep the explicit `HttpsProxyAgent` wiring in `src/slack.ts`; Slack's Web API client does not rely only on proxy env vars.

Slack returns `invalid_auth` behind Agent Vault: do not pass per-call Slack `token` arguments. The template authenticates Slack clients with a client-level token so the token stays in the Authorization header where Agent Vault can substitute it.

Allowlist rejects everyone: unset `AGENT_ALLOWLIST` to allow all workspace users, or add `users:read` and `users:read.email` scopes, reinstall the Slack app, and set `AGENT_ALLOWLIST` to approved email addresses.

Model calls fail but Slack works: verify the `api.anthropic.com` service and `ANTHROPIC_API_KEY` placeholder mapping.

Example API tool returns setup guidance: set `EXAMPLE_API_BASE_URL` or replace `src/tools/example-api.ts` with a real service-specific tool.
