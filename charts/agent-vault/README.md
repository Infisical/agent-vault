# Agent Vault Helm Chart

This chart deploys [Agent Vault](https://github.com/Infisical/agent-vault), an HTTP credential proxy and vault for AI agents.

Agent Vault exposes two listeners:

- Management UI/API: port `14321`
- MITM proxy: port `14322`

Keep the MITM proxy private to trusted agent networks. The chart only creates an ingress for the management UI/API, and ingress is disabled by default.

## Install

```bash
helm install agent-vault ./charts/agent-vault \
  --set env.AGENT_VAULT_ADDR=http://agent-vault.example.internal:14321 \
  --set secretEnv.AGENT_VAULT_MASTER_PASSWORD=change-me
```

For a local UI session:

```bash
kubectl port-forward svc/agent-vault 14321:14321
open http://127.0.0.1:14321/register
```

The first registered user becomes the instance owner.

## Production with PostgreSQL

By default, Agent Vault uses SQLite under `/data/.agent-vault/agent-vault.db` and this chart enables a PVC. For production, set `DATABASE_URL` to use PostgreSQL. You may disable persistence when all durable state is in PostgreSQL.

```yaml
env:
  AGENT_VAULT_ADDR: https://agent-vault.example.com
  AGENT_VAULT_TELEMETRY: "false"

existingSecret: agent-vault-env
existingSecretKeys:
  - AGENT_VAULT_MASTER_PASSWORD
  - DATABASE_URL

persistence:
  enabled: false
```

The referenced secret should contain:

```text
AGENT_VAULT_MASTER_PASSWORD
DATABASE_URL
```

## Infisical-backed credential stores

Set `INFISICAL_URL` and one supported Infisical machine identity auth group to enable Infisical-backed vaults. For Universal Auth:

```yaml
env:
  INFISICAL_URL: https://app.infisical.com

existingSecret: agent-vault-env
existingSecretKeys:
  - AGENT_VAULT_MASTER_PASSWORD
  - DATABASE_URL
  - INFISICAL_UNIVERSAL_AUTH_CLIENT_ID
  - INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET
```

Then create an Infisical-backed vault from the Agent Vault CLI or UI:

```bash
agent-vault vault create hermes \
  --credential-store=infisical \
  --infisical-project-id=<project-id> \
  --infisical-environment=prod \
  --infisical-path=/hermes \
  --poll-interval-seconds=60
```

The Infisical machine identity should be read-only and scoped to the smallest project/path that Agent Vault needs.

## Values

| Value | Default | Description |
| --- | --- | --- |
| `replicaCount` | `1` | Number of Agent Vault pods. Use PostgreSQL before increasing. |
| `image.repository` | `infisical/agent-vault` | Container image repository. |
| `image.tag` | chart appVersion | Container image tag. |
| `server.port` | `14321` | Management UI/API port. |
| `server.mitmPort` | `14322` | MITM proxy port. |
| `env` | `{}` | Non-secret env vars. |
| `secretEnv` | `{}` | Secret env vars for chart-created Secret. |
| `existingSecret` | `""` | Existing Secret containing sensitive env vars. |
| `existingSecretKeys` | common Agent Vault secret keys | Keys to expose from `existingSecret`. |
| `service.api.type` | `ClusterIP` | Service type for the management UI/API. |
| `service.proxy.type` | `ClusterIP` | Service type for the MITM proxy. Keep private. |
| `ingress.enabled` | `false` | Whether to expose the management UI/API with Ingress. |
| `persistence.enabled` | `true` | PVC for SQLite/data storage. |
| `resources` | `{}` | Pod resource requests/limits. |

## Security notes

- Deploy Agent Vault separately from untrusted agent execution environments.
- Keep `14322` reachable only from trusted agent hosts/sandboxes.
- Prefer PostgreSQL and a strong `AGENT_VAULT_MASTER_PASSWORD` for production.
- Store real credentials in Agent Vault or in an Infisical-backed vault; agents should receive only placeholders and Agent Vault tokens.
- Do not put production secrets directly into `values.yaml`. Use `existingSecret` or your platform secret manager.
