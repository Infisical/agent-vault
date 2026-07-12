# Agent Vault Helm Chart

This chart deploys [Agent Vault](https://github.com/Infisical/agent-vault), an HTTP credential proxy and vault for AI agents.

Agent Vault exposes two listeners through one Kubernetes Service because clients derive the proxy hostname from `AGENT_VAULT_ADDR` and change only the port:

- Management UI/API: port `14321`
- Credential proxy: port `14322`

The optional Ingress routes only the management UI/API. It never exposes the proxy listener and is intended for human access. Agents must use a private address that reaches both ports on the Service.

## Install from OCI

Release tags publish a signed chart to GHCR. Strip the leading `v` from the application tag when selecting the chart version:

```bash
helm install agent-vault \
  oci://ghcr.io/infisical/charts/agent-vault \
  --version 0.40.0 \
  --set-string secretEnv.AGENT_VAULT_MASTER_PASSWORD='replace-me'
```

For production, do not put the master password on the command line or in a values file. Sync it into a Kubernetes Secret and use `existingSecret`.

Verify the chart artifact before deployment:

```bash
cosign verify \
  --certificate-identity-regexp='^https://github.com/Infisical/agent-vault/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  ghcr.io/infisical/charts/agent-vault:0.40.0
```

## Local access

Port-forward both listeners from the same Service so the CLI's derived proxy address remains valid:

```bash
kubectl port-forward svc/agent-vault 14321:14321 14322:14322
export AGENT_VAULT_ADDR=http://127.0.0.1:14321
open http://127.0.0.1:14321/register
```

The first registered user becomes the instance owner. A local deployment keeps both cleartext Agent Vault tokens and proxied credentials on the loopback interface. A shared cluster deployment centralizes persistence and operations, but it must place both listeners behind a private network because `Proxy-Authorization` is not end-to-end encrypted between the client and Agent Vault.

## PostgreSQL and scaling

The default configuration uses SQLite under `/data/.agent-vault/agent-vault.db`, enables a PVC, forces a `Recreate` deployment strategy, and rejects `replicaCount > 1`.

Use PostgreSQL before scaling above one replica. Set `DATABASE_URL` from a database-managed Kubernetes Secret, then disable local persistence:

```yaml
replicaCount: 2

existingSecret: agent-vault-runtime
existingSecretKeys:
  required:
    - AGENT_VAULT_MASTER_PASSWORD
  optional: []

extraEnv:
  - name: DATABASE_URL
    valueFrom:
      secretKeyRef:
        name: agent-vault-db-app
        key: uri

persistence:
  enabled: false
```

All replicas must share the same PostgreSQL database and master password. Validate one replica, migrations, CA persistence, and client sessions before increasing the replica count.

## Infisical-backed credential stores

Agent Vault supports Infisical Kubernetes Auth without a static client secret. Enable service-account token mounting only for this workload and bind the corresponding Infisical identity to the narrowest project and path it needs:

```yaml
serviceAccount:
  automount: true

env:
  INFISICAL_URL: https://app.infisical.com
  INFISICAL_KUBERNETES_IDENTITY_ID: identity-id
  INFISICAL_KUBERNETES_SERVICE_ACCOUNT_TOKEN_PATH: /var/run/secrets/kubernetes.io/serviceaccount/token
```

Then create an Infisical-backed vault from the CLI or UI:

```bash
agent-vault vault create hermes \
  --credential-store=infisical \
  --infisical-project-id=<project-id> \
  --infisical-environment=prod \
  --infisical-path=/hermes \
  --poll-interval-seconds=60
```

## Network boundaries

The chart enables an ingress-only `NetworkPolicy` by default:

- API port `14321` accepts all otherwise-routable sources by default.
- Proxy port `14322` accepts pods in the release namespace by default.
- `networkPolicy.api.from` and `networkPolicy.proxy.from` accept standard Kubernetes NetworkPolicy peers, including namespace selectors, pod selectors, and IP blocks.
- The chart deliberately does not add an egress policy. Agent Vault's netguard independently rejects loopback, private, link-local, and cloud metadata destinations.

For a NodePort or private-overlay bridge, add only the node or bridge source CIDRs to `networkPolicy.proxy.from`. Never publish `14322` through a public Ingress or load balancer.

Agent Vault passes unmatched destinations through by default. Use strict-deny vault policy for agents that should only reach registered services; the Kubernetes policy protects who can reach the proxy, while vault policy controls what the proxy will authorize.

## Important values

| Value | Default | Description |
| --- | --- | --- |
| `replicaCount` | `1` | Agent Vault pods; values above one require PostgreSQL and `persistence.enabled=false`. |
| `image.repository` | `infisical/agent-vault` | Container image repository. |
| `image.tag` | chart appVersion | Container image tag. |
| `image.digest` | `""` | Optional `sha256:` digest; takes precedence over the tag. |
| `serviceAccount.automount` | `false` | Mount a Kubernetes token only for workload identity. |
| `existingSecret` | `""` | Existing Secret containing sensitive environment variables. |
| `existingSecretKeys.required` | master password | Keys that must exist in `existingSecret`. |
| `existingSecretKeys.optional` | supported integrations | Keys ignored when absent. |
| `service.type` | `ClusterIP` | Type of the single dual-port Service. |
| `service.api.nodePort` | `0` | Optional explicit API NodePort. |
| `service.proxy.nodePort` | `0` | Optional explicit private proxy NodePort. |
| `networkPolicy.enabled` | `true` | Restrict inbound API/proxy access. |
| `ingress.enabled` | `false` | Expose only the management UI/API with Ingress. |
| `persistence.enabled` | `true` | PVC for SQLite/data storage. |

## Security notes

- Deploy Agent Vault separately from untrusted agent execution environments.
- Use a strong `AGENT_VAULT_MASTER_PASSWORD`; the chart refuses to render without one supplied through a generated or existing Secret.
- Pin both the chart version and image digest in production.
- Store real provider credentials in Agent Vault or a supported external credential store. Agents should receive only placeholders and scoped Agent Vault tokens.
- Keep the API and proxy on a private network unless the API is separately protected by a trusted access layer.
