# ADR 0003: Agent Vault MCP control-plane hub

- Status: Accepted
- Decision date: 2026-09-21
- Scope: macOS host-wide control plane

## Context

Docker MCP Gateway, ToolHive, ContextForge, and agentgateway were scored for
macOS lifecycle (25%), transport bridging (20%), authentication and OBO (20%),
policy and audit (15%), OpenTelemetry (10%), and operating cost (10%).

agentgateway scored 88.3 and ToolHive 79.8. Both cleared the threshold; the
8.5-point difference triggered the “within 10%, prefer existing infrastructure”
rule. ContextForge was rejected for its Apple Silicon production posture and
larger operational dependency set. Docker MCP Gateway was prerelease at the
research date. ToolHive remains the fallback if standards-based delegated OBO
becomes a V1 requirement, because OSS agentgateway did not document that feature.

## Decision

Use a dedicated, version- and hash-pinned agentgateway standalone process:

- its own LaunchAgent, config, and loopback-only bind, separate from LLM lanes;
- authenticated per-caller ingress; loopback reachability is not authentication;
- authorization restricted to exactly six tools:
  `vault_proposal_list`, `vault_proposal_show`, `vault_acquisition_start`,
  `vault_acquisition_status`, `vault_acquisition_cancel`, and
  `vault_approval_open`;
- every tool call requires an active `context_binding_id` and remains scoped to
  the authenticated vault;
- schemas contain references, enums, and timestamps only—never credentials,
  secret lengths, executable metadata, or approval tokens;
- argument and result bodies are excluded from hub logs; audit authority stays
  in Agent Vault;
- the provider runner remains independent, so hub failure cannot block CLI or
  browser approval.

OSS agentgateway OBO is explicitly out of scope for V1. If OBO becomes required,
the hub decision must be reopened and ToolHive or an enterprise STS evaluated.

## Consequences

Agent Vault exposes an authenticated Streamable HTTP endpoint for the six tools.
The hub carries only control-plane references. Approval remains a human action,
and no MCP request or response can carry credential material.

## Research provenance

See the [hub comparison](https://www.perplexity.ai/computer/tasks/7ce1c991-9d7c-42ec-8068-80574b1e5e09)
and [final synthesis](https://www.perplexity.ai/computer/tasks/67f645ea-cf2f-4751-8c41-ba1e2ae686da).
Primary references: [agentgateway standalone](https://agentgateway.dev/docs/standalone/latest/),
[ToolHive](https://docs.stacklok.com/toolhive/), and
[MCP Streamable HTTP](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports#streamable-http).
