# ADR 0001: Delegated credential provider protocol

- Status: Accepted
- Decision date: 2026-09-21
- Scope: Agent Vault core and native providers

## Context

Agent Vault needs to acquire one credential through an allowlisted local
provider without exposing plaintext to an agent, MCP payload, process argument,
environment variable, log, trace, screenshot, crash report, or loopback socket.
The acquisition must also remain bound to the originating Codex task,
Perplexity project, and registered workstation.

The research compared stdin/stdout, inherited pipes, Unix sockets, browser
native messaging, and loopback callbacks. JSON over stdin/stdout was rejected
because diagnostics and secret-bearing output share process streams. A private
socketpair was preferred because the parent creates both endpoints, can pass one
fixed descriptor to the child, and can close every unrelated descriptor.

The provider-semantics research also found a material disagreement around
`gh auth token`: the CLI can resolve ambient environment credentials, while the
macOS keyring entry remains readable by other same-user processes invoking the
same integration. Therefore GitHub CLI is accepted only as an audited bootstrap
import, not a steady-state credential provider.

## Decision

Use AVSH/1:

- canonical CBOR messages with a four-byte little-endian length prefix;
- a 64 KiB maximum frame and at most eight 1 KiB progress messages;
- a private inherited socket at file descriptor 3;
- `SOCK_SEQPACKET` on Linux and bounded stream framing on macOS;
- 32 random ticket bytes, single use, with bounded continuation state;
- an opaque server-issued `context_binding_id` on every message;
- direct absolute-binary execution, a sanitized environment, process groups,
  deadlines, bounded stderr, and pre/post-spawn hash and identity checks;
- locked, non-dumpable secret buffers that are encrypted immediately and wiped;
- Security.framework exact-item retrieval on macOS. `/usr/bin/security` is not
  an approved provider path;
- GitHub CLI v2.81.0 or newer, a fixed host, parsed active-account status,
  explicit `--user`, hidden `--secure-storage`, and provenance
  `untrusted_same_user_readable`.

The context binding is an anti-misrouting and anti-replay control. It is not an
authenticator and does not add confidentiality against arbitrary same-user code
execution.

## Consequences

Providers cannot be supplied commands, arguments, environment variables,
Keychain selectors, or browser selectors by proposals. Unsupported profiles and
modes fail closed. The GitHub provider imports once into vault-native encrypted
storage; consumers never receive a refresh token. Interactive provider work is
bounded and cannot weaken proposal approval.

## Research provenance

The four parallel Perplexity Deep Research tasks were
[secure handoff](https://www.perplexity.ai/computer/tasks/12f579c6-e3f3-48f4-a785-7eba8fe15603),
[provider semantics](https://www.perplexity.ai/computer/tasks/7626fa0c-9f3c-43fd-825f-1cb93cddf7a9),
[browser threat model](https://www.perplexity.ai/computer/tasks/7b9276d1-e0b5-4a3f-be81-6a32bd777446),
and [MCP hub selection](https://www.perplexity.ai/computer/tasks/7ce1c991-9d7c-42ec-8068-80574b1e5e09).
The [reasoning synthesis](https://www.perplexity.ai/computer/tasks/67f645ea-cf2f-4751-8c41-ba1e2ae686da)
reconciled disagreements and approved the amended V1 on 2026-09-21.

Primary references include [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252),
[RFC 8628](https://www.rfc-editor.org/rfc/rfc8628),
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), and
[Apple Keychain Services](https://developer.apple.com/documentation/security/keychain_services).
