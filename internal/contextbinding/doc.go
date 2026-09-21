// Package contextbinding defines immutable context identifiers used to prevent
// acquisition jobs from being replayed or routed into a different Codex,
// Perplexity project, or registered workstation context.
//
// Context binding is an anti-misrouting and anti-replay control. It does not
// provide authentication, authorization, confidentiality, or workstation
// attestation; callers must provide those controls separately.
package contextbinding
