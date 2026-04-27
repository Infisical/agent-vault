package inspect

import (
	"fmt"
	"strings"
)

// RequestLog is the secret-free request metadata needed for diagnostics.
type RequestLog struct {
	ID             int64    `json:"id"`
	Ingress        string   `json:"ingress"`
	Method         string   `json:"method"`
	Host           string   `json:"host"`
	Path           string   `json:"path"`
	MatchedService string   `json:"matched_service"`
	CredentialKeys []string `json:"credential_keys"`
	Status         int      `json:"status"`
	LatencyMs      int64    `json:"latency_ms"`
	ErrorCode      string   `json:"error_code"`
	ActorType      string   `json:"actor_type"`
	ActorID        string   `json:"actor_id"`
	CreatedAt      string   `json:"created_at"`
}

// Diagnosis is a best-effort explanation derived only from safe metadata.
type Diagnosis struct {
	Summary       string   `json:"summary"`
	Details       []string `json:"details,omitempty"`
	SuggestedNext []string `json:"suggested_next,omitempty"`
}

// Diagnose explains the most likely failure class for a single request log.
func Diagnose(log RequestLog) Diagnosis {
	method := strings.ToUpper(strings.TrimSpace(log.Method))
	errCode := strings.ToLower(strings.TrimSpace(log.ErrorCode))

	if log.Status == 405 && method != "CONNECT" && (log.Ingress == "mitm" || strings.Contains(errCode, "method")) {
		return Diagnosis{
			Summary: "Plain HTTP traffic may be hitting Agent Vault's transparent HTTPS proxy listener.",
			Details: []string{
				fmt.Sprintf("The request used %s and returned 405 on the %s ingress.", valueOrDash(method), valueOrDash(log.Ingress)),
				"Agent Vault's transparent HTTPS proxy path expects CONNECT-based HTTPS traffic.",
			},
			SuggestedNext: []string{
				"Use an HTTPS upstream endpoint if the provider or gateway supports one.",
				"If this is a local AI gateway, check whether Agent Vault needs explicit HTTP proxy support for that integration.",
			},
		}
	}

	if log.MatchedService == "" {
		if log.Status == 403 || log.Status == 404 {
			return Diagnosis{
				Summary: "No configured service appears to match this request host.",
				Details: []string{
					fmt.Sprintf("Host %q did not record a matched service.", log.Host),
					"Agent Vault can only inject credentials after a vault service matches the request target.",
				},
				SuggestedNext: []string{
					"Run `agent-vault vault service list` and verify the host pattern.",
					"If the host is expected, add or enable a service for it.",
				},
			}
		}
		return Diagnosis{
			Summary: "The request did not record a matched service.",
			Details: []string{
				"Credential injection probably did not run for this request.",
			},
			SuggestedNext: []string{
				"Verify the target host is configured in the active vault.",
			},
		}
	}

	if log.Status == 401 || log.Status == 403 {
		next := []string{
			"Verify the referenced credential is current.",
			"Confirm the service auth configuration matches the provider's expected header or URL format.",
		}
		if len(log.CredentialKeys) == 0 {
			next = append(next, "If this service should inject credentials, check whether it is configured as passthrough.")
		} else {
			next = append(next, "Check provider-specific required headers such as version or beta headers.")
		}
		return Diagnosis{
			Summary: "The upstream service rejected the authenticated request.",
			Details: []string{
				fmt.Sprintf("The request matched service %q and returned HTTP %d.", log.MatchedService, log.Status),
			},
			SuggestedNext: next,
		}
	}

	if log.Status == 407 {
		return Diagnosis{
			Summary: "Proxy authentication failed before the request reached the upstream service.",
			Details: []string{
				"Agent Vault did not accept the proxy/session credentials for this request.",
			},
			SuggestedNext: []string{
				"Relaunch the agent with `agent-vault run` or mint a fresh scoped session.",
				"Verify HTTPS_PROXY and Proxy-Authorization are coming from the same Agent Vault instance.",
			},
		}
	}

	if log.Status >= 500 && log.Status <= 599 {
		return Diagnosis{
			Summary: "The request failed at the upstream service or network boundary.",
			Details: []string{
				fmt.Sprintf("The request matched service %q and returned HTTP %d.", log.MatchedService, log.Status),
			},
			SuggestedNext: []string{
				"Retry against the provider directly from a trusted shell to separate provider outage from proxy configuration.",
				"Check Agent Vault server debug logs for transport errors around the same timestamp.",
			},
		}
	}

	if log.Status == 0 || errCode != "" {
		return Diagnosis{
			Summary: "The request failed before Agent Vault received a normal upstream HTTP response.",
			Details: []string{
				fmt.Sprintf("Recorded error code: %s.", valueOrDash(log.ErrorCode)),
			},
			SuggestedNext: []string{
				"Check TLS/CA trust configuration for the agent runtime.",
				"Check DNS, sandbox egress rules, and local network access to the target host.",
			},
		}
	}

	if log.LatencyMs >= 10000 {
		return Diagnosis{
			Summary: "The request succeeded or completed, but latency is high.",
			Details: []string{
				fmt.Sprintf("Recorded latency was %d ms.", log.LatencyMs),
			},
			SuggestedNext: []string{
				"Compare with direct provider latency from the same environment.",
				"Check whether sandbox networking or the upstream provider is adding delay.",
			},
		}
	}

	if log.Status >= 200 && log.Status <= 399 {
		return Diagnosis{
			Summary: "No obvious failure detected from request-log metadata.",
			Details: []string{
				fmt.Sprintf("The request matched service %q and returned HTTP %d.", log.MatchedService, log.Status),
			},
			SuggestedNext: []string{
				"If the agent still failed, inspect the agent-side application error because the proxy path appears healthy.",
			},
		}
	}

	return Diagnosis{
		Summary: "No specific diagnosis matched this request.",
		Details: []string{
			"Agent Vault only records secret-free request metadata, so this explanation is intentionally conservative.",
		},
		SuggestedNext: []string{
			"Use status, matched service, ingress, and server debug logs to narrow the failure.",
		},
	}
}

// DiagnoseBatch returns diagnoses for failed or suspicious logs.
func DiagnoseBatch(logs []RequestLog) []DiagnosisForLog {
	out := make([]DiagnosisForLog, 0, len(logs))
	for _, log := range logs {
		if !isSuspicious(log) {
			continue
		}
		out = append(out, DiagnosisForLog{Log: log, Diagnosis: Diagnose(log)})
	}
	return out
}

// DiagnosisForLog pairs a log with its diagnosis.
type DiagnosisForLog struct {
	Log       RequestLog `json:"log"`
	Diagnosis Diagnosis  `json:"diagnosis"`
}

func isSuspicious(log RequestLog) bool {
	return log.Status == 0 || log.Status >= 400 || log.ErrorCode != "" || log.MatchedService == "" || log.LatencyMs >= 10000
}

func valueOrDash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}
