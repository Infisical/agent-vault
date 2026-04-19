package brokercore

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// ParseProxyAuth extracts an Agent Vault session token and optional vault
// hint from a Proxy-Authorization header.
//
// Supported forms:
//   - Bearer <token>                        — token only, no vault hint
//   - Basic base64(<token>)                 — token only, no vault hint
//   - Basic base64(<token>:<vault-name>)    — token + vault hint
//
// The Basic form maps directly to HTTPS_PROXY URLs:
//
//	HTTPS_PROXY=https://<token>@host:port          (scoped session)
//	HTTPS_PROXY=https://<token>:<vault>@host:port  (instance-level agent token)
//
// Vault names are config-validated as UPPER/lowercase alphanumeric + hyphens,
// so they cannot contain a colon; splitting on the first colon in the decoded
// userinfo is unambiguous.
//
// Returns ErrInvalidSession when the header is missing, malformed, or of an
// unsupported scheme. Higher-level handlers map this to 407.
func ParseProxyAuth(r *http.Request) (token, vaultHint string, err error) {
	h := r.Header.Get("Proxy-Authorization")
	if h == "" {
		return "", "", ErrInvalidSession
	}

	scheme, rest, ok := strings.Cut(h, " ")
	if !ok || rest == "" {
		return "", "", ErrInvalidSession
	}
	rest = strings.TrimSpace(rest)

	switch strings.ToLower(scheme) {
	case "bearer":
		if rest == "" {
			return "", "", ErrInvalidSession
		}
		return rest, "", nil
	case "basic":
		decoded, derr := base64.StdEncoding.DecodeString(rest)
		if derr != nil {
			return "", "", ErrInvalidSession
		}
		userinfo := string(decoded)
		if userinfo == "" {
			return "", "", ErrInvalidSession
		}
		if idx := strings.Index(userinfo, ":"); idx >= 0 {
			tok := userinfo[:idx]
			hint := userinfo[idx+1:]
			if tok == "" {
				return "", "", ErrInvalidSession
			}
			return tok, hint, nil
		}
		return userinfo, "", nil
	default:
		return "", "", ErrInvalidSession
	}
}
