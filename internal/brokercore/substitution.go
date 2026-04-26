package brokercore

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ResolvedSubstitution is a placeholder rewrite ready to apply to an
// outbound request. Value is SECRET — never log it.
type ResolvedSubstitution struct {
	Placeholder string
	Value       string
	In          []string // subset of {"path","query","header"} — security boundary
}

// ApplySubstitutions rewrites declared surfaces of an outbound request
// in-place. Path uses url.PathEscape, query uses url.QueryEscape, header
// uses the raw value with a CRLF guard. On error, callers must not
// forward the request — partial mutations may have been applied.
func ApplySubstitutions(u *url.URL, headers http.Header, subs []ResolvedSubstitution) error {
	if len(subs) == 0 {
		return nil
	}
	for _, sub := range subs {
		for _, surface := range sub.In {
			switch surface {
			case "path":
				if u == nil {
					continue
				}
				// Operate on the wire-encoded path so PathEscape'd values
				// land in the URL exactly once and don't get re-encoded
				// by String(). Placeholder characters are restricted to
				// RFC 3986 unreserved by the validator, so they appear
				// identically in encoded and decoded forms.
				escaped := u.EscapedPath()
				rewritten := strings.ReplaceAll(escaped, sub.Placeholder, url.PathEscape(sub.Value))
				if rewritten == escaped {
					continue
				}
				decoded, err := url.PathUnescape(rewritten)
				if err != nil {
					return fmt.Errorf("substitution into path produced invalid encoding for placeholder %q: %w", sub.Placeholder, err)
				}
				u.Path = decoded
				u.RawPath = rewritten
			case "query":
				if u != nil {
					u.RawQuery = strings.ReplaceAll(u.RawQuery, sub.Placeholder, url.QueryEscape(sub.Value))
				}
			case "header":
				if headers == nil {
					continue
				}
				if strings.ContainsAny(sub.Value, "\r\n") {
					return fmt.Errorf("substitution into header surface rejected: resolved value for placeholder %q contains CR or LF (header injection guard)", sub.Placeholder)
				}
				for _, vals := range headers {
					for i, v := range vals {
						vals[i] = strings.ReplaceAll(v, sub.Placeholder, sub.Value)
					}
				}
			}
		}
	}
	return nil
}
