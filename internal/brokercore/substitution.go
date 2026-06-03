package brokercore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

// ResolvedSubstitution is a placeholder rewrite ready to apply to an
// outbound request. Value is SECRET — never log it.
type ResolvedSubstitution struct {
	Placeholder string
	Value       string
	In          []string // subset of {"path","query","header","body","websocket"} — security boundary
}

// HasBodySubstitutions reports whether any substitution targets the
// "body" surface — used to decide whether the request body must be
// materialized in RAM.
func HasBodySubstitutions(subs []ResolvedSubstitution) bool {
	for _, sub := range subs {
		for _, s := range sub.In {
			if s == "body" {
				return true
			}
		}
	}
	return false
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

// ApplyBodySubstitutions rewrites the request body in-place for any
// substitution declaring the "body" surface. Encoding is content-type-aware:
// form-urlencoded values are QueryEscaped, JSON values are string-escaped,
// multipart bodies are skipped, and everything else uses raw replacement.
// Returns the (possibly new) body, its byte length, whether anything changed,
// and any error.
func ApplyBodySubstitutions(body io.ReadCloser, contentLength int64, contentType string, subs []ResolvedSubstitution) (io.ReadCloser, int64, bool, error) {
	var bodySubs []ResolvedSubstitution
	for _, sub := range subs {
		for _, s := range sub.In {
			if s == "body" {
				bodySubs = append(bodySubs, sub)
				break
			}
		}
	}
	if len(bodySubs) == 0 {
		return body, contentLength, false, nil
	}
	if body == nil || body == http.NoBody {
		return body, contentLength, false, nil
	}

	data, err := io.ReadAll(body)
	if err != nil {
		return nil, 0, false, fmt.Errorf("reading body for substitution: %w", err)
	}
	if len(data) == 0 {
		return http.NoBody, 0, false, nil
	}

	mediaType, _, _ := mime.ParseMediaType(contentType)
	if strings.HasPrefix(mediaType, "multipart/") {
		return io.NopCloser(bytes.NewReader(data)), int64(len(data)), false, nil
	}

	encode := bodyEncoder(mediaType)
	orig := string(data)
	text := orig
	for _, sub := range bodySubs {
		text = strings.ReplaceAll(text, sub.Placeholder, encode(sub.Value))
	}

	if text == orig {
		return io.NopCloser(bytes.NewReader(data)), int64(len(data)), false, nil
	}

	modified := []byte(text)
	return io.NopCloser(bytes.NewReader(modified)), int64(len(modified)), true, nil
}

func bodyEncoder(mediaType string) func(string) string {
	switch mediaType {
	case "application/x-www-form-urlencoded":
		return url.QueryEscape
	case "application/json":
		return jsonEscapeString
	default:
		return func(s string) string { return s }
	}
}

func jsonEscapeString(s string) string {
	b, _ := json.Marshal(s)
	// json.Marshal wraps in quotes: "value" → strip them
	return string(b[1 : len(b)-1])
}
