package brokercore

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"net/http"
	"sort"
	"strings"
)

const DefaultRedactionReplacement = "[REDACTED]"

// ResolvedRedaction is an exact response-body replacement rule.
// Value is SECRET and must never be logged.
type ResolvedRedaction struct {
	Value       string
	Replacement string
	Source      string
}

// ApplyResponseRedactions replaces exact secret values in eligible
// text-like response bodies. Callers should only invoke this after deciding
// that the response can be safely materialized.
func ApplyResponseRedactions(body io.ReadCloser, contentLength int64, contentType string, redactions []ResolvedRedaction) (io.ReadCloser, int64, bool, error) {
	if len(redactions) == 0 {
		return body, contentLength, false, nil
	}
	if body == nil || body == http.NoBody {
		return body, contentLength, false, nil
	}

	data, err := io.ReadAll(body)
	if err != nil {
		return nil, 0, false, fmt.Errorf("reading body for response redaction: %w", err)
	}
	if len(data) == 0 {
		return http.NoBody, 0, false, nil
	}
	if !ShouldRedactResponseContentType(contentType) {
		return io.NopCloser(bytes.NewReader(data)), int64(len(data)), false, nil
	}

	ordered := make([]ResolvedRedaction, 0, len(redactions))
	for _, r := range redactions {
		if r.Value != "" {
			ordered = append(ordered, r)
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return len(ordered[i].Value) > len(ordered[j].Value)
	})

	orig := string(data)
	text := orig
	for _, r := range ordered {
		replacement := r.Replacement
		if replacement == "" {
			replacement = DefaultRedactionReplacement
		}
		text = strings.ReplaceAll(text, r.Value, replacement)
	}
	if text == orig {
		return io.NopCloser(bytes.NewReader(data)), int64(len(data)), false, nil
	}

	modified := []byte(text)
	return io.NopCloser(bytes.NewReader(modified)), int64(len(modified)), true, nil
}

// ShouldRedactResponseContentType reports whether response body redaction
// should materialize and scan a response with the given Content-Type.
func ShouldRedactResponseContentType(contentType string) bool {
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if mediaType == "" {
		return false
	}
	if strings.HasPrefix(mediaType, "text/") {
		return mediaType != "text/event-stream"
	}
	switch mediaType {
	case "application/json", "application/x-www-form-urlencoded", "application/xml":
		return true
	default:
		return strings.HasSuffix(mediaType, "+json") || strings.HasSuffix(mediaType, "+xml")
	}
}
