package server

import (
	"bytes"
	"fmt"
	"strings"
)

// uiBaseHrefTag is the placeholder <base> tag the Vite build leaves in
// webdist/index.html (see web/index.html). injectBasePath rewrites it at
// startup; the byte sequence must match the source file exactly.
const uiBaseHrefTag = `<base href="/" />`

// NormalizeBasePath validates and canonicalizes a --ui-base-path value.
// "" and "/" both mean root mounting and return "". Anything else is
// returned with a leading "/" and no trailing slash (e.g. "/vault",
// "/tools/vault").
func NormalizeBasePath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || p == "/" {
		return "", nil
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimRight(p, "/")
	// Allowlist: the value is spliced into an HTML attribute by
	// injectBasePath and into cookie paths / redirect targets, so reject
	// anything beyond unreserved URL characters and the segment separator.
	for _, r := range p {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '/' || r == '-' || r == '_' || r == '.' || r == '~':
		default:
			return "", fmt.Errorf("invalid UI base path %q: only letters, digits, '/', '-', '_', '.', '~' are allowed", p)
		}
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("invalid UI base path %q: empty or relative path segment", p)
		}
	}
	return p, nil
}

// injectBasePath rewrites the <base href="/" /> placeholder in index.html
// to the configured prefix so the SPA's relative asset URLs, router
// basepath, and API calls all resolve under it. An empty basePath returns
// the input unchanged, keeping root deployments byte-for-byte identical to
// the build output. Only this unhashed entrypoint is ever rewritten —
// content-hashed assets must keep matching their filenames so immutable
// caching stays valid.
func injectBasePath(indexHTML []byte, basePath string) []byte {
	if basePath == "" {
		return indexHTML
	}
	return bytes.Replace(indexHTML, []byte(uiBaseHrefTag), []byte(`<base href="`+basePath+`/" />`), 1)
}
