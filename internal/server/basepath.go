package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	pathpkg "path"
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
	if p == "" {
		return "", fmt.Errorf("invalid UI base path: empty after removing trailing slashes")
	}
	if p == "/health" || p == "/discover" || p == "/v1" || strings.HasPrefix(p, "/v1/") {
		return "", fmt.Errorf("invalid UI base path %q: overlaps a root control route", p)
	}
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

// mountUIBasePath sends prefixed requests through the same application mux
// as root requests. Redirects from the mux are rebased after prefix stripping
// so its canonical route redirects remain inside the mount.
func mountUIBasePath(app http.Handler, basePath string) http.Handler {
	if basePath == "" {
		return app
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == basePath {
			u := *r.URL
			u.Path = basePath + "/"
			u.RawPath = ""
			http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
			return
		}
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			u := *r.URL
			u.Path = basePath + "/"
			u.RawPath = ""
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
		if !strings.HasPrefix(r.URL.Path, basePath+"/") {
			app.ServeHTTP(w, r)
			return
		}
		if location, ok := canonicalMountedLocation(r.URL, basePath); ok {
			http.Redirect(w, r, location, http.StatusTemporaryRedirect)
			return
		}
		clone := r.Clone(r.Context())
		u := *r.URL
		u.Path = strings.TrimPrefix(u.Path, basePath)
		rawSuffix, ok := escapedMountSuffix(r.URL.EscapedPath(), basePath)
		if !ok {
			http.Error(w, "invalid escaped mount path", http.StatusBadRequest)
			return
		}
		u.RawPath = rawSuffix
		clone.URL = &u
		app.ServeHTTP(&basePathRedirectWriter{ResponseWriter: w, basePath: basePath}, clone)
	})
}

func canonicalMountedLocation(requestURL *url.URL, basePath string) (string, bool) {
	escapedPath := requestURL.EscapedPath()
	suffix, ok := escapedMountSuffix(escapedPath, basePath)
	if !ok {
		return "", false
	}
	cleaned := pathpkg.Clean(suffix)
	if strings.HasSuffix(suffix, "/") && cleaned != "/" {
		cleaned += "/"
	}
	if cleaned == suffix {
		return "", false
	}
	cleaned = basePath + cleaned
	decoded, err := url.PathUnescape(cleaned)
	if err != nil {
		return "", false
	}
	u := *requestURL
	u.Path = decoded
	u.RawPath = cleaned
	return u.String(), true
}

// escapedMountSuffix removes a decoded mount name from an escaped URL path.
// A client may escape unreserved bytes in the mount itself (/%76ault), so a
// literal string trim would leave RawPath inconsistent with Path.
func escapedMountSuffix(escapedPath, basePath string) (string, bool) {
	index := 0
	for i := 0; i < len(basePath); i++ {
		if index >= len(escapedPath) {
			return "", false
		}
		var next byte
		if escapedPath[index] == '%' {
			if index+3 > len(escapedPath) {
				return "", false
			}
			decoded, err := url.PathUnescape(escapedPath[index : index+3])
			if err != nil || len(decoded) != 1 {
				return "", false
			}
			next = decoded[0]
			index += 3
		} else {
			next = escapedPath[index]
			index++
		}
		if next != basePath[i] {
			return "", false
		}
	}
	suffix := escapedPath[index:]
	if len(suffix) >= 3 && suffix[0] == '%' && suffix[1] == '2' && (suffix[2] == 'F' || suffix[2] == 'f') {
		// The slash after the mount may itself be escaped. It is a route
		// separator in Path, so keep RawPath absolute after stripping.
		suffix = "/" + suffix[3:]
	}
	return suffix, true
}

type basePathRedirectWriter struct {
	http.ResponseWriter
	basePath string
}

func (w *basePathRedirectWriter) WriteHeader(status int) {
	if status >= http.StatusMultipleChoices && status < http.StatusBadRequest {
		if location := w.Header().Get("Location"); location != "" {
			u, err := url.Parse(location)
			if err == nil && !u.IsAbs() && u.Host == "" && strings.HasPrefix(u.Path, "/") {
				u.Path = w.basePath + u.Path
				if u.RawPath != "" {
					u.RawPath = w.basePath + u.RawPath
				}
				w.Header().Set("Location", u.String())
			}
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *basePathRedirectWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
