package server

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testIndexHTML mirrors the structure of the built webdist/index.html.
// Tests inject it explicitly because webdist is empty until `make build`.
const testIndexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<base href="/" />
<link rel="icon" href="./favicon.svg" />
<script type="module" src="./assets/index-abc123.js"></script>
</head>
<body><div id="root"></div></body>
</html>`

func TestNormalizeBasePath(t *testing.T) {
	valid := []struct{ in, want string }{
		{"", ""},
		{"/", ""},
		{" /vault ", "/vault"},
		{"/vault", "/vault"},
		{"/vault/", "/vault"},
		{"vault", "/vault"},
		{"/tools/vault", "/tools/vault"},
		{"/tools/vault/", "/tools/vault"},
	}
	for _, tc := range valid {
		got, err := NormalizeBasePath(tc.in)
		if err != nil {
			t.Errorf("NormalizeBasePath(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("NormalizeBasePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	invalid := []string{"//vault", "/vault//x", "/va ult", "/vault?x", "/vault#x", "/./vault", "/../vault"}
	for _, in := range invalid {
		if got, err := NormalizeBasePath(in); err == nil {
			t.Errorf("NormalizeBasePath(%q) = %q, want error", in, got)
		}
	}
}

func TestInjectBasePath(t *testing.T) {
	in := []byte(testIndexHTML)

	// Root mode: byte-for-byte unchanged.
	if got := injectBasePath(in, ""); !bytes.Equal(got, in) {
		t.Errorf("injectBasePath with empty base path mutated index.html:\n%s", got)
	}

	got := string(injectBasePath(in, "/vault"))
	if !strings.Contains(got, `<base href="/vault/" />`) {
		t.Errorf("injected index.html missing rewritten base tag:\n%s", got)
	}
	if strings.Contains(got, `<base href="/" />`) {
		t.Errorf("injected index.html still contains root base tag:\n%s", got)
	}
	// Hashed asset references must be untouched.
	if !strings.Contains(got, `./assets/index-abc123.js`) {
		t.Errorf("injected index.html altered asset references:\n%s", got)
	}
}

// serveBasePath dispatches a request through the full handler chain
// (security headers, rate limiting, prefix mounting).
func serveBasePath(srv *Server, method, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	return rec
}

func TestUIBasePathRouting(t *testing.T) {
	srv := newTestServerWithBasePath("/vault")
	srv.indexHTML = injectBasePath([]byte(testIndexHTML), "/vault")

	// API and SPA routes are served under the prefix.
	if rec := serveBasePath(srv, http.MethodGet, "/vault/v1/status"); rec.Code != http.StatusOK {
		t.Errorf("GET /vault/v1/status = %d, want 200", rec.Code)
	}
	if rec := serveBasePath(srv, http.MethodGet, "/vault/login"); rec.Code != http.StatusOK {
		t.Errorf("GET /vault/login = %d, want 200", rec.Code)
	}

	// index.html carries the injected base tag.
	rec := serveBasePath(srv, http.MethodGet, "/vault/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /vault/ = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `<base href="/vault/" />`) {
		t.Errorf("GET /vault/ body missing injected base tag:\n%s", rec.Body.String())
	}

	// Unprefixed paths are not served (the proxy passes the prefix through).
	if rec := serveBasePath(srv, http.MethodGet, "/v1/status"); rec.Code != http.StatusNotFound {
		t.Errorf("GET /v1/status = %d, want 404", rec.Code)
	}

	// Root /health stays reachable for platform probes.
	if rec := serveBasePath(srv, http.MethodGet, "/health"); rec.Code != http.StatusOK {
		t.Errorf("GET /health = %d, want 200", rec.Code)
	}

	// Redirects onto the prefix.
	if rec := serveBasePath(srv, http.MethodGet, "/"); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/vault/" {
		t.Errorf("GET / = %d %q, want 302 /vault/", rec.Code, rec.Header().Get("Location"))
	}
	if rec := serveBasePath(srv, http.MethodGet, "/vault"); rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/vault/" {
		t.Errorf("GET /vault = %d %q, want 301 /vault/", rec.Code, rec.Header().Get("Location"))
	}
}

func TestUIBasePathCookieAndLogout(t *testing.T) {
	srv := newTestServerWithBasePath("/vault")

	c := srv.sessionCookie(httptest.NewRequest(http.MethodGet, "/vault/", nil), "tok", 60)
	if c.Path != "/vault/" {
		t.Errorf("sessionCookie Path = %q, want /vault/", c.Path)
	}

	rec := serveBasePath(srv, http.MethodPost, "/vault/v1/auth/logout")
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /vault/v1/auth/logout = %d, want 200", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Path != "/vault/" {
		t.Errorf("logout Set-Cookie = %+v, want one av_session cookie with Path=/vault/", cookies)
	}
}

func TestUIBasePathBaseURL(t *testing.T) {
	// Prefix is appended to the externally-reachable base URL so generated
	// links (invites, approval URLs, OAuth redirects) include it.
	srv := newTestServerWithBasePath("/vault")
	if got := srv.BaseURL(); got != "http://127.0.0.1:14321/vault" {
		t.Errorf("BaseURL() = %q, want http://127.0.0.1:14321/vault", got)
	}

	// Already-suffixed base URLs are not double-appended.
	srv2 := New("127.0.0.1:0", newMockStore(), make([]byte, 32), nil, true, "https://example.com/vault/", "/vault", slog.New(slog.DiscardHandler))
	if got := srv2.BaseURL(); got != "https://example.com/vault" {
		t.Errorf("BaseURL() = %q, want https://example.com/vault", got)
	}
}

func TestRootModeUnchanged(t *testing.T) {
	srv := newTestServer()
	srv.indexHTML = []byte(testIndexHTML)

	// Served index.html is byte-for-byte the build output.
	rec := serveBasePath(srv, http.MethodGet, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if rec.Body.String() != testIndexHTML {
		t.Errorf("root-mode index.html was mutated:\n%s", rec.Body.String())
	}

	if rec := serveBasePath(srv, http.MethodGet, "/v1/status"); rec.Code != http.StatusOK {
		t.Errorf("GET /v1/status = %d, want 200", rec.Code)
	}

	c := srv.sessionCookie(httptest.NewRequest(http.MethodGet, "/", nil), "tok", 60)
	if c.Path != "/" {
		t.Errorf("root-mode sessionCookie Path = %q, want /", c.Path)
	}
	if got := srv.BaseURL(); got != "http://127.0.0.1:14321" {
		t.Errorf("root-mode BaseURL() = %q, want http://127.0.0.1:14321", got)
	}
}
