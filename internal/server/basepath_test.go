package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
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

	invalid := []string{
		"//", "///", "/health", "/discover", "/v1", "/v1/admin",
		"//vault", "/vault//x", "/./vault", "/../vault",
		"/va ult", "/vault?x", "/vault#x", `/va"ult`, "/va<ult", "/vault%20x", "/vault'x",
	}
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

	// Root control APIs remain available to existing clients.
	if rec := serveBasePath(srv, http.MethodGet, "/v1/status"); rec.Code != http.StatusOK {
		t.Errorf("GET /v1/status = %d, want 200", rec.Code)
	}
	for _, path := range []string{"/discover", "/vault/discover"} {
		if rec := serveBasePath(srv, http.MethodGet, path); rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s = %d, want 401 from the same auth route", path, rec.Code)
		}
	}

	// Root /health stays reachable for platform probes.
	if rec := serveBasePath(srv, http.MethodGet, "/health"); rec.Code != http.StatusOK {
		t.Errorf("GET /health = %d, want 200", rec.Code)
	}

	// Redirects onto the prefix.
	if rec := serveBasePath(srv, http.MethodGet, "/"); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/vault/" {
		t.Errorf("GET / = %d %q, want 302 /vault/", rec.Code, rec.Header().Get("Location"))
	}
	if rec := serveBasePath(srv, http.MethodGet, "/?token=example"); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/vault/?token=example" {
		t.Errorf("GET /?token=example = %d %q, want 302 /vault/?token=example", rec.Code, rec.Header().Get("Location"))
	}
	if rec := serveBasePath(srv, http.MethodGet, "/vault"); rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/vault/" {
		t.Errorf("GET /vault = %d %q, want 301 /vault/", rec.Code, rec.Header().Get("Location"))
	}
}

func TestMountedSkillsRoutes(t *testing.T) {
	srv := newTestServerWithBasePath("/vault")
	srv.indexHTML = injectBasePath([]byte(testIndexHTML), "/vault")
	for _, path := range []string{"/v1/vaults/default/skills", "/vault/v1/vaults/default/skills"} {
		if rec := serveBasePath(srv, http.MethodGet, path); rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s = %d, want 401 from Skills API authentication", path, rec.Code)
		}
	}
	page := serveBasePath(srv, http.MethodGet, "/vault/vaults/default/skills")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `<base href="/vault/" />`) {
		t.Errorf("mounted Skills page = %d, missing UI base tag", page.Code)
	}
}

func TestUIBasePathCanonicalRedirects(t *testing.T) {
	for _, tc := range []struct{ base, target, want string }{
		{"/vault", "/vault/manage?next=%2Fone", "/vault/manage/?next=%2Fone"},
		{"/vault", "/vault/vaults//demo/a%2Fb?next=%2Fone", "/vault/vaults/demo/a%2Fb?next=%2Fone"},
		{"/account", "/account/account?next=%2Fone", "/account/account/?next=%2Fone"},
		{"/assets", "/assets/assets?next=%2Fone", "/assets/assets/?next=%2Fone"},
	} {
		srv := newTestServerWithBasePath(tc.base)
		rec := serveBasePath(srv, http.MethodGet, tc.target)
		if got := rec.Header().Get("Location"); got != tc.want {
			t.Errorf("GET %s: status=%d Location=%q, want %q", tc.target, rec.Code, got, tc.want)
		}
	}
}

func TestMountRedirectLocationForms(t *testing.T) {
	for _, tc := range []struct{ location, want string }{
		{"/a%2Fb?next=%2Fone", "/vault/a%2Fb?next=%2Fone"},
		{"next?token=one", "next?token=one"},
		{"https://example.test/next?token=one", "https://example.test/next?token=one"},
	} {
		app := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", tc.location)
			w.WriteHeader(http.StatusFound)
		})
		rec := httptest.NewRecorder()
		mountUIBasePath(app, "/vault").ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/vault/start", nil))
		if got := rec.Header().Get("Location"); got != tc.want {
			t.Errorf("Location %q rebased to %q, want %q", tc.location, got, tc.want)
		}
	}
}

func TestEscapedMountPreservesEscapedSuffix(t *testing.T) {
	for _, tc := range []struct{ mount, target string }{
		{"/vault", "/vault/echo/a%2Fb?next=%2Fone"},
		{"/vault", "/%76ault/echo/a%2Fb?next=%2Fone"},
		{"/vault", "/%76ault%2Fecho/a%2Fb?next=%2Fone"},
		{"/tools/vault", "/tools/%76ault/echo/a%2Fb?next=%2Fone"},
	} {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /echo/{value}", func(w http.ResponseWriter, r *http.Request) {
			if got := r.PathValue("value"); got != "a/b" {
				t.Errorf("value = %q, want a/b", got)
			}
			if got := r.URL.RawQuery; got != "next=%2Fone" {
				t.Errorf("query = %q, want next=%%2Fone", got)
			}
			w.WriteHeader(http.StatusNoContent)
		})
		rec := httptest.NewRecorder()
		mountUIBasePath(mux, tc.mount).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.target, nil))
		if rec.Code != http.StatusNoContent {
			t.Errorf("GET %s = %d, want 204", tc.target, rec.Code)
		}
	}
}

func TestEscapedMountCanonicalRedirect(t *testing.T) {
	srv := newTestServerWithBasePath("/vault")
	rec := serveBasePath(srv, http.MethodGet, "/%76ault/vaults//demo/a%2Fb?next=%2Fone")
	const want = "/vault/vaults/demo/a%2Fb?next=%2Fone"
	if got := rec.Header().Get("Location"); got != want {
		t.Errorf("status=%d Location=%q, want %q", rec.Code, got, want)
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
	if len(cookies) != 2 || cookies[0].Path != "/vault/" || cookies[1].Path != "/" {
		t.Errorf("logout Set-Cookie = %+v, want prefixed and root av_session clearing cookies", cookies)
	}
}

func TestUIBasePathBaseURL(t *testing.T) {
	// Control clients keep the configured origin; browser links use UIURL.
	srv := newTestServerWithBasePath("/vault")
	if got := srv.BaseURL(); got != "http://127.0.0.1:14321" {
		t.Errorf("BaseURL() = %q, want http://127.0.0.1:14321", got)
	}
	suffixed := newTestServerWithBasePath("/vault", withBaseURL("https://example.test/vault"))
	if got := suffixed.UIURL("/login"); got != "https://example.test/vault/login" {
		t.Errorf("already-suffixed UIURL() = %q", got)
	}
}

func TestUIBasePathBrowserLinks(t *testing.T) {
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServerWithBasePath("/vault", withStore(ms))

	req := httptest.NewRequest(http.MethodPost, "/vault/v1/users/invites", strings.NewReader(`{"email":"guest@example.test"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("invite status = %d: %s", rec.Code, rec.Body.String())
	}
	var invite map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &invite); err != nil {
		t.Fatal(err)
	}
	if got := invite["invite_link"]; got != "http://127.0.0.1:14321/vault/invite/av_uinv_testtoken_guest@example.test" {
		t.Errorf("invite_link = %v", got)
	}

	complete := httptest.NewRecorder()
	srv.redirectOAuthComplete(complete, httptest.NewRequest(http.MethodGet, "/vault/v1/oauth/callback", nil), "demo", "KEY", "success", "")
	if got := complete.Header().Get("Location"); got != "http://127.0.0.1:14321/vault/oauth/complete?status=success&vault=demo&key=KEY" {
		t.Errorf("OAuth completion = %q", got)
	}
	callback := serveBasePath(srv, http.MethodGet, "/vault/v1/oauth/callback?error=denied")
	if got := callback.Header().Get("Location"); callback.Code != http.StatusFound || got != "http://127.0.0.1:14321/vault/oauth/complete?status=error&message=denied" {
		t.Errorf("OAuth callback = %d %q", callback.Code, got)
	}
}

func TestUIBasePathProposalLink(t *testing.T) {
	_, ms, token := setupProposalTest(t)
	srv := newTestServerWithBasePath("/vault", withStore(ms))
	body := `{"services":[{"action":"set","name":"stripe","host":"api.stripe.com","auth":{"type":"bearer","token":"STRIPE_KEY"}}],"credentials":[{"action":"set","key":"STRIPE_KEY","description":"Stripe key"}],"message":"need stripe"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proposals", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("proposal status = %d: %s", rec.Code, rec.Body.String())
	}
	var proposal map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &proposal); err != nil {
		t.Fatal(err)
	}
	if got, ok := proposal["approval_url"].(string); !ok || !strings.HasPrefix(got, "http://127.0.0.1:14321/vault/approve/") {
		t.Errorf("approval_url = %v", proposal["approval_url"])
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

// CI's Go-only job embeds a stub index. This exercises actual immutable
// Vite output when the frontend has been built before the Go test command.
func TestBuiltAssetsAtRootAndNestedMount(t *testing.T) {
	requireAssets := os.Getenv("AGENT_VAULT_REQUIRE_BUILT_ASSETS") == "1"
	index, err := fs.ReadFile(webDistFS, "webdist/index.html")
	if errors.Is(err, fs.ErrNotExist) {
		if requireAssets {
			t.Fatal("frontend index is not built")
		}
		t.Skip("frontend assets are not built")
	}
	if err != nil {
		t.Fatal(err)
	}
	asset := regexp.MustCompile(`\./assets/[^" ]+\.js`).Find(index)
	if len(asset) == 0 {
		if requireAssets {
			t.Fatal("frontend index has no built JavaScript asset")
		}
		t.Skip("frontend assets are not built")
	}
	assetPath := strings.TrimPrefix(string(asset), ".")
	want, err := fs.ReadFile(webDistFS, "webdist"+assetPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ prefix, path, baseTag string }{
		{"", assetPath, `<base href="/" />`},
		{"/vault", "/vault" + assetPath, `<base href="/vault/" />`},
		{"/tools/vault", "/tools/vault" + assetPath, `<base href="/tools/vault/" />`},
	} {
		srv := newTestServerWithBasePath(tc.prefix)
		html := serveBasePath(srv, http.MethodGet, tc.prefix+"/")
		if html.Code != http.StatusOK || !bytes.Contains(html.Body.Bytes(), asset) || !strings.Contains(html.Body.String(), tc.baseTag) {
			t.Errorf("index at %q = %d, missing built asset or base tag %q", tc.prefix, html.Code, tc.baseTag)
		}
		got := serveBasePath(srv, http.MethodGet, tc.path)
		if got.Code != http.StatusOK || !bytes.Equal(got.Body.Bytes(), want) {
			t.Errorf("asset at %q = %d, content differs from embedded build", tc.path, got.Code)
		}
		if cache := got.Header().Get("Cache-Control"); cache != cacheImmutable {
			t.Errorf("asset at %q cache = %q, want %q", tc.path, cache, cacheImmutable)
		}
		icon := serveBasePath(srv, http.MethodGet, tc.prefix+"/favicon.svg")
		if icon.Code != http.StatusOK || icon.Header().Get("Cache-Control") != cacheDay {
			t.Errorf("favicon at %q = %d with cache %q", tc.prefix, icon.Code, icon.Header().Get("Cache-Control"))
		}
	}
}
