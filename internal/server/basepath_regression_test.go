package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

func TestMigrationLogoutClearsOnlyCurrentBrowserSessions(t *testing.T) {
	ms := newMockStore()
	root := New(
		"127.0.0.1:0",
		ms,
		make([]byte, 32),
		nil,
		false,
		"https://vault.example.com",
		"",
		slog.New(slog.DiscardHandler),
	)

	request := func(jar http.CookieJar, srv *Server, method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		u, err := url.Parse("https://vault.example.com" + path)
		if err != nil {
			t.Fatalf("parse request URL: %v", err)
		}
		req := httptest.NewRequest(method, u.String(), strings.NewReader(body))
		for _, cookie := range jar.Cookies(u) {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		jar.SetCookies(u, rec.Result().Cookies())
		return rec
	}

	firstBrowser, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create first cookie jar: %v", err)
	}
	secondBrowser, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create second cookie jar: %v", err)
	}
	credentials := `{"email":"owner@example.test","password":"owner-password-843"}`
	if rec := request(firstBrowser, root, http.MethodPost, "/v1/auth/register", credentials); rec.Code != http.StatusCreated {
		t.Fatalf("register: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec := request(secondBrowser, root, http.MethodPost, "/v1/auth/login", credentials); rec.Code != http.StatusOK {
		t.Fatalf("second browser login: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	mounted := New(
		"127.0.0.1:0",
		ms,
		make([]byte, 32),
		nil,
		true,
		"https://vault.example.com",
		"/vault",
		slog.New(slog.DiscardHandler),
	)
	if rec := request(firstBrowser, mounted, http.MethodPost, "/vault/v1/auth/login", credentials); rec.Code != http.StatusOK {
		t.Fatalf("prefixed login: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	prefixedURL, err := url.Parse("https://vault.example.com/vault/v1/auth/me")
	if err != nil {
		t.Fatalf("parse prefixed URL: %v", err)
	}
	firstBrowserCookies := firstBrowser.Cookies(prefixedURL)
	if got := len(firstBrowserCookies); got != 2 {
		t.Errorf("first browser cookies after mount migration = %d, want 2", got)
	}

	if rec := request(firstBrowser, mounted, http.MethodPost, "/vault/v1/auth/logout", ""); rec.Code != http.StatusOK {
		t.Fatalf("logout: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := len(firstBrowser.Cookies(prefixedURL)); got != 0 {
		t.Errorf("first browser cookies after logout = %d, want 0", got)
	}
	for _, cookie := range firstBrowserCookies {
		if _, ok := ms.sessions[cookie.Value]; ok {
			t.Error("a first-browser session survives logout")
		}
	}
	if rec := request(firstBrowser, mounted, http.MethodGet, "/vault/v1/auth/me", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("first browser reauthenticated after logout: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec := request(secondBrowser, mounted, http.MethodGet, "/vault/v1/auth/me", ""); rec.Code != http.StatusOK {
		t.Fatalf("second browser session was revoked: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestMigrationSelfRevokeClearsOnlyCurrentBrowserSessions(t *testing.T) {
	ms := newMockStore()
	root := New(
		"127.0.0.1:0",
		ms,
		make([]byte, 32),
		nil,
		false,
		"https://vault.example.com",
		"",
		slog.New(slog.DiscardHandler),
	)

	request := func(jar http.CookieJar, srv *Server, method, requestPath, body string) *httptest.ResponseRecorder {
		t.Helper()
		u, err := url.Parse("https://vault.example.com" + requestPath)
		if err != nil {
			t.Fatalf("parse request URL: %v", err)
		}
		req := httptest.NewRequest(method, u.String(), strings.NewReader(body))
		for _, cookie := range jar.Cookies(u) {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		jar.SetCookies(u, rec.Result().Cookies())
		return rec
	}

	firstBrowser, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create first cookie jar: %v", err)
	}
	secondBrowser, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create second cookie jar: %v", err)
	}
	credentials := `{"email":"owner@example.test","password":"owner-password-843"}`
	register := request(firstBrowser, root, http.MethodPost, "/v1/auth/register", credentials)
	if register.Code != http.StatusCreated {
		t.Fatalf("register: status = %d, body = %s", register.Code, register.Body.String())
	}
	var rootLogin loginResponse
	if err := json.NewDecoder(register.Body).Decode(&rootLogin); err != nil {
		t.Fatalf("decode root registration: %v", err)
	}
	secondLogin := request(secondBrowser, root, http.MethodPost, "/v1/auth/login", credentials)
	if secondLogin.Code != http.StatusOK {
		t.Fatalf("second browser login: status = %d, body = %s", secondLogin.Code, secondLogin.Body.String())
	}
	var secondBrowserLogin loginResponse
	if err := json.NewDecoder(secondLogin.Body).Decode(&secondBrowserLogin); err != nil {
		t.Fatalf("decode second browser login: %v", err)
	}

	mounted := New(
		"127.0.0.1:0",
		ms,
		make([]byte, 32),
		nil,
		true,
		"https://vault.example.com",
		"/vault",
		slog.New(slog.DiscardHandler),
	)
	prefixedLogin := request(firstBrowser, mounted, http.MethodPost, "/vault/v1/auth/login", credentials)
	if prefixedLogin.Code != http.StatusOK {
		t.Fatalf("prefixed login: status = %d, body = %s", prefixedLogin.Code, prefixedLogin.Body.String())
	}
	var mountedSession loginResponse
	if err := json.NewDecoder(prefixedLogin.Body).Decode(&mountedSession); err != nil {
		t.Fatalf("decode prefixed login: %v", err)
	}
	prefixedURL, err := url.Parse("https://vault.example.com/vault/v1/auth/me")
	if err != nil {
		t.Fatalf("parse prefixed URL: %v", err)
	}
	if got := len(firstBrowser.Cookies(prefixedURL)); got != 2 {
		t.Errorf("first browser cookies after mount migration = %d, want 2", got)
	}
	current := ms.sessions[mountedSession.Token]
	if current == nil {
		t.Fatal("prefixed session was not stored")
	}

	revokePath := "/vault/v1/auth/sessions/" + current.PublicID
	if rec := request(firstBrowser, mounted, http.MethodDelete, revokePath, ""); rec.Code != http.StatusOK {
		t.Fatalf("self-revoke: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := len(firstBrowser.Cookies(prefixedURL)); got != 0 {
		t.Errorf("first browser cookies after self-revoke = %d, want 0", got)
	}
	for _, token := range []string{rootLogin.Token, mountedSession.Token} {
		if _, ok := ms.sessions[token]; ok {
			t.Errorf("first-browser session %q survives self-revoke", token)
		}
	}
	if _, ok := ms.sessions[secondBrowserLogin.Token]; !ok {
		t.Fatal("second browser session was revoked")
	}
	if rec := request(firstBrowser, mounted, http.MethodGet, "/vault/v1/auth/me", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("first browser reauthenticated after self-revoke: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec := request(secondBrowser, mounted, http.MethodGet, "/vault/v1/auth/me", ""); rec.Code != http.StatusOK {
		t.Fatalf("second browser session stopped authenticating: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestMountedRedirectsStayPrefixed(t *testing.T) {
	srv := New("127.0.0.1:0", newMockStore(), make([]byte, 32), nil, true, "https://vault.example.com", "/vault", slog.New(slog.DiscardHandler))
	for _, c := range []struct{ path, want string }{
		{"/vault/manage", "/vault/manage/"},
		{"/vault/account", "/vault/account/"},
		{"/vault?token=example", "/vault/?token=example"},
	} {
		t.Run(c.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, c.path, nil))
			if rec.Header().Get("Location") != c.want {
				t.Errorf("status=%d Location=%q; want %q", rec.Code, rec.Header().Get("Location"), c.want)
			}
		})
	}
}

func TestSlashOnlyPrefixDoesNotPanic(t *testing.T) {
	defer func() {
		if value := recover(); value != nil {
			t.Errorf("prefix caused panic: %v", value)
		}
	}()
	if value, err := NormalizeBasePath("//"); err == nil {
		t.Errorf("accepted invalid prefix as %q", value)
	}
}

func TestMigrationLogoutRespectsSessionOwner(t *testing.T) {
	ms := newMockStore()
	expires := time.Now().Add(time.Hour)
	ms.sessions["first"] = &store.Session{ID: "first", UserID: "user-a", ExpiresAt: &expires}
	ms.sessions["second"] = &store.Session{ID: "second", UserID: "user-a", ExpiresAt: &expires}
	ms.sessions["other-user"] = &store.Session{ID: "other-user", UserID: "user-b", ExpiresAt: &expires}
	srv := newTestServerWithBasePath("/vault", withStore(ms))
	req := httptest.NewRequest(http.MethodPost, "/vault/v1/auth/logout", nil)
	for _, token := range []string{"first", "other-user", "second"} {
		req.AddCookie(&http.Cookie{Name: "av_session", Value: token})
	}
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout = %d: %s", rec.Code, rec.Body.String())
	}
	for _, token := range []string{"first", "second"} {
		if _, ok := ms.sessions[token]; ok {
			t.Errorf("session %q survives logout", token)
		}
	}
	if _, ok := ms.sessions["other-user"]; !ok {
		t.Fatal("another user's session was revoked")
	}
}

func TestBearerLogoutKeepsBrowserSession(t *testing.T) {
	ms := newMockStore()
	expires := time.Now().Add(time.Hour)
	ms.sessions["bearer"] = &store.Session{ID: "bearer", UserID: "user-a", ExpiresAt: &expires}
	ms.sessions["browser"] = &store.Session{ID: "browser", UserID: "user-b", ExpiresAt: &expires}
	srv := newTestServerWithBasePath("/vault", withStore(ms))
	req := httptest.NewRequest(http.MethodPost, "/vault/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer bearer")
	req.AddCookie(&http.Cookie{Name: "av_session", Value: "browser"})
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout = %d: %s", rec.Code, rec.Body.String())
	}
	if _, ok := ms.sessions["bearer"]; ok {
		t.Fatal("Bearer session survives logout")
	}
	if _, ok := ms.sessions["browser"]; !ok {
		t.Fatal("browser session was revoked by Bearer logout")
	}
}
