package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

// The upstream proxy API is admin-only surface that decides where an agent's
// traffic goes once credentials have been injected. These tests cover the
// authorisation boundary, input validation, secret handling, and the
// reference-count guard that keeps a deletion from silently re-routing live
// traffic.

func proxyRequest(t *testing.T, srv *Server, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, r)
	return rec
}

func proxyFixtureJSON(t *testing.T, fields map[string]any) string {
	t.Helper()
	body, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal proxy fixture: %v", err)
	}
	return string(body)
}

func decodeProxyView(t *testing.T, rec *httptest.ResponseRecorder) proxyView {
	t.Helper()
	var resp struct {
		Proxy proxyView `json:"proxy"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode proxy view: %v (body %s)", err, rec.Body.String())
	}
	return resp.Proxy
}

func TestUpstreamProxyEndpointsRequireOwner(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	memberToken := setupMemberSession(t, ms)
	srv := newTestServer(withStore(ms))

	if err := ms.CreateUpstreamProxy(t.Context(), &store.UpstreamProxy{
		Name: "corp", Scheme: "http", Host: "proxy.internal:3128", OnFailure: "fail_closed", Enabled: true,
	}); err != nil {
		t.Fatalf("seed proxy: %v", err)
	}

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"list", http.MethodGet, "/v1/admin/upstream-proxies", ""},
		{"create", http.MethodPost, "/v1/admin/upstream-proxies", `{"name":"x","scheme":"http","host":"h:1","on_failure":"fail_closed"}`},
		{"get", http.MethodGet, "/v1/admin/upstream-proxies/corp", ""},
		{"update", http.MethodPatch, "/v1/admin/upstream-proxies/corp", `{"host":"proxy.internal:3129"}`},
		{"delete", http.MethodDelete, "/v1/admin/upstream-proxies/corp", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := proxyRequest(t, srv, tc.method, tc.path, memberToken, tc.body)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s %s by a member = %d, want %d: %s", tc.method, tc.path, rec.Code, http.StatusForbidden, rec.Body.String())
			}
		})
	}

	// A member must not even learn that a profile exists.
	rec := proxyRequest(t, srv, http.MethodGet, "/v1/admin/upstream-proxies", memberToken, "")
	if strings.Contains(rec.Body.String(), "proxy.internal") {
		t.Fatalf("member response leaked proxy details: %s", rec.Body.String())
	}
}

func TestUpstreamProxyEndpointsRejectAnonymous(t *testing.T) {
	srv := newTestServer(withStore(newMockStore()))
	rec := proxyRequest(t, srv, http.MethodGet, "/v1/admin/upstream-proxies", "", "")
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("anonymous list = %d, want 401/403: %s", rec.Code, rec.Body.String())
	}
}

func TestUpstreamProxyCreateRejectsBadInput(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	cases := []struct {
		name string
		body string
	}{
		{"missing name", `{"scheme":"http","host":"proxy.internal:3128","on_failure":"fail_closed"}`},
		{"empty name", `{"name":"  ","scheme":"http","host":"proxy.internal:3128","on_failure":"fail_closed"}`},
		{"name too long", `{"name":"` + strings.Repeat("a", 65) + `","scheme":"http","host":"proxy.internal:3128","on_failure":"fail_closed"}`},
		{"unknown scheme", `{"name":"p","scheme":"ftp","host":"proxy.internal:21","on_failure":"fail_closed"}`},
		{"missing scheme", `{"name":"p","host":"proxy.internal:3128","on_failure":"fail_closed"}`},
		{"invalid name", `{"name":"bad/name","scheme":"http","host":"proxy.internal:3128","on_failure":"fail_closed"}`},
		{"host without port", `{"name":"p","scheme":"http","host":"proxy.internal","on_failure":"fail_closed"}`},
		{"empty host", `{"name":"p","scheme":"http","host":"","on_failure":"fail_closed"}`},
		{"non-numeric port", `{"name":"p","scheme":"http","host":"proxy.internal:http","on_failure":"fail_closed"}`},
		{"port zero", `{"name":"p","scheme":"http","host":"proxy.internal:0","on_failure":"fail_closed"}`},
		{"port too large", `{"name":"p","scheme":"http","host":"proxy.internal:65536","on_failure":"fail_closed"}`},
		{"host with userinfo", `{"name":"p","scheme":"http","host":"user:pass@proxy.internal:3128","on_failure":"fail_closed"}`},
		{"host with path", `{"name":"p","scheme":"http","host":"proxy.internal:3128/relay","on_failure":"fail_closed"}`},
		{"invalid CA PEM", `{"name":"p","scheme":"http","host":"proxy.internal:3128","proxy_ca_pem":"not a certificate","on_failure":"fail_closed"}`},
		{"unknown failure policy", `{"name":"p","scheme":"http","host":"proxy.internal:3128","on_failure":"retry"}`},
		{"invalid json", `{"name":`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("create(%s) = %d, want 400: %s", tc.body, rec.Code, rec.Body.String())
			}
		})
	}
	if len(ms.upstreamProxies) != 0 {
		t.Fatalf("expected no profiles persisted after %d rejected creates", len(ms.upstreamProxies))
	}
}

func TestUpstreamProxyAcceptsEverySupportedScheme(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	for _, scheme := range []string{"http", "https", "socks5", "socks5h"} {
		body := `{"name":"` + scheme + `-proxy","scheme":"` + scheme + `","host":"proxy.internal:3128","on_failure":"fail_closed"}`
		rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken, body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create scheme %s = %d, want 201: %s", scheme, rec.Code, rec.Body.String())
		}
	}
	rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken,
		`{"name":"normalized","scheme":" HTTPS ","host":"proxy.internal:443","on_failure":"fail_closed"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create with normalized scheme = %d: %s", rec.Code, rec.Body.String())
	}
	if got := ms.upstreamProxies["normalized"].Scheme; got != "https" {
		t.Fatalf("stored scheme = %q, want normalized https", got)
	}
	rec = proxyRequest(t, srv, http.MethodGet, "/v1/admin/upstream-proxies", ownerToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", rec.Code, rec.Body.String())
	}
	var listed struct {
		Proxies []proxyView `json:"proxies"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&listed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(listed.Proxies) != 5 {
		t.Fatalf("listed %d proxies, want 5", len(listed.Proxies))
	}
}

func TestUpstreamProxyCredentialsAreWriteOnlyAndPatchedIndependently(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	// Deterministic per-test fixtures, not credentials for an external service.
	username := t.Name() + "/username"
	password := t.Name() + "/password"
	updatedUsername := username + "/updated"
	updatedPassword := password + "/updated"
	ignoredUsername := username + "/ignored"
	ignoredPassword := password + "/ignored"

	assertWriteOnly := func(rec *httptest.ResponseRecorder) {
		t.Helper()
		var body map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		var profile map[string]json.RawMessage
		if proxy, ok := body["proxy"]; ok {
			if err := json.Unmarshal(proxy, &profile); err != nil {
				t.Fatalf("decode proxy response: %v", err)
			}
		} else if proxies, ok := body["proxies"]; ok {
			var list []map[string]json.RawMessage
			if err := json.Unmarshal(proxies, &list); err != nil {
				t.Fatalf("decode proxy list: %v", err)
			}
			for _, item := range list {
				if _, ok := item["username"]; ok {
					t.Fatal("proxy list contains username")
				}
				if _, ok := item["password"]; ok {
					t.Fatal("proxy list contains password")
				}
			}
		}
		for _, key := range []string{"username", "password"} {
			if _, ok := profile[key]; ok {
				t.Fatalf("response contains %s", key)
			}
		}
		for _, secret := range []string{
			username, password, updatedUsername, updatedPassword, ignoredUsername, ignoredPassword,
			base64.StdEncoding.EncodeToString(ms.upstreamProxies["corp"].UsernameCT),
			base64.StdEncoding.EncodeToString(ms.upstreamProxies["corp"].PasswordCT),
		} {
			if secret != "" && strings.Contains(rec.Body.String(), secret) {
				t.Fatal("response leaked credential or ciphertext")
			}
		}
	}

	rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken,
		proxyFixtureJSON(t, map[string]any{
			"name": "corp", "scheme": "http", "host": "proxy.internal:3128",
			"username": username, "password": password, "on_failure": "fail_closed", "is_default": true,
		}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	assertWriteOnly(rec)
	if !decodeProxyView(t, rec).HasAuth {
		t.Fatal("has_auth = false after creating credentials")
	}

	rec = proxyRequest(t, srv, http.MethodGet, "/v1/admin/upstream-proxies/corp", ownerToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get = %d: %s", rec.Code, rec.Body.String())
	}
	assertWriteOnly(rec)
	rec = proxyRequest(t, srv, http.MethodGet, "/v1/admin/upstream-proxies", ownerToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", rec.Code, rec.Body.String())
	}
	assertWriteOnly(rec)

	rec = proxyRequest(t, srv, http.MethodPatch, "/v1/admin/upstream-proxies/corp", ownerToken,
		proxyFixtureJSON(t, map[string]any{"username": updatedUsername}))
	if rec.Code != http.StatusOK {
		t.Fatalf("username update = %d: %s", rec.Code, rec.Body.String())
	}
	assertWriteOnly(rec)
	got, err := srv.UpstreamProxyResolver().ResolveUpstreamProxy(context.Background(), "", "")
	if err != nil {
		t.Fatalf("resolve after username update: %v", err)
	}
	if got == nil || got.Username != updatedUsername || got.Password != password {
		t.Fatal("username-only patch must update username and preserve password")
	}

	rec = proxyRequest(t, srv, http.MethodPatch, "/v1/admin/upstream-proxies/corp", ownerToken,
		proxyFixtureJSON(t, map[string]any{"password": updatedPassword}))
	if rec.Code != http.StatusOK {
		t.Fatalf("password update = %d: %s", rec.Code, rec.Body.String())
	}
	assertWriteOnly(rec)
	got, err = srv.UpstreamProxyResolver().ResolveUpstreamProxy(context.Background(), "", "")
	if err != nil {
		t.Fatalf("resolve after password update: %v", err)
	}
	if got == nil || got.Username != updatedUsername || got.Password != updatedPassword {
		t.Fatal("password-only patch must update password and preserve username")
	}
	rec = proxyRequest(t, srv, http.MethodPatch, "/v1/admin/upstream-proxies/corp", ownerToken, `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("empty patch = %d: %s", rec.Code, rec.Body.String())
	}
	got, err = srv.UpstreamProxyResolver().ResolveUpstreamProxy(context.Background(), "", "")
	if err != nil || got == nil || got.Username != updatedUsername || got.Password != updatedPassword {
		t.Fatalf("empty patch must preserve both credentials: %v", err)
	}

	rec = proxyRequest(t, srv, http.MethodPatch, "/v1/admin/upstream-proxies/corp", ownerToken, `{"username":""}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("empty username update = %d: %s", rec.Code, rec.Body.String())
	}
	got, err = srv.UpstreamProxyResolver().ResolveUpstreamProxy(context.Background(), "", "")
	if err != nil || got == nil || got.Username != "" || got.Password != updatedPassword {
		t.Fatalf("clearing username must preserve password: %v", err)
	}
	rec = proxyRequest(t, srv, http.MethodPatch, "/v1/admin/upstream-proxies/corp", ownerToken, `{"password":""}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("empty password update = %d: %s", rec.Code, rec.Body.String())
	}
	got, err = srv.UpstreamProxyResolver().ResolveUpstreamProxy(context.Background(), "", "")
	if err != nil || got == nil || got.Username != "" || got.Password != "" {
		t.Fatalf("clearing password must leave both credentials empty: %v", err)
	}

	rec = proxyRequest(t, srv, http.MethodPatch, "/v1/admin/upstream-proxies/corp", ownerToken,
		proxyFixtureJSON(t, map[string]any{
			"username": ignoredUsername, "password": ignoredPassword, "clear_auth": true,
		}))
	if rec.Code != http.StatusOK {
		t.Fatalf("clear_auth update = %d: %s", rec.Code, rec.Body.String())
	}
	assertWriteOnly(rec)
	got, err = srv.UpstreamProxyResolver().ResolveUpstreamProxy(context.Background(), "", "")
	if err != nil {
		t.Fatalf("resolve after clear_auth: %v", err)
	}
	if got == nil || got.Username != "" || got.Password != "" || decodeProxyView(t, rec).HasAuth {
		t.Fatal("clear_auth must clear both credentials and has_auth")
	}
}

func TestUpstreamProxyEmptyCredentialPatchClearsRuntimeAuth(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))
	username := t.Name() + "/username"
	password := t.Name() + "/password"

	rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken,
		proxyFixtureJSON(t, map[string]any{
			"name": "corp", "scheme": "http", "host": "proxy.internal:3128",
			"username": username, "password": password, "is_default": true,
		}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}

	rec = proxyRequest(t, srv, http.MethodPatch, "/v1/admin/upstream-proxies/corp", ownerToken, `{"username":""}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear username = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), username) || strings.Contains(rec.Body.String(), password) {
		t.Fatal("patch response leaked credentials")
	}
	if len(ms.upstreamProxies["corp"].UsernameCT) != 0 || len(ms.upstreamProxies["corp"].PasswordCT) == 0 {
		t.Fatal("clearing username must remove its ciphertext and preserve password")
	}
	runtimeProfile, err := srv.UpstreamProxyResolver().ResolveUpstreamProxy(context.Background(), "", "")
	if err != nil || runtimeProfile == nil || runtimeProfile.Username != "" || runtimeProfile.Password != password {
		t.Fatalf("runtime credentials after clearing username differ from empty/preserved password: %v", err)
	}

	rec = proxyRequest(t, srv, http.MethodPatch, "/v1/admin/upstream-proxies/corp", ownerToken, `{"password":""}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear password = %d: %s", rec.Code, rec.Body.String())
	}
	if decodeProxyView(t, rec).HasAuth {
		t.Fatalf("PATCH has_auth = true after clearing both credentials: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), username) || strings.Contains(rec.Body.String(), password) {
		t.Fatal("patch response leaked credentials")
	}
	if len(ms.upstreamProxies["corp"].UsernameCT) != 0 || len(ms.upstreamProxies["corp"].PasswordCT) != 0 {
		t.Fatal("clearing both credentials must remove both ciphertexts")
	}
	runtimeProfile, err = srv.UpstreamProxyResolver().ResolveUpstreamProxy(context.Background(), "", "")
	if err != nil || runtimeProfile == nil || runtimeProfile.Username != "" || runtimeProfile.Password != "" {
		t.Fatalf("runtime credentials after clearing both are not empty: %v", err)
	}

	rec = proxyRequest(t, srv, http.MethodGet, "/v1/admin/upstream-proxies/corp", ownerToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", rec.Code, rec.Body.String())
	}
	if decodeProxyView(t, rec).HasAuth {
		t.Fatalf("GET has_auth = true after clearing both credentials: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), username) || strings.Contains(rec.Body.String(), password) {
		t.Fatal("GET response leaked credentials")
	}
}

func TestUpstreamProxyLegacyEncryptedEmptyAuthIsNotReportedAsSet(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))
	rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken,
		`{"name":"corp","scheme":"http","host":"proxy.internal:3128"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	emptyCT, nonce, err := crypto.Encrypt(nil, srv.encKey)
	if err != nil {
		t.Fatal(err)
	}
	ms.upstreamProxies["corp"].UsernameCT, ms.upstreamProxies["corp"].UsernameNonce = emptyCT, nonce
	ms.upstreamProxies["corp"].PasswordCT, ms.upstreamProxies["corp"].PasswordNonce = emptyCT, nonce
	rec = proxyRequest(t, srv, http.MethodGet, "/v1/admin/upstream-proxies/corp", ownerToken, "")
	if rec.Code != http.StatusOK || decodeProxyView(t, rec).HasAuth {
		t.Fatalf("legacy empty credentials reported as set: status %d", rec.Code)
	}
}

func TestUpstreamProxyUpdateRejectsBadInput(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken,
		`{"name":"corp","scheme":"http","host":"proxy.internal:3128","on_failure":"fail_closed"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	rec = proxyRequest(t, srv, http.MethodPatch, "/v1/admin/upstream-proxies/corp", ownerToken, `{"scheme":" HTTPS "}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("scheme normalization patch = %d: %s", rec.Code, rec.Body.String())
	}
	if got := ms.upstreamProxies["corp"].Scheme; got != "https" {
		t.Fatalf("stored scheme after patch = %q, want normalized https", got)
	}

	for _, tc := range []struct{ name, body string }{
		{"bad scheme", `{"scheme":"gopher"}`},
		{"bad host", `{"host":"proxy.internal"}`},
		{"port outside range", `{"host":"proxy.internal:65536"}`},
		{"port zero", `{"host":"proxy.internal:0"}`},
		{"bad CA PEM", `{"proxy_ca_pem":"not a certificate"}`},
		{"bad failure policy", `{"on_failure":"sometimes"}`},
		{"invalid json", `{`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := proxyRequest(t, srv, http.MethodPatch, "/v1/admin/upstream-proxies/corp", ownerToken, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("patch(%s) = %d, want 400: %s", tc.body, rec.Code, rec.Body.String())
			}
		})
	}

	rec = proxyRequest(t, srv, http.MethodPatch, "/v1/admin/upstream-proxies/absent", ownerToken, `{"host":"h:1"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("patch missing = %d, want 404: %s", rec.Code, rec.Body.String())
	}
}

func TestUpstreamProxyDefaultIsExclusive(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	for _, body := range []string{
		`{"name":"first","scheme":"http","host":"a.internal:3128","on_failure":"fail_closed","is_default":true}`,
		`{"name":"second","scheme":"http","host":"b.internal:3128","on_failure":"fail_closed","is_default":true}`,
	} {
		if rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken, body); rec.Code != http.StatusCreated {
			t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
		}
	}

	var defaults int
	for _, p := range ms.upstreamProxies {
		if p.IsDefault {
			defaults++
		}
	}
	if defaults != 1 {
		t.Fatalf("%d profiles flagged default, want exactly 1 (is_default is exclusive)", defaults)
	}

	// Promoting an existing profile must demote the previous holder.
	if rec := proxyRequest(t, srv, http.MethodPatch, "/v1/admin/upstream-proxies/first", ownerToken, `{"is_default":true}`); rec.Code != http.StatusOK {
		t.Fatalf("promote = %d: %s", rec.Code, rec.Body.String())
	}
	defaults = 0
	for _, p := range ms.upstreamProxies {
		if p.IsDefault {
			defaults++
		}
	}
	if defaults != 1 {
		t.Fatalf("%d profiles flagged default after promotion, want 1", defaults)
	}
}

func TestUpstreamProxyDuplicateNameIsConflict(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	body := `{"name":"corp","scheme":"http","host":"a.internal:3128","on_failure":"fail_closed"}`
	if rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken, body); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken, body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate create = %d, want 409: %s", rec.Code, rec.Body.String())
	}
}

func TestUpstreamProxyDeleteRefusedWhileReferenced(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	if rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken,
		`{"name":"corp","scheme":"http","host":"a.internal:3128","on_failure":"fail_closed"}`); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	ms.upstreamProxyRefs["corp"] = []string{"default/anthropic", "team/openai"}

	rec := proxyRequest(t, srv, http.MethodDelete, "/v1/admin/upstream-proxies/corp", ownerToken, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("delete referenced = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "anthropic") {
		t.Fatalf("409 must name the referencing services: %s", rec.Body.String())
	}
	if _, ok := ms.upstreamProxies["corp"]; !ok {
		t.Fatal("referenced profile must survive the refused delete")
	}

	delete(ms.upstreamProxyRefs, "corp")
	rec = proxyRequest(t, srv, http.MethodDelete, "/v1/admin/upstream-proxies/corp", ownerToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete = %d: %s", rec.Code, rec.Body.String())
	}
	if _, ok := ms.upstreamProxies["corp"]; ok {
		t.Fatal("profile remained after delete")
	}
}

// TestServiceUpstreamProxyReferenceRoundTrip covers the *consumer* side of the
// profile API: a service references a profile by name through the normal
// vault write path, and a reference to a profile that does not exist is
// rejected before it can be persisted. A half-written reference would leave a
// service whose traffic silently falls back to a direct dial.
func TestServiceUpstreamProxyReferenceRoundTrip(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	if rec := proxyRequest(t, srv, http.MethodPost, "/v1/admin/upstream-proxies", ownerToken,
		`{"name":"corp","scheme":"http","host":"a.internal:3128","on_failure":"fail_closed"}`); rec.Code != http.StatusCreated {
		t.Fatalf("create proxy = %d: %s", rec.Code, rec.Body.String())
	}
	if err := ms.CreateUpstreamProxy(t.Context(), &store.UpstreamProxy{
		Name: "default-corp", Scheme: "http", Host: "default.internal:3128",
		OnFailure: "fail_closed", Enabled: true, IsDefault: true,
	}); err != nil {
		t.Fatalf("seed default proxy: %v", err)
	}

	put := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/v1/vaults/default/services", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+ownerToken)
		r.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, r)
		return rec
	}

	// A new service without an egress selection must not inherit the default.
	directWithoutFlag := `{"name":"public","host":"public.example.com","auth":{"type":"passthrough"}}`
	if rec := put(fmt.Sprintf(`{"services":[%s]}`, directWithoutFlag)); rec.Code != http.StatusOK {
		t.Fatalf("PUT new direct service = %d: %s", rec.Code, rec.Body.String())
	}
	direct, err := srv.UpstreamProxyResolver().ResolveUpstreamProxy(t.Context(), "root-ns-id", "public")
	if err != nil || direct != nil {
		t.Fatalf("new service without opt-in resolved %#v, err %v; want direct", direct, err)
	}

	const service = `{"name":"anthropic","host":"api.anthropic.com","auth":{"type":"bearer","token":"ANTHROPIC_KEY"},"upstream_proxy":"%s"}`
	if rec := put(fmt.Sprintf(`{"services":[%s]}`, fmt.Sprintf(service, "corp"))); rec.Code != http.StatusOK {
		t.Fatalf("PUT with valid reference = %d: %s", rec.Code, rec.Body.String())
	}

	// The reference must survive the read/write cycle, otherwise the UI would
	// present a selector that forgets the operator's choice on the next save.
	getRec := proxyRequest(t, srv, http.MethodGet, "/v1/vaults/default/services", ownerToken, "")
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET services = %d: %s", getRec.Code, getRec.Body.String())
	}
	var got struct {
		Services []struct {
			Name                string `json:"name"`
			UpstreamProxy       string `json:"upstream_proxy"`
			BypassUpstreamProxy bool   `json:"bypass_upstream_proxy"`
			UseUpstreamProxy    bool   `json:"use_upstream_proxy"`
		} `json:"services"`
	}
	if err := json.NewDecoder(getRec.Body).Decode(&got); err != nil {
		t.Fatalf("decode services: %v", err)
	}
	if len(got.Services) != 1 || got.Services[0].UpstreamProxy != "corp" || got.Services[0].BypassUpstreamProxy {
		t.Fatalf("upstream_proxy not persisted correctly: %+v", got.Services)
	}

	// Explicitly opt into the instance default, then verify that switching
	// to direct invalidates the cached route without waiting for its TTL.
	inheritedService := `{"name":"anthropic","host":"api.anthropic.com","auth":{"type":"bearer","token":"ANTHROPIC_KEY"},"use_upstream_proxy":true}`
	if rec := put(fmt.Sprintf(`{"services":[%s]}`, inheritedService)); rec.Code != http.StatusOK {
		t.Fatalf("PUT with default opt-in = %d: %s", rec.Code, rec.Body.String())
	}
	resolver := srv.UpstreamProxyResolver()
	routed, err := resolver.ResolveUpstreamProxy(t.Context(), "root-ns-id", "anthropic")
	if err != nil || routed == nil || routed.Name != "default-corp" {
		t.Fatalf("resolve opted-in service before change = %#v, err %v", routed, err)
	}

	directService := `{"name":"anthropic","host":"api.anthropic.com","auth":{"type":"bearer","token":"ANTHROPIC_KEY"},"bypass_upstream_proxy":true}`
	if rec := put(fmt.Sprintf(`{"services":[%s]}`, directService)); rec.Code != http.StatusOK {
		t.Fatalf("PUT with service direct bypass = %d: %s", rec.Code, rec.Body.String())
	}
	routed, err = resolver.ResolveUpstreamProxy(t.Context(), "root-ns-id", "anthropic")
	if err != nil || routed != nil {
		t.Fatalf("resolve service after direct change = %#v, err %v; want nil", routed, err)
	}
	getRec = proxyRequest(t, srv, http.MethodGet, "/v1/vaults/default/services", ownerToken, "")
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET services after direct bypass = %d: %s", getRec.Code, getRec.Body.String())
	}
	got.Services = nil
	if err := json.NewDecoder(getRec.Body).Decode(&got); err != nil {
		t.Fatalf("decode services after direct bypass: %v", err)
	}
	if len(got.Services) != 1 || !got.Services[0].BypassUpstreamProxy || got.Services[0].UpstreamProxy != "" {
		t.Fatalf("bypass_upstream_proxy not persisted: %+v", got.Services)
	}
	if rec := put(fmt.Sprintf(`{"services":[%s]}`, inheritedService)); rec.Code != http.StatusOK {
		t.Fatalf("PUT removing direct bypass = %d: %s", rec.Code, rec.Body.String())
	}
	routed, err = resolver.ResolveUpstreamProxy(t.Context(), "root-ns-id", "anthropic")
	if err != nil || routed == nil || routed.Name != "default-corp" {
		t.Fatalf("resolve after removing direct bypass = %#v, err %v; want instance default", routed, err)
	}
	getRec = proxyRequest(t, srv, http.MethodGet, "/v1/vaults/default/services", ownerToken, "")
	got.Services = nil
	if err := json.NewDecoder(getRec.Body).Decode(&got); err != nil || len(got.Services) != 1 || !got.Services[0].UseUpstreamProxy {
		t.Fatalf("default opt-in not persisted: %+v, err %v", got.Services, err)
	}

	conflict := `{"name":"anthropic","host":"api.anthropic.com","auth":{"type":"bearer","token":"ANTHROPIC_KEY"},"bypass_upstream_proxy":true,"upstream_proxy":"corp"}`
	if rec := put(fmt.Sprintf(`{"services":[%s]}`, conflict)); rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT with conflicting egress controls = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if rec := put(fmt.Sprintf(`{"services":[%s]}`, `{"name":"anthropic","host":"api.anthropic.com","auth":{"type":"bearer","token":"ANTHROPIC_KEY"},"use_upstream_proxy":true,"upstream_proxy":"corp"}`)); rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT with default and named profile = %d, want 400: %s", rec.Code, rec.Body.String())
	}

	rec := put(fmt.Sprintf(`{"services":[%s]}`, fmt.Sprintf(service, "no-such-proxy")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT with unknown reference = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "no-such-proxy") {
		t.Fatalf("400 must name the unknown profile: %s", rec.Body.String())
	}
}

func TestNewServiceDirectDoesNotRerouteExistingImplicitDefault(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	seedProxy(t, ms, "default-corp", "http", "default.internal:3128", true, true)
	legacy := `[{"name":"legacy","host":"legacy.example.com","auth":{"type":"passthrough"}}]`
	if _, err := ms.SetBrokerConfig(t.Context(), "root-ns-id", legacy); err != nil {
		t.Fatal(err)
	}
	srv := newTestServer(withStore(ms))
	body := `{"services":[{"name":"legacy","host":"legacy.example.com","auth":{"type":"passthrough"}},{"name":"fresh","host":"fresh.example.com","auth":{"type":"passthrough"}}]}`
	rec := proxyRequest(t, srv, http.MethodPut, "/v1/vaults/default/services", ownerToken, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT mixed legacy and new services = %d: %s", rec.Code, rec.Body.String())
	}
	resolver := srv.UpstreamProxyResolver()
	legacyRoute, err := resolver.ResolveUpstreamProxy(t.Context(), "root-ns-id", "legacy")
	if err != nil || legacyRoute == nil || legacyRoute.Name != "default-corp" {
		t.Fatalf("legacy route = %#v, err %v; want inherited default", legacyRoute, err)
	}
	freshRoute, err := resolver.ResolveUpstreamProxy(t.Context(), "root-ns-id", "fresh")
	if err != nil || freshRoute != nil {
		t.Fatalf("new route = %#v, err %v; want direct", freshRoute, err)
	}
	rec = proxyRequest(t, srv, http.MethodPost, "/v1/vaults/default/services", ownerToken,
		`{"services":[{"name":"post-added","host":"post.example.com","auth":{"type":"passthrough"}}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST new service = %d: %s", rec.Code, rec.Body.String())
	}
	postRoute, err := resolver.ResolveUpstreamProxy(t.Context(), "root-ns-id", "post-added")
	if err != nil || postRoute != nil {
		t.Fatalf("POST new route = %#v, err %v; want direct", postRoute, err)
	}
	legacyRoute, err = resolver.ResolveUpstreamProxy(t.Context(), "root-ns-id", "legacy")
	if err != nil || legacyRoute == nil || legacyRoute.Name != "default-corp" {
		t.Fatalf("legacy route after POST = %#v, err %v; want inherited default", legacyRoute, err)
	}
}

func TestUpstreamProxyGetMissingIsNotFound(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	rec := proxyRequest(t, srv, http.MethodGet, "/v1/admin/upstream-proxies/absent", ownerToken, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing = %d, want 404: %s", rec.Code, rec.Body.String())
	}
}
