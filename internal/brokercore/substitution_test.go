package brokercore

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestApplySubstitutionsPath(t *testing.T) {
	u := mustParseURL(t, "https://api.twilio.com/2010-04-01/Accounts/__account_sid__/Messages.json")
	subs := []ResolvedSubstitution{{
		Placeholder: "__account_sid__",
		Value:       "AC12345",
		In:          []string{"path"},
	}}
	if err := ApplySubstitutions(u, nil, subs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := u.String()
	want := "https://api.twilio.com/2010-04-01/Accounts/AC12345/Messages.json"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestApplySubstitutionsPathEncodesValue(t *testing.T) {
	// A value with "/" must be escaped so it stays inside the path segment
	// and cannot escape into a different path segment.
	u := mustParseURL(t, "https://api.example.com/items/__id__/get")
	subs := []ResolvedSubstitution{{
		Placeholder: "__id__",
		Value:       "abc/def",
		In:          []string{"path"},
	}}
	if err := ApplySubstitutions(u, nil, subs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(u.String(), "abc%2Fdef") {
		t.Fatalf("expected '/' encoded as %%2F, got %s", u.String())
	}
}

func TestApplySubstitutionsQuery(t *testing.T) {
	u := mustParseURL(t, "https://api.example.com/data?api_key=__api_key__&format=json")
	subs := []ResolvedSubstitution{{
		Placeholder: "__api_key__",
		Value:       "secret&value=oops",
		In:          []string{"query"},
	}}
	if err := ApplySubstitutions(u, nil, subs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	q := u.Query()
	if q.Get("api_key") != "secret&value=oops" {
		t.Fatalf("expected query parser to round-trip the encoded value, got %q", q.Get("api_key"))
	}
	if q.Get("format") != "json" {
		t.Fatalf("expected non-substituted segment preserved, got %q", q.Get("format"))
	}
}

func TestApplySubstitutionsHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Tenant", "tenant=__tenant_id__")
	subs := []ResolvedSubstitution{{
		Placeholder: "__tenant_id__",
		Value:       "acme",
		In:          []string{"header"},
	}}
	if err := ApplySubstitutions(nil, headers, subs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := headers.Get("X-Tenant"); got != "tenant=acme" {
		t.Fatalf("expected 'tenant=acme', got %q", got)
	}
}

func TestApplySubstitutionsHeaderRejectsCRLF(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Tenant", "__tenant_id__")
	subs := []ResolvedSubstitution{{
		Placeholder: "__tenant_id__",
		Value:       "acme\r\nX-Injected: yes",
		In:          []string{"header"},
	}}
	err := ApplySubstitutions(nil, headers, subs)
	if err == nil || !strings.Contains(err.Error(), "header injection guard") {
		t.Fatalf("expected CRLF injection guard error, got %v", err)
	}
}

func TestApplySubstitutionsScopingSkipsUndeclaredSurfaces(t *testing.T) {
	// Substitution declared only for "path"; placeholder also appears
	// in query, header, and would-be body. Only the path is rewritten;
	// the others retain the literal token.
	u := mustParseURL(t, "https://api.example.com/items/__sid__?id=__sid__")
	headers := http.Header{}
	headers.Set("X-Echo", "__sid__")

	subs := []ResolvedSubstitution{{
		Placeholder: "__sid__",
		Value:       "REAL",
		In:          []string{"path"},
	}}
	if err := ApplySubstitutions(u, headers, subs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(u.Path, "REAL") {
		t.Fatalf("expected path rewritten, got %q", u.Path)
	}
	if u.RawQuery != "id=__sid__" {
		t.Fatalf("expected query untouched, got %q", u.RawQuery)
	}
	if headers.Get("X-Echo") != "__sid__" {
		t.Fatalf("expected header untouched, got %q", headers.Get("X-Echo"))
	}
}

func TestApplySubstitutionsCaseSensitive(t *testing.T) {
	u := mustParseURL(t, "https://api.example.com/items/__SID__")
	subs := []ResolvedSubstitution{{
		Placeholder: "__sid__",
		Value:       "REAL",
		In:          []string{"path"},
	}}
	if err := ApplySubstitutions(u, nil, subs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(u.Path, "__SID__") {
		t.Fatalf("expected uppercase placeholder NOT to match (case-sensitive), got %q", u.Path)
	}
}

func TestApplySubstitutionsMultiple(t *testing.T) {
	u := mustParseURL(t, "https://api.example.com/__org__/items/__id__?v=1")
	subs := []ResolvedSubstitution{
		{Placeholder: "__org__", Value: "acme", In: []string{"path"}},
		{Placeholder: "__id__", Value: "42", In: []string{"path"}},
	}
	if err := ApplySubstitutions(u, nil, subs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Path != "/acme/items/42" {
		t.Fatalf("expected both substitutions applied, got %q", u.Path)
	}
}

func TestApplySubstitutionsNoMatchIsNoop(t *testing.T) {
	u := mustParseURL(t, "https://api.example.com/items/123")
	subs := []ResolvedSubstitution{{
		Placeholder: "__sid__",
		Value:       "REAL",
		In:          []string{"path", "query"},
	}}
	before := u.String()
	if err := ApplySubstitutions(u, nil, subs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.String() != before {
		t.Fatalf("expected no-op, got %q", u.String())
	}
}

func TestApplySubstitutionsEmpty(t *testing.T) {
	u := mustParseURL(t, "https://api.example.com/items/__sid__")
	if err := ApplySubstitutions(u, nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Path != "/items/__sid__" {
		t.Fatal("nil subs slice should not mutate URL")
	}
}

// --- Body substitution tests ---

func makeBody(s string) io.ReadCloser {
	return io.NopCloser(strings.NewReader(s))
}

func readBody(t *testing.T, body io.ReadCloser) string {
	t.Helper()
	data, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	return string(data)
}

func TestApplyBodySubstitutionsFormURLEncoded(t *testing.T) {
	body := makeBody("client_id=abc&client_secret=__secret__&code=xyz")
	subs := []ResolvedSubstitution{{
		Placeholder: "__secret__",
		Value:       "s3cr&t=val+ue",
		In:          []string{"body"},
	}}
	newBody, newLen, modified, err := ApplyBodySubstitutions(body, 46, "application/x-www-form-urlencoded", subs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !modified {
		t.Fatal("expected modified=true")
	}
	got := readBody(t, newBody)
	if !strings.Contains(got, "client_secret=s3cr%26t%3Dval%2Bue") {
		t.Fatalf("expected URL-encoded value, got %q", got)
	}
	if int64(len(got)) != newLen {
		t.Fatalf("Content-Length mismatch: body=%d, reported=%d", len(got), newLen)
	}
}

func TestApplyBodySubstitutionsFormURLEncodedWithCharset(t *testing.T) {
	body := makeBody("secret=__secret__")
	subs := []ResolvedSubstitution{{
		Placeholder: "__secret__",
		Value:       "a&b",
		In:          []string{"body"},
	}}
	newBody, _, modified, err := ApplyBodySubstitutions(body, 17, "application/x-www-form-urlencoded; charset=utf-8", subs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !modified {
		t.Fatal("expected modified=true")
	}
	got := readBody(t, newBody)
	if !strings.Contains(got, "secret=a%26b") {
		t.Fatalf("expected URL-encoded value with charset param, got %q", got)
	}
}

func TestApplyBodySubstitutionsJSON(t *testing.T) {
	body := makeBody(`{"token": "__token__"}`)
	subs := []ResolvedSubstitution{{
		Placeholder: "__token__",
		Value:       `val"with\slash`,
		In:          []string{"body"},
	}}
	newBody, _, modified, err := ApplyBodySubstitutions(body, 21, "application/json", subs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !modified {
		t.Fatal("expected modified=true")
	}
	got := readBody(t, newBody)
	if !strings.Contains(got, `val\"with\\slash`) {
		t.Fatalf("expected JSON-escaped value, got %q", got)
	}
}

func TestApplyBodySubstitutionsJSONWithCharset(t *testing.T) {
	body := makeBody(`{"key": "__key__"}`)
	subs := []ResolvedSubstitution{{
		Placeholder: "__key__",
		Value:       `has"quote`,
		In:          []string{"body"},
	}}
	_, _, modified, err := ApplyBodySubstitutions(body, 18, "application/json; charset=utf-8", subs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !modified {
		t.Fatal("expected modified=true (json with charset param)")
	}
}

func TestApplyBodySubstitutionsMultipartSkipped(t *testing.T) {
	body := makeBody("--boundary\r\nContent-Disposition: form-data; name=\"secret\"\r\n\r\n__secret__\r\n--boundary--")
	subs := []ResolvedSubstitution{{
		Placeholder: "__secret__",
		Value:       "real",
		In:          []string{"body"},
	}}
	_, _, modified, err := ApplyBodySubstitutions(body, 85, "multipart/form-data; boundary=boundary", subs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if modified {
		t.Fatal("expected modified=false for multipart body")
	}
}

func TestApplyBodySubstitutionsRawForPlaintext(t *testing.T) {
	body := makeBody("token=__token__")
	subs := []ResolvedSubstitution{{
		Placeholder: "__token__",
		Value:       "raw&value",
		In:          []string{"body"},
	}}
	newBody, _, modified, err := ApplyBodySubstitutions(body, 15, "text/plain", subs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !modified {
		t.Fatal("expected modified=true")
	}
	got := readBody(t, newBody)
	if got != "token=raw&value" {
		t.Fatalf("expected raw replacement, got %q", got)
	}
}

func TestApplyBodySubstitutionsNoBodySurface(t *testing.T) {
	body := makeBody("secret=__secret__")
	subs := []ResolvedSubstitution{{
		Placeholder: "__secret__",
		Value:       "real",
		In:          []string{"header"},
	}}
	_, _, modified, err := ApplyBodySubstitutions(body, 17, "text/plain", subs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if modified {
		t.Fatal("expected modified=false when no sub targets body surface")
	}
}

func TestApplyBodySubstitutionsNilBody(t *testing.T) {
	subs := []ResolvedSubstitution{{
		Placeholder: "__secret__",
		Value:       "real",
		In:          []string{"body"},
	}}
	_, _, modified, err := ApplyBodySubstitutions(nil, 0, "", subs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if modified {
		t.Fatal("expected modified=false for nil body")
	}
}

func TestApplyBodySubstitutionsNoBody(t *testing.T) {
	subs := []ResolvedSubstitution{{
		Placeholder: "__secret__",
		Value:       "real",
		In:          []string{"body"},
	}}
	_, _, modified, err := ApplyBodySubstitutions(http.NoBody, 0, "", subs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if modified {
		t.Fatal("expected modified=false for http.NoBody")
	}
}

func TestApplyBodySubstitutionsEmptyBody(t *testing.T) {
	body := makeBody("")
	subs := []ResolvedSubstitution{{
		Placeholder: "__secret__",
		Value:       "real",
		In:          []string{"body"},
	}}
	_, _, modified, err := ApplyBodySubstitutions(body, 0, "text/plain", subs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if modified {
		t.Fatal("expected modified=false for empty body")
	}
}

func TestApplyBodySubstitutionsNoMatch(t *testing.T) {
	body := makeBody("secret=other_value")
	subs := []ResolvedSubstitution{{
		Placeholder: "__secret__",
		Value:       "real",
		In:          []string{"body"},
	}}
	_, _, modified, err := ApplyBodySubstitutions(body, 18, "text/plain", subs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if modified {
		t.Fatal("expected modified=false when placeholder not present")
	}
}

func TestApplyBodySubstitutionsScopingDoesNotAffectOtherSurfaces(t *testing.T) {
	u := mustParseURL(t, "https://api.example.com/items/__sid__?id=__sid__")
	headers := http.Header{}
	headers.Set("X-Echo", "__sid__")

	subs := []ResolvedSubstitution{{
		Placeholder: "__sid__",
		Value:       "REAL",
		In:          []string{"body"},
	}}
	if err := ApplySubstitutions(u, headers, subs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(u.Path, "__sid__") {
		t.Fatalf("body-only sub should not modify path, got %q", u.Path)
	}
	if u.RawQuery != "id=__sid__" {
		t.Fatalf("body-only sub should not modify query, got %q", u.RawQuery)
	}
	if headers.Get("X-Echo") != "__sid__" {
		t.Fatalf("body-only sub should not modify header, got %q", headers.Get("X-Echo"))
	}
}

func TestHasBodySubstitutions(t *testing.T) {
	cases := []struct {
		name string
		subs []ResolvedSubstitution
		want bool
	}{
		{"nil", nil, false},
		{"empty", []ResolvedSubstitution{}, false},
		{"header only", []ResolvedSubstitution{{In: []string{"header"}}}, false},
		{"path and query", []ResolvedSubstitution{{In: []string{"path", "query"}}}, false},
		{"body", []ResolvedSubstitution{{In: []string{"body"}}}, true},
		{"body among others", []ResolvedSubstitution{{In: []string{"header", "body"}}}, true},
		{"second sub has body", []ResolvedSubstitution{
			{In: []string{"header"}},
			{In: []string{"body"}},
		}, true},
		{"websocket only", []ResolvedSubstitution{{In: []string{"websocket"}}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasBodySubstitutions(tc.subs); got != tc.want {
				t.Errorf("HasBodySubstitutions() = %v, want %v", got, tc.want)
			}
		})
	}
}
