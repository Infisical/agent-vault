package brokercore

import (
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
