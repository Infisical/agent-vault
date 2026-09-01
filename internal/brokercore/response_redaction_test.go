package brokercore

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func readCloserString(t *testing.T, body io.ReadCloser) string {
	t.Helper()
	data, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return string(data)
}

func TestApplyResponseRedactionsJSONRawToken(t *testing.T) {
	body := io.NopCloser(strings.NewReader(`{"token":"injected-secret"}`))
	next, n, modified, err := ApplyResponseRedactions(body, 27, "application/json", []ResolvedRedaction{{
		Value: "injected-secret",
	}})
	if err != nil {
		t.Fatalf("ApplyResponseRedactions: %v", err)
	}
	if !modified {
		t.Fatal("expected body to be modified")
	}
	got := readCloserString(t, next)
	if strings.Contains(got, "injected-secret") {
		t.Fatalf("secret was not redacted: %s", got)
	}
	if got != `{"token":"[REDACTED]"}` {
		t.Fatalf("body = %q", got)
	}
	if n != int64(len(got)) {
		t.Fatalf("length = %d, want %d", n, len(got))
	}
}

func TestApplyResponseRedactionsPrefersLongerRenderedValue(t *testing.T) {
	body := io.NopCloser(strings.NewReader(`{"auth":"Bearer injected-secret","token":"injected-secret"}`))
	next, _, modified, err := ApplyResponseRedactions(body, 0, "application/json", []ResolvedRedaction{
		{Value: "injected-secret", Replacement: "[TOKEN]"},
		{Value: "Bearer injected-secret", Replacement: "[AUTH]"},
	})
	if err != nil {
		t.Fatalf("ApplyResponseRedactions: %v", err)
	}
	if !modified {
		t.Fatal("expected body to be modified")
	}
	got := readCloserString(t, next)
	if got != `{"auth":"[AUTH]","token":"[TOKEN]"}` {
		t.Fatalf("body = %q", got)
	}
}

func TestApplyResponseRedactionsDisabledWhenNoRules(t *testing.T) {
	body := io.NopCloser(strings.NewReader(`{"token":"injected-secret"}`))
	next, n, modified, err := ApplyResponseRedactions(body, 27, "application/json", nil)
	if err != nil {
		t.Fatalf("ApplyResponseRedactions: %v", err)
	}
	if modified {
		t.Fatal("expected body to be unchanged")
	}
	if next == nil {
		t.Fatal("expected original body")
	}
	if n != 27 {
		t.Fatalf("length = %d, want 27", n)
	}
}

func TestApplyResponseRedactionsSkipsBinaryBody(t *testing.T) {
	body := io.NopCloser(strings.NewReader("injected-secret"))
	next, _, modified, err := ApplyResponseRedactions(body, 15, "application/octet-stream", []ResolvedRedaction{{
		Value: "injected-secret",
	}})
	if err != nil {
		t.Fatalf("ApplyResponseRedactions: %v", err)
	}
	if modified {
		t.Fatal("expected binary body to be skipped")
	}
	if got := readCloserString(t, next); got != "injected-secret" {
		t.Fatalf("body = %q", got)
	}
}

func TestApplyResponseRedactionsNoBody(t *testing.T) {
	next, n, modified, err := ApplyResponseRedactions(http.NoBody, 0, "application/json", []ResolvedRedaction{{
		Value: "injected-secret",
	}})
	if err != nil {
		t.Fatalf("ApplyResponseRedactions: %v", err)
	}
	if next != http.NoBody || n != 0 || modified {
		t.Fatalf("next=%v length=%d modified=%v", next, n, modified)
	}
}
