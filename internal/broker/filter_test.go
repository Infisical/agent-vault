package broker

import (
	"encoding/json"
	"testing"
)

func TestFilterJSONPresence(t *testing.T) {
	var omitted Service
	if err := json.Unmarshal([]byte(`{"name":"gh","host":"github.com","auth":{"type":"passthrough"}}`), &omitted); err != nil {
		t.Fatal(err)
	}
	if omitted.FilterOp != FilterOpOmit || omitted.Filter != nil {
		t.Fatalf("omit: op=%q filter=%v", omitted.FilterOp, omitted.Filter)
	}

	var cleared Service
	if err := json.Unmarshal([]byte(`{"name":"gh","host":"github.com","auth":{"type":"passthrough"},"filter":null}`), &cleared); err != nil {
		t.Fatal(err)
	}
	if cleared.FilterOp != FilterOpClear || cleared.Filter != nil {
		t.Fatalf("clear: op=%q filter=%v", cleared.FilterOp, cleared.Filter)
	}
	raw, err := json.Marshal(cleared)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) || !contains(string(raw), `"filter":null`) {
		t.Fatalf("clear marshal = %s", raw)
	}

	var set Service
	if err := json.Unmarshal([]byte(`{"name":"gh","host":"github.com","auth":{"type":"passthrough"},"filter":{"url":"http://127.0.0.1:9"}}`), &set); err != nil {
		t.Fatal(err)
	}
	if set.FilterOp != FilterOpSet || set.Filter == nil || set.Filter.URL != "http://127.0.0.1:9" {
		t.Fatalf("set: %+v", set.Filter)
	}
}

func TestValidateFilter(t *testing.T) {
	ok := &Filter{URL: "http://127.0.0.1:9"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (&Filter{URL: "http://localhost:9"}).Validate(); err == nil {
		t.Fatal("localhost without the insecure flag should fail")
	}
	if err := (&Filter{URL: "http://user:pass@127.0.0.1:9"}).Validate(); err == nil {
		t.Fatal("userinfo should fail")
	}
	if err := (&Filter{URL: "https://example.com", CA: "not-a-cert"}).Validate(); err == nil {
		t.Fatal("bad ca should fail")
	}
	if err := (&Filter{URL: "http://127.0.0.1:9", CA: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"}).Validate(); err == nil {
		t.Fatal("ca on http should fail")
	}
}

func TestShadowsFiltered(t *testing.T) {
	filtered := Service{Name: "push", Host: "github.com", Path: "/*/git-receive-pack", Filter: &Filter{URL: "http://127.0.0.1:9"}}
	same := Service{Name: "open", Host: "github.com", Path: "/*/git-receive-pack"}
	if !ShadowsFiltered(same, filtered) {
		t.Fatal("equal matcher should shadow")
	}
	catchAll := Service{Name: "all", Host: "github.com"}
	if ShadowsFiltered(catchAll, filtered) {
		t.Fatal("less specific catch-all should not shadow a longer path")
	}
	otherHost := Service{Name: "other", Host: "gitlab.com"}
	if ShadowsFiltered(otherHost, filtered) {
		t.Fatal("disjoint host should not shadow")
	}
	exactOverWild := Service{Name: "api", Host: "api.github.com"}
	wild := Service{Name: "wild", Host: "*.github.com", Filter: &Filter{URL: "http://127.0.0.1:9"}}
	if !ShadowsFiltered(exactOverWild, wild) {
		t.Fatal("exact host should shadow a wildcard filter")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || (func() bool { return stringIndex(s, sub) >= 0 })())
}

func stringIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
