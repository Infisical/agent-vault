package brokercore

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func reqWithProxyAuth(v string) *http.Request {
	r := httptest.NewRequest(http.MethodConnect, "api.example.com:443", nil)
	if v != "" {
		r.Header.Set("Proxy-Authorization", v)
	}
	return r
}

func basic(userinfo string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(userinfo))
}

func TestParseProxyAuth_BearerOnly(t *testing.T) {
	tok, hint, err := ParseProxyAuth(reqWithProxyAuth("Bearer av_sess_abc"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "av_sess_abc" || hint != "" {
		t.Fatalf("got token=%q hint=%q", tok, hint)
	}
}

func TestParseProxyAuth_BasicTokenOnly(t *testing.T) {
	tok, hint, err := ParseProxyAuth(reqWithProxyAuth(basic("av_sess_abc")))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "av_sess_abc" || hint != "" {
		t.Fatalf("got token=%q hint=%q", tok, hint)
	}
}

func TestParseProxyAuth_BasicTokenAndVault(t *testing.T) {
	tok, hint, err := ParseProxyAuth(reqWithProxyAuth(basic("av_agt_xyz:default")))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "av_agt_xyz" || hint != "default" {
		t.Fatalf("got token=%q hint=%q", tok, hint)
	}
}

func TestParseProxyAuth_BasicEmptyVault(t *testing.T) {
	// Trailing colon with empty vault name — treat as empty hint.
	tok, hint, err := ParseProxyAuth(reqWithProxyAuth(basic("av_sess_abc:")))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "av_sess_abc" || hint != "" {
		t.Fatalf("got token=%q hint=%q", tok, hint)
	}
}

func TestParseProxyAuth_MissingHeader(t *testing.T) {
	_, _, err := ParseProxyAuth(reqWithProxyAuth(""))
	if !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expected ErrInvalidSession, got %v", err)
	}
}

func TestParseProxyAuth_UnsupportedScheme(t *testing.T) {
	_, _, err := ParseProxyAuth(reqWithProxyAuth("Digest whatever"))
	if !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expected ErrInvalidSession, got %v", err)
	}
}

func TestParseProxyAuth_MalformedBasic(t *testing.T) {
	_, _, err := ParseProxyAuth(reqWithProxyAuth("Basic not-base64!@#"))
	if !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expected ErrInvalidSession, got %v", err)
	}
}

func TestParseProxyAuth_EmptyToken(t *testing.T) {
	// Basic base64(":vault") — empty token.
	_, _, err := ParseProxyAuth(reqWithProxyAuth(basic(":default")))
	if !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expected ErrInvalidSession, got %v", err)
	}
}

func TestParseProxyAuth_EmptyBearer(t *testing.T) {
	_, _, err := ParseProxyAuth(reqWithProxyAuth("Bearer "))
	if !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expected ErrInvalidSession, got %v", err)
	}
}

func TestParseProxyAuth_CaseInsensitiveScheme(t *testing.T) {
	tok, _, err := ParseProxyAuth(reqWithProxyAuth("bearer av_sess_abc"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "av_sess_abc" {
		t.Fatalf("got token=%q", tok)
	}
}
