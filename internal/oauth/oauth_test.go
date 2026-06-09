package oauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// helper: parse form from request body
func parseForm(t *testing.T, r *http.Request) url.Values {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("reading request body: %v", err)
	}
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		t.Fatalf("parsing form body: %v", err)
	}
	return vals
}

func TestExchange_HappyPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		form := parseForm(t, r)
		if got := form.Get("grant_type"); got != "authorization_code" {
			t.Errorf("grant_type = %q, want authorization_code", got)
		}
		if got := form.Get("code"); got != "auth-code-123" {
			t.Errorf("code = %q, want auth-code-123", got)
		}
		if got := form.Get("redirect_uri"); got != "http://localhost/callback" {
			t.Errorf("redirect_uri = %q, want http://localhost/callback", got)
		}
		if got := form.Get("client_id"); got != "my-client" {
			t.Errorf("client_id = %q, want my-client", got)
		}
		if got := form.Get("client_secret"); got != "my-secret" {
			t.Errorf("client_secret = %q, want my-secret", got)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "tok",
			"token_type":    "bearer",
			"expires_in":    3600,
			"refresh_token": "ref",
		})
	}))
	defer ts.Close()

	before := time.Now()
	tok, err := Exchange(context.Background(), ExchangeConfig{
		TokenURL:     ts.URL,
		ClientID:     "my-client",
		ClientSecret: "my-secret",
		Code:         "auth-code-123",
		RedirectURI:  "http://localhost/callback",
	})
	if err != nil {
		t.Fatalf("Exchange returned error: %v", err)
	}
	if tok.AccessToken != "tok" {
		t.Errorf("AccessToken = %q, want tok", tok.AccessToken)
	}
	if tok.RefreshToken != "ref" {
		t.Errorf("RefreshToken = %q, want ref", tok.RefreshToken)
	}
	if tok.TokenType != "bearer" {
		t.Errorf("TokenType = %q, want bearer", tok.TokenType)
	}
	if tok.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want 3600", tok.ExpiresIn)
	}
	// ExpiresAt should be roughly now + 3600s
	expectedAt := before.Add(3600 * time.Second)
	if tok.ExpiresAt.Before(before) || tok.ExpiresAt.After(expectedAt.Add(5*time.Second)) {
		t.Errorf("ExpiresAt = %v, expected ~%v", tok.ExpiresAt, expectedAt)
	}
}

func TestExchange_PublicClient(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		form := parseForm(t, r)
		if form.Get("client_secret") != "" {
			t.Error("client_secret should NOT be present for public clients")
		}
		if got := form.Get("code_verifier"); got != "my-verifier" {
			t.Errorf("code_verifier = %q, want my-verifier", got)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "public-tok",
			"token_type":   "bearer",
			"expires_in":   1800,
		})
	}))
	defer ts.Close()

	tok, err := Exchange(context.Background(), ExchangeConfig{
		TokenURL:     ts.URL,
		ClientID:     "public-client",
		ClientSecret: "", // public client — no secret
		Code:         "code",
		RedirectURI:  "http://localhost/callback",
		CodeVerifier: "my-verifier",
	})
	if err != nil {
		t.Fatalf("Exchange returned error: %v", err)
	}
	if tok.AccessToken != "public-tok" {
		t.Errorf("AccessToken = %q, want public-tok", tok.AccessToken)
	}
}

func TestExchange_ClientSecretBasic(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			t.Fatal("expected Basic auth header")
		}
		if user != "my-client" || pass != "my-secret" {
			t.Errorf("Basic auth = %q:%q, want my-client:my-secret", user, pass)
		}

		// client_secret should NOT be in the form body for basic auth
		form := parseForm(t, r)
		if form.Get("client_secret") != "" {
			t.Error("client_secret should NOT be in form body for client_secret_basic")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "basic-tok",
			"token_type":   "bearer",
			"expires_in":   3600,
		})
	}))
	defer ts.Close()

	tok, err := Exchange(context.Background(), ExchangeConfig{
		TokenURL:        ts.URL,
		ClientID:        "my-client",
		ClientSecret:    "my-secret",
		Code:            "code",
		RedirectURI:     "http://localhost/callback",
		TokenAuthMethod: "client_secret_basic",
	})
	if err != nil {
		t.Fatalf("Exchange returned error: %v", err)
	}
	if tok.AccessToken != "basic-tok" {
		t.Errorf("AccessToken = %q, want basic-tok", tok.AccessToken)
	}
}

func TestRefresh_HappyPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		form := parseForm(t, r)
		if got := form.Get("grant_type"); got != "refresh_token" {
			t.Errorf("grant_type = %q, want refresh_token", got)
		}
		if got := form.Get("refresh_token"); got != "old-refresh" {
			t.Errorf("refresh_token = %q, want old-refresh", got)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "new-access",
			"token_type":    "bearer",
			"expires_in":    3600,
			"refresh_token": "new-refresh",
		})
	}))
	defer ts.Close()

	tok, err := Refresh(context.Background(), RefreshConfig{
		TokenURL:     ts.URL,
		ClientID:     "my-client",
		ClientSecret: "my-secret",
		RefreshToken: "old-refresh",
	})
	if err != nil {
		t.Fatalf("Refresh returned error: %v", err)
	}
	if tok.AccessToken != "new-access" {
		t.Errorf("AccessToken = %q, want new-access", tok.AccessToken)
	}
	if tok.RefreshToken != "new-refresh" {
		t.Errorf("RefreshToken = %q, want new-refresh", tok.RefreshToken)
	}
}

func TestRefresh_TokenRotation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "rotated-access",
			"token_type":    "bearer",
			"expires_in":    7200,
			"refresh_token": "rotated-refresh",
		})
	}))
	defer ts.Close()

	tok, err := Refresh(context.Background(), RefreshConfig{
		TokenURL:     ts.URL,
		ClientID:     "c",
		ClientSecret: "s",
		RefreshToken: "old",
	})
	if err != nil {
		t.Fatalf("Refresh returned error: %v", err)
	}
	if tok.RefreshToken != "rotated-refresh" {
		t.Errorf("RefreshToken = %q, want rotated-refresh", tok.RefreshToken)
	}
}

func TestRefresh_NoNewRefreshToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Provider does not rotate the refresh token — omit from response
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "fresh-access",
			"token_type":   "bearer",
			"expires_in":   3600,
		})
	}))
	defer ts.Close()

	tok, err := Refresh(context.Background(), RefreshConfig{
		TokenURL:     ts.URL,
		ClientID:     "c",
		ClientSecret: "s",
		RefreshToken: "keep-me",
	})
	if err != nil {
		t.Fatalf("Refresh returned error: %v", err)
	}
	if tok.RefreshToken != "" {
		t.Errorf("RefreshToken = %q, want empty (provider did not rotate)", tok.RefreshToken)
	}
}

func TestRefresh_PermanentError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer ts.Close()

	_, err := Refresh(context.Background(), RefreshConfig{
		TokenURL:     ts.URL,
		ClientID:     "c",
		ClientSecret: "s",
		RefreshToken: "bad",
	})
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
	te, ok := err.(*TokenError)
	if !ok {
		t.Fatalf("expected *TokenError, got %T", err)
	}
	if te.StatusCode != 400 {
		t.Errorf("StatusCode = %d, want 400", te.StatusCode)
	}
	if !te.Permanent {
		t.Error("expected Permanent = true for 400")
	}
}

func TestRefresh_TransientError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("internal server error"))
	}))
	defer ts.Close()

	_, err := Refresh(context.Background(), RefreshConfig{
		TokenURL:     ts.URL,
		ClientID:     "c",
		ClientSecret: "s",
		RefreshToken: "tok",
	})
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	te, ok := err.(*TokenError)
	if !ok {
		t.Fatalf("expected *TokenError, got %T", err)
	}
	if te.Permanent {
		t.Error("expected Permanent = false for 500")
	}
}

func TestRefresh_RateLimited(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		w.Write([]byte("too many requests"))
	}))
	defer ts.Close()

	_, err := Refresh(context.Background(), RefreshConfig{
		TokenURL:     ts.URL,
		ClientID:     "c",
		ClientSecret: "s",
		RefreshToken: "tok",
	})
	if err == nil {
		t.Fatal("expected error for 429 response")
	}
	te, ok := err.(*TokenError)
	if !ok {
		t.Fatalf("expected *TokenError, got %T", err)
	}
	if te.StatusCode != 429 {
		t.Errorf("StatusCode = %d, want 429", te.StatusCode)
	}
	if te.Permanent {
		t.Error("expected Permanent = false for 429 (rate-limited is transient)")
	}
}

func TestIsPermanentError(t *testing.T) {
	tests := []struct {
		code int
		want bool
	}{
		{200, false},
		{301, false},
		{400, true},
		{401, true},
		{403, true},
		{404, true},
		{408, false},  // Request Timeout — transient
		{422, true},
		{429, false},  // Too Many Requests — transient
		{500, false},
		{502, false},
		{503, false},
	}
	for _, tt := range tests {
		got := IsPermanentError(tt.code)
		if got != tt.want {
			t.Errorf("IsPermanentError(%d) = %v, want %v", tt.code, got, tt.want)
		}
	}
}
