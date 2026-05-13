package brokercore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOAuthTokenSource_FreshFetch(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Fatalf("Content-Type = %q", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if got := r.Form.Get("grant_type"); got != "refresh_token" {
			t.Fatalf("grant_type = %q", got)
		}
		if got := r.Form.Get("refresh_token"); got != "refresh-token" {
			t.Fatalf("refresh_token = %q", got)
		}
		if got := r.Form.Get("client_id"); got != "client-id" {
			t.Fatalf("client_id = %q", got)
		}
		if got := r.Form.Get("client_secret"); got != "client-secret" {
			t.Fatalf("client_secret = %q", got)
		}
		if got := r.Form.Get("scope"); got != "repo read:user" {
			t.Fatalf("scope = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"access-token","expires_in":3600}`)
	}))
	defer srv.Close()

	src := NewOAuthTokenSource()
	token, err := src.Get(context.Background(), "client-id", "client-secret", "refresh-token", srv.URL, []string{"repo", "read:user"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if token != "access-token" {
		t.Fatalf("token = %q", token)
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1", hits)
	}
}

func TestOAuthTokenSource_CacheHit(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		fmt.Fprintf(w, `{"access_token":"access-%d","expires_in":3600}`, hits)
	}))
	defer srv.Close()

	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	src := NewOAuthTokenSource()
	src.now = func() time.Time { return now }

	first, err := src.Get(context.Background(), "client-id", "client-secret", "refresh-token", srv.URL, nil)
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	second, err := src.Get(context.Background(), "client-id", "client-secret", "refresh-token", srv.URL, nil)
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if first != second {
		t.Fatalf("expected cache hit token %q, got %q", first, second)
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1", hits)
	}
}

func TestOAuthTokenSource_CacheExpiry(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		fmt.Fprintf(w, `{"access_token":"access-%d","expires_in":120}`, hits)
	}))
	defer srv.Close()

	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	src := NewOAuthTokenSource()
	src.now = func() time.Time { return now }

	first, err := src.Get(context.Background(), "client-id", "client-secret", "refresh-token", srv.URL, nil)
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	now = now.Add(61 * time.Second)
	second, err := src.Get(context.Background(), "client-id", "client-secret", "refresh-token", srv.URL, nil)
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if first == second {
		t.Fatalf("expected refreshed token after expiry, got %q both times", first)
	}
	if hits != 2 {
		t.Fatalf("hits = %d, want 2", hits)
	}
}

func TestOAuthTokenSource_NonOKResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "invalid refresh token", http.StatusBadRequest)
	}))
	defer srv.Close()

	src := NewOAuthTokenSource()
	_, err := src.Get(context.Background(), "client-id", "client-secret", "refresh-token", srv.URL, nil)
	if !errors.Is(err, ErrOAuthRefreshFailed) {
		t.Fatalf("expected ErrOAuthRefreshFailed, got %v", err)
	}
}
