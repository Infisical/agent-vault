package hashicorp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
)

func TestDetectAuthMethod(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want AuthMethod
	}{
		{"token only", map[string]string{"VAULT_TOKEN": "t"}, AuthToken},
		{"approle only", map[string]string{"VAULT_ROLE_ID": "r", "VAULT_SECRET_ID": "s"}, AuthAppRole},
		{"approle wins over token", map[string]string{"VAULT_TOKEN": "t", "VAULT_ROLE_ID": "r", "VAULT_SECRET_ID": "s"}, AuthAppRole},
		{"partial approle falls back to token", map[string]string{"VAULT_TOKEN": "t", "VAULT_ROLE_ID": "r"}, AuthToken},
		{"partial approle, no token", map[string]string{"VAULT_ROLE_ID": "r"}, ""},
		{"nothing configured", map[string]string{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(k string) string { return tc.env[k] }
			got, err := DetectAuthMethod(getenv, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("DetectAuthMethod = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestLogin_AppRole exercises the AppRole login path: login() POSTs RoleID +
// SecretID to auth/approle/login and adopts the returned client token.
func TestLogin_AppRole(t *testing.T) {
	var gotPath string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": map[string]interface{}{"client_token": "hcv-approle-token"},
		})
	}))
	defer srv.Close()

	t.Setenv("VAULT_ROLE_ID", "role-123")
	t.Setenv("VAULT_SECRET_ID", "secret-456")

	cfg := vaultapi.DefaultConfig()
	cfg.Address = srv.URL
	api, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatalf("vault api client: %v", err)
	}
	if err := login(context.Background(), api, AuthAppRole); err != nil {
		t.Fatalf("login(AppRole): %v", err)
	}
	if gotPath != "/v1/auth/approle/login" {
		t.Errorf("login path = %q, want /v1/auth/approle/login", gotPath)
	}
	if gotBody["role_id"] != "role-123" || gotBody["secret_id"] != "secret-456" {
		t.Errorf("login body = %+v, want role_id/secret_id from env", gotBody)
	}
	if api.Token() != "hcv-approle-token" {
		t.Errorf("client token = %q, want the AppRole-issued token", api.Token())
	}
}

// TestLogin_AppRoleNoToken: a login response without a client token is an error,
// not a silent success with an empty token.
func TestLogin_AppRoleNoToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"auth":null}`)
	}))
	defer srv.Close()
	t.Setenv("VAULT_ROLE_ID", "r")
	t.Setenv("VAULT_SECRET_ID", "s")
	cfg := vaultapi.DefaultConfig()
	cfg.Address = srv.URL
	api, _ := vaultapi.NewClient(cfg)
	if err := login(context.Background(), api, AuthAppRole); err == nil {
		t.Fatal("expected an error when login returns no client token")
	}
}

// TestLogin_AppRoleCustomMount: VAULT_APPROLE_MOUNT overrides the login path for
// Enterprise/HCP setups that mount AppRole at a non-default location.
func TestLogin_AppRoleCustomMount(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": map[string]interface{}{"client_token": "tok"},
		})
	}))
	defer srv.Close()
	t.Setenv("VAULT_ROLE_ID", "r")
	t.Setenv("VAULT_SECRET_ID", "s")
	t.Setenv("VAULT_APPROLE_MOUNT", "prod-approle")
	cfg := vaultapi.DefaultConfig()
	cfg.Address = srv.URL
	api, _ := vaultapi.NewClient(cfg)
	if err := login(context.Background(), api, AuthAppRole); err != nil {
		t.Fatalf("login(AppRole, custom mount): %v", err)
	}
	if gotPath != "/v1/auth/prod-approle/login" {
		t.Errorf("login path = %q, want /v1/auth/prod-approle/login", gotPath)
	}
}

// TestLogin_Token: token auth probes lookup-self so an invalid token fails fast
// at startup rather than surfacing on the first sync tick.
func TestLogin_Token(t *testing.T) {
	var lookedUp bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			lookedUp = true
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"id": "x"}})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv("VAULT_TOKEN", "valid-token")
	cfg := vaultapi.DefaultConfig()
	cfg.Address = srv.URL
	api, _ := vaultapi.NewClient(cfg)
	if err := login(context.Background(), api, AuthToken); err != nil {
		t.Fatalf("login(Token): %v", err)
	}
	if !lookedUp {
		t.Error("expected a lookup-self probe for token auth")
	}
	if api.Token() != "valid-token" {
		t.Errorf("client token = %q, want valid-token", api.Token())
	}
}

// TestLogin_TokenInvalid: a token that fails lookup-self (e.g. expired) errors
// at login rather than silently succeeding.
func TestLogin_TokenInvalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"errors":["permission denied"]}`)
	}))
	defer srv.Close()
	t.Setenv("VAULT_TOKEN", "expired-token")
	cfg := vaultapi.DefaultConfig()
	cfg.Address = srv.URL
	api, _ := vaultapi.NewClient(cfg)
	if err := login(context.Background(), api, AuthToken); err == nil {
		t.Fatal("expected login to fail fast for an invalid token")
	}
}
