package isolation

import (
	"net/url"
	"strings"
	"testing"
)

func envMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

func TestBuildContainerEnv_ProxyURL(t *testing.T) {
	env := BuildContainerEnv("av_sess_abc", "myvault", 14321, 14322, true, nil)
	vars := envMap(env)

	u, err := url.Parse(vars["HTTPS_PROXY"])
	if err != nil {
		t.Fatalf("parse HTTPS_PROXY: %v", err)
	}
	if u.Scheme != "https" {
		t.Errorf("scheme = %q, want https", u.Scheme)
	}
	if u.Hostname() != ContainerProxyHost {
		t.Errorf("host = %q, want %q (container view, not 127.0.0.1)", u.Hostname(), ContainerProxyHost)
	}
	if u.Port() != "14322" {
		t.Errorf("port = %q, want 14322", u.Port())
	}
	if u.User.Username() != "av_sess_abc" {
		t.Errorf("username = %q, want av_sess_abc", u.User.Username())
	}
	if pw, _ := u.User.Password(); pw != "myvault" {
		t.Errorf("password = %q, want myvault", pw)
	}
}

func TestBuildContainerEnv_OldServerScheme(t *testing.T) {
	env := BuildContainerEnv("tok", "v", 14321, 14322, false, nil)
	vars := envMap(env)
	u, _ := url.Parse(vars["HTTPS_PROXY"])
	if u.Scheme != "http" {
		t.Errorf("scheme = %q, want http (pre-TLS server)", u.Scheme)
	}
}

func TestBuildContainerEnv_CAPathsAllPointAtBindMount(t *testing.T) {
	env := BuildContainerEnv("tok", "v", 14321, 14322, true, nil)
	vars := envMap(env)
	for _, k := range []string{
		"SSL_CERT_FILE",
		"NODE_EXTRA_CA_CERTS",
		"REQUESTS_CA_BUNDLE",
		"CURL_CA_BUNDLE",
		"GIT_SSL_CAINFO",
		"DENO_CERT",
	} {
		if vars[k] != ContainerCAPath {
			t.Errorf("%s = %q, want %q (container-internal path)", k, vars[k], ContainerCAPath)
		}
	}
}

func TestBuildContainerEnv_AgentVaultAddrUsesContainerHost(t *testing.T) {
	env := BuildContainerEnv("tok", "v", 14321, 14322, true, nil)
	vars := envMap(env)
	want := "http://" + ContainerProxyHost + ":14321"
	if vars["AGENT_VAULT_ADDR"] != want {
		t.Errorf("AGENT_VAULT_ADDR = %q, want %q", vars["AGENT_VAULT_ADDR"], want)
	}
	if vars["AGENT_VAULT_SESSION_TOKEN"] != "tok" {
		t.Errorf("session token = %q", vars["AGENT_VAULT_SESSION_TOKEN"])
	}
	if vars["AGENT_VAULT_VAULT"] != "v" {
		t.Errorf("vault = %q", vars["AGENT_VAULT_VAULT"])
	}
}

// Internal helpers for init-firewall.sh — stripped from claude's env by
// entrypoint.sh, but we emit them so the init script sees them.
func TestBuildContainerEnv_FirewallPortsEmitted(t *testing.T) {
	env := BuildContainerEnv("tok", "v", 14321, 14322, true, nil)
	vars := envMap(env)
	if vars["VAULT_HTTP_PORT"] != "14321" {
		t.Errorf("VAULT_HTTP_PORT = %q", vars["VAULT_HTTP_PORT"])
	}
	if vars["VAULT_MITM_PORT"] != "14322" {
		t.Errorf("VAULT_MITM_PORT = %q", vars["VAULT_MITM_PORT"])
	}
}

// HTTP_PROXY must not be set — the MITM proxy is HTTPS-only and would
// 405 any plain http:// request routed through it.
func TestBuildContainerEnv_NoHTTPProxy(t *testing.T) {
	env := BuildContainerEnv("tok", "v", 14321, 14322, true, nil)
	vars := envMap(env)
	if v, ok := vars["HTTP_PROXY"]; ok {
		t.Errorf("HTTP_PROXY must not be set, got %q", v)
	}
}

// TestBuildProxyEnv_NoProxyDefault confirms the loopback defaults are
// emitted verbatim when no extras are supplied. This is the contract
// every existing caller relied on before ExtraNoProxy existed.
func TestBuildProxyEnv_NoProxyDefault(t *testing.T) {
	env := BuildProxyEnv(ProxyEnvParams{
		Host: "127.0.0.1", Port: 14322, Token: "tok", Vault: "v",
		CAPath: "/tmp/ca.pem", MITMTLS: true,
	})
	if got := envMap(env)["NO_PROXY"]; got != "localhost,127.0.0.1" {
		t.Errorf("NO_PROXY = %q, want localhost,127.0.0.1", got)
	}
}

// TestBuildProxyEnv_NoProxyExtras_Append covers the happy path: an
// operator passes a tailnet sidecar host (e.g. Aperture's "ai") and it
// shows up after the loopback defaults.
func TestBuildProxyEnv_NoProxyExtras_Append(t *testing.T) {
	env := BuildProxyEnv(ProxyEnvParams{
		Host: "127.0.0.1", Port: 14322, Token: "tok", Vault: "v",
		CAPath: "/tmp/ca.pem", MITMTLS: true,
		ExtraNoProxy: []string{"ai", "*.ts.net"},
	})
	if got := envMap(env)["NO_PROXY"]; got != "localhost,127.0.0.1,ai,*.ts.net" {
		t.Errorf("NO_PROXY = %q, want localhost,127.0.0.1,ai,*.ts.net", got)
	}
}

// TestBuildProxyEnv_NoProxyExtras_TrimAndDedup verifies the input
// sanitization: leading/trailing whitespace gets trimmed, empties are
// dropped, duplicates collapse, and the loopback defaults can't be
// re-injected to reorder them.
func TestBuildProxyEnv_NoProxyExtras_TrimAndDedup(t *testing.T) {
	env := BuildProxyEnv(ProxyEnvParams{
		Host: "127.0.0.1", Port: 14322, Token: "tok", Vault: "v",
		CAPath: "/tmp/ca.pem", MITMTLS: true,
		ExtraNoProxy: []string{"  ai  ", "", "ai", "localhost", "127.0.0.1", "foo.example.com"},
	})
	if got := envMap(env)["NO_PROXY"]; got != "localhost,127.0.0.1,ai,foo.example.com" {
		t.Errorf("NO_PROXY = %q, want localhost,127.0.0.1,ai,foo.example.com", got)
	}
}

// TestBuildContainerEnv_NoProxyExtras_PassThrough guards that container
// mode honors the extras the same way host mode does — both call paths
// share BuildProxyEnv but it's a thin wrapper, easy to drop the param.
func TestBuildContainerEnv_NoProxyExtras_PassThrough(t *testing.T) {
	env := BuildContainerEnv("tok", "v", 14321, 14322, true, []string{"ai"})
	if got := envMap(env)["NO_PROXY"]; got != "localhost,127.0.0.1,ai" {
		t.Errorf("NO_PROXY = %q, want localhost,127.0.0.1,ai", got)
	}
}
