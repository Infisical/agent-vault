package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// expectedRunFlags is the single source of truth for flags both `vault run`
// and the top-level `run` shorthand must expose. Adding a flag to one without
// the other is a bug. `vault` is inherited from vaultCmd's persistent flags
// on `vault run` and registered locally on the top-level `run`.
var expectedRunFlags = []string{
	"address", "ttl", "vault",
	"isolation", "image", "mount", "keep", "no-firewall",
	"home-volume-shared", "share-agent-dir",
}

func TestRunFlagsRegistered(t *testing.T) {
	vCmd := findSubcommand(rootCmd, "vault")
	if vCmd == nil {
		t.Fatal("vault command not found")
	}
	rCmd := findSubcommand(vCmd, "run")
	if rCmd == nil {
		t.Fatal("vault run subcommand not found")
	}

	// Flag walks local + inherited persistent flags, matching what users see.
	for _, name := range expectedRunFlags {
		if rCmd.Flag(name) == nil {
			t.Errorf("expected vault run flag --%s to be registered", name)
		}
	}
}

// TestTopLevelRunRegistered guards the `agent-vault run` shorthand — it must
// be a direct child of rootCmd and expose the same flag surface as `vault run`.
func TestTopLevelRunRegistered(t *testing.T) {
	tCmd := findSubcommand(rootCmd, "run")
	if tCmd == nil {
		t.Fatal("top-level run command not found")
	}
	if tCmd.Parent() != rootCmd {
		t.Errorf("top-level run must be parented to rootCmd, got %v", tCmd.Parent())
	}

	for _, name := range expectedRunFlags {
		if tCmd.Flag(name) == nil {
			t.Errorf("expected top-level run flag --%s to be registered", name)
		}
	}
}

func TestAugmentEnvWithMITM_Disabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/mitm/ca.pem" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("MITM proxy is not enabled on this server\n"))
	}))
	defer srv.Close()

	caPath := filepath.Join(t.TempDir(), "mitm-ca.pem")
	baseEnv := []string{"FOO=bar"}

	env, port, ok, err := augmentEnvWithMITM(baseEnv, srv.URL, "av_sess_abc", "default", caPath)
	if err != nil {
		t.Fatalf("expected nil err on 404, got %v", err)
	}
	if ok {
		t.Fatal("expected ok=false when server 404s")
	}
	if port != 0 {
		t.Errorf("expected port=0 when disabled, got %d", port)
	}
	if len(env) != len(baseEnv) || env[0] != "FOO=bar" {
		t.Errorf("env should be unchanged on 404, got %v", env)
	}
	if _, err := os.Stat(caPath); !os.IsNotExist(err) {
		t.Errorf("expected no CA file on 404, stat err=%v", err)
	}
}

func TestRequireMITMEnv_DisabledIsFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	caPath := filepath.Join(t.TempDir(), "mitm-ca.pem")
	_, _, err := requireMITMEnv(nil, srv.URL, "tok", "v", caPath)
	if err == nil {
		t.Fatal("expected fatal error when server has MITM disabled")
	}
	// Operator-facing message must point at the server-side fix.
	if !strings.Contains(err.Error(), "--mitm-port 0") {
		t.Errorf("error should reference --mitm-port 0; got: %v", err)
	}
}

func TestRequireMITMEnv_TransportFailureIsFatal(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "mitm-ca.pem")
	// Bogus address that will fail to dial.
	_, _, err := requireMITMEnv(nil, "http://127.0.0.1:1", "tok", "v", caPath)
	if err == nil {
		t.Fatal("expected fatal error on transport failure")
	}
	if !strings.Contains(err.Error(), "MITM setup failed") {
		t.Errorf("error should be wrapped with 'MITM setup failed'; got: %v", err)
	}
}

// fakeMITMServer returns an httptest server that mimics the real
// /v1/mitm/ca.pem endpoint. advertisedPort, when non-zero, is written
// into the X-MITM-Port response header.
func fakeMITMServer(t *testing.T, pem string, advertisedPort int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if advertisedPort > 0 {
			w.Header().Set("X-MITM-Port", fmt.Sprintf("%d", advertisedPort))
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write([]byte(pem))
	}))
}

func TestAugmentEnvWithMITM_Enabled(t *testing.T) {
	const fakePEM = "-----BEGIN CERTIFICATE-----\nMIIFAKE\n-----END CERTIFICATE-----\n"
	srv := fakeMITMServer(t, fakePEM, 9001)
	defer srv.Close()

	caPath := filepath.Join(t.TempDir(), "mitm-ca.pem")
	env, port, ok, err := augmentEnvWithMITM(nil, srv.URL, "av_sess_abc", "default", caPath)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true on 200")
	}
	if port != 9001 {
		t.Errorf("port = %d, want 9001 (from X-MITM-Port header)", port)
	}

	got, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("reading CA file: %v", err)
	}
	if string(got) != fakePEM {
		t.Errorf("CA file contents mismatch:\nwant %q\n got %q", fakePEM, string(got))
	}

	want := map[string]string{
		"HTTPS_PROXY":         "", // checked separately below
		"HTTP_PROXY":          "", // checked separately below
		"NO_PROXY":            "", // checked separately — includes AV host
		"NODE_USE_ENV_PROXY":  "1",
		"OPENCLAW_PROXY_URL":  "", // checked separately below (equals HTTPS_PROXY)
		"SSL_CERT_FILE":       caPath,
		"NODE_EXTRA_CA_CERTS": caPath,
		"REQUESTS_CA_BUNDLE":  caPath,
		"CURL_CA_BUNDLE":      caPath,
		"GIT_SSL_CAINFO":      caPath,
		"DENO_CERT":           caPath,
	}
	vars := envMap(env)
	for k, v := range want {
		got, ok := vars[k]
		if !ok {
			t.Errorf("missing env var %s", k)
			continue
		}
		if v != "" && got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}

	// HTTP_PROXY and OPENCLAW_PROXY_URL must equal HTTPS_PROXY — all
	// point at the same MITM ingress so plain http:// upstreams and
	// OpenClaw's Proxyline route through the broker.
	if vars["HTTP_PROXY"] != vars["HTTPS_PROXY"] {
		t.Errorf("HTTP_PROXY = %q, want it to equal HTTPS_PROXY = %q", vars["HTTP_PROXY"], vars["HTTPS_PROXY"])
	}
	if vars["OPENCLAW_PROXY_URL"] != vars["HTTPS_PROXY"] {
		t.Errorf("OPENCLAW_PROXY_URL = %q, want it to equal HTTPS_PROXY = %q", vars["OPENCLAW_PROXY_URL"], vars["HTTPS_PROXY"])
	}

	// NO_PROXY must include the AV host so control-plane calls bypass the proxy.
	noProxy := vars["NO_PROXY"]
	if !strings.Contains(noProxy, "localhost") || !strings.Contains(noProxy, "127.0.0.1") {
		t.Errorf("NO_PROXY = %q, want localhost and 127.0.0.1", noProxy)
	}

	// Proxy URL must parse cleanly and carry token:vault userinfo.
	proxyURL := vars["HTTPS_PROXY"]
	if proxyURL == "" {
		t.Fatal("HTTPS_PROXY not set")
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("parse HTTPS_PROXY: %v", err)
	}
	if u.Scheme != "http" {
		t.Errorf("proxy scheme = %q, want http", u.Scheme)
	}
	if u.User == nil {
		t.Fatal("proxy URL missing userinfo")
	}
	if u.User.Username() != "av_sess_abc" {
		t.Errorf("proxy username = %q, want av_sess_abc", u.User.Username())
	}
	if pw, _ := u.User.Password(); pw != "default" {
		t.Errorf("proxy password (vault) = %q, want default", pw)
	}
	// Host should use the advertised X-MITM-Port (9001), not the compile-time
	// default — this guards the regression where --mitm-port 9000 produced
	// a URL pointing at 14322.
	wantHost := "127.0.0.1:9001"
	if u.Host != wantHost {
		t.Errorf("proxy host = %q, want %q", u.Host, wantHost)
	}
}

// TestAugmentEnvWithMITM_PortFallback verifies that a server which does
// not advertise X-MITM-Port (e.g. pre-v0.8 build) is still usable — the
// client falls back to DefaultMITMPort rather than emitting a URL with
// port 0.
func TestAugmentEnvWithMITM_PortFallback(t *testing.T) {
	const fakePEM = "-----BEGIN CERTIFICATE-----\nMIIFAKE\n-----END CERTIFICATE-----\n"
	srv := fakeMITMServer(t, fakePEM, 0) // no port header
	defer srv.Close()

	caPath := filepath.Join(t.TempDir(), "mitm-ca.pem")
	_, port, ok, err := augmentEnvWithMITM(nil, srv.URL, "tok", "v", caPath)
	if err != nil || !ok {
		t.Fatalf("augmentEnvWithMITM: ok=%v err=%v", ok, err)
	}
	if port != DefaultMITMPort {
		t.Errorf("port = %d, want fallback to DefaultMITMPort (%d)", port, DefaultMITMPort)
	}
}

// TestAugmentEnvWithMITM_DedupesParentEnv guards the corporate-proxy
// regression: if the parent shell already has HTTPS_PROXY / SSL_CERT_FILE
// etc. set, C tooling (curl, libcurl-backed Python, git) reads the FIRST
// matching envp entry via getenv — so the stale parent value would win
// over the injected MITM value and bypass credential injection entirely.
// The fix strips the parent entries before appending the new ones.
func TestAugmentEnvWithMITM_DedupesParentEnv(t *testing.T) {
	const fakePEM = "-----BEGIN CERTIFICATE-----\nMIIFAKE\n-----END CERTIFICATE-----\n"
	srv := fakeMITMServer(t, fakePEM, 14322)
	defer srv.Close()

	caPath := filepath.Join(t.TempDir(), "mitm-ca.pem")
	parentEnv := []string{
		"FOO=bar",
		"HTTPS_PROXY=http://corp-proxy:3128",
		"HTTP_PROXY=http://corp-proxy:3128",
		"NO_PROXY=internal.example.com",
		"SSL_CERT_FILE=/etc/ssl/corp-ca.pem",
		"NODE_EXTRA_CA_CERTS=/etc/ssl/corp-ca.pem",
		"REQUESTS_CA_BUNDLE=/etc/ssl/corp-ca.pem",
		"CURL_CA_BUNDLE=/etc/ssl/corp-ca.pem",
		"GIT_SSL_CAINFO=/etc/ssl/corp-ca.pem",
		"DENO_CERT=/etc/ssl/corp-ca.pem",
		"UNRELATED=keep-me",
	}
	env, _, ok, err := augmentEnvWithMITM(parentEnv, srv.URL, "tok", "v", caPath)
	if err != nil || !ok {
		t.Fatalf("augmentEnvWithMITM: ok=%v err=%v", ok, err)
	}

	// Each managed key must appear exactly once, and that single value
	// must be the injected MITM value — not the stale parent value.
	counts := map[string]int{}
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			counts[kv[:i]]++
		}
	}
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "NODE_USE_ENV_PROXY", "OPENCLAW_PROXY_URL", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "DENO_CERT"} {
		if counts[k] != 1 {
			t.Errorf("%s appears %d times in env, want exactly 1 (POSIX getenv returns first match)", k, counts[k])
		}
	}

	vars := envMap(env)
	if vars["HTTPS_PROXY"] == "http://corp-proxy:3128" {
		t.Error("HTTPS_PROXY still carries the parent corp-proxy value")
	}
	if !strings.Contains(vars["HTTPS_PROXY"], "127.0.0.1:14322") {
		t.Errorf("HTTPS_PROXY = %q, want the MITM URL", vars["HTTPS_PROXY"])
	}
	if vars["SSL_CERT_FILE"] != caPath {
		t.Errorf("SSL_CERT_FILE = %q, want %q", vars["SSL_CERT_FILE"], caPath)
	}
	if vars["UNRELATED"] != "keep-me" {
		t.Error("unrelated parent env vars must be preserved")
	}
	if vars["FOO"] != "bar" {
		t.Error("unrelated parent env vars must be preserved")
	}
}

func envMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

// newRunCmdForTest builds a run command with --vault registered locally so
// tests don't depend on the persistent flag inherited from vaultCmd.
func newRunCmdForTest() *cobra.Command {
	c := newRunCmd("test")
	c.Flags().String("vault", "", "target vault")
	return c
}

func TestResolveVaultForAgentMode(t *testing.T) {
	t.Run("flag wins", func(t *testing.T) {
		t.Setenv("AGENT_VAULT_VAULT", "env-vault")
		c := newRunCmdForTest()
		_ = c.Flags().Set("vault", "flag-vault")
		got, err := resolveVaultForAgentMode(c)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "flag-vault" {
			t.Errorf("got %q, want flag-vault", got)
		}
	})

	t.Run("env when no flag", func(t *testing.T) {
		t.Setenv("AGENT_VAULT_VAULT", "env-vault")
		c := newRunCmdForTest()
		got, err := resolveVaultForAgentMode(c)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "env-vault" {
			t.Errorf("got %q, want env-vault", got)
		}
	})

	t.Run("error when neither set", func(t *testing.T) {
		t.Setenv("AGENT_VAULT_VAULT", "")
		c := newRunCmdForTest()
		_, err := resolveVaultForAgentMode(c)
		if err == nil {
			t.Fatal("expected error when no vault is configured")
		}
		if !strings.Contains(err.Error(), "AGENT_VAULT_VAULT") {
			t.Errorf("error should mention AGENT_VAULT_VAULT; got: %v", err)
		}
	})
}

// TestStripEnvKeys_AgentVaultInjectedKeys is the AGENT_VAULT_* analogue of
// TestAugmentEnvWithMITM_DedupesParentEnv. In agent mode the parent env is
// guaranteed to already carry AGENT_VAULT_TOKEN/ADDR/VAULT (that's how agent
// mode is detected), so without this strip the parent's stale value would
// silently win in the child via POSIX getenv first-match semantics — most
// dangerously, --vault would be overridden by a stale AGENT_VAULT_VAULT.
func TestStripEnvKeys_AgentVaultInjectedKeys(t *testing.T) {
	parent := []string{
		"AGENT_VAULT_TOKEN=stale-tok",
		"AGENT_VAULT_ADDR=https://stale.example/",
		"AGENT_VAULT_VAULT=stale-vault",
		"UNRELATED=keep-me",
	}
	stripped := stripEnvKeys(parent, agentVaultInjectedKeys)
	for _, kv := range stripped {
		key := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			key = kv[:i]
		}
		if _, dropped := agentVaultInjectedKeys[key]; dropped {
			t.Errorf("expected %q to be stripped from parent env, still present as %q", key, kv)
		}
	}
	if !contains(stripped, "UNRELATED=keep-me") {
		t.Error("unrelated parent env vars must be preserved")
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// TestRunCmdAgentMode_RejectsTTL exercises the runCmdRunE early-exit when a
// pre-supplied token is used together with --ttl. The token's lifetime is
// fixed at mint time, so --ttl is meaningless in agent mode.
func TestRunCmdAgentMode_RejectsTTL(t *testing.T) {
	t.Setenv("AGENT_VAULT_TOKEN", "tok123")
	t.Setenv("AGENT_VAULT_ADDR", "http://example.invalid")
	t.Setenv("AGENT_VAULT_VAULT", "myvault")

	c := newRunCmd("test")
	_ = c.Flags().Set("ttl", "3600")
	err := runCmdRunE(c, []string{"true"})
	if err == nil {
		t.Fatal("expected error rejecting --ttl in agent mode")
	}
	if !strings.Contains(err.Error(), "--ttl has no effect") {
		t.Errorf("error should mention --ttl rejection; got: %v", err)
	}
}
