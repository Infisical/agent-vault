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
)

func TestRunFlagsRegistered(t *testing.T) {
	vCmd := findSubcommand(rootCmd, "vault")
	if vCmd == nil {
		t.Fatal("vault command not found")
	}
	rCmd := findSubcommand(vCmd, "run")
	if rCmd == nil {
		t.Fatal("vault run subcommand not found")
	}

	for _, name := range []string{"address", "role", "ttl", "no-mitm"} {
		if rCmd.Flags().Lookup(name) == nil {
			t.Errorf("expected vault run flag --%s to be registered", name)
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
		"NO_PROXY":            "localhost,127.0.0.1",
		"NODE_USE_ENV_PROXY":  "1",
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

	// HTTP_PROXY must NOT be set — the MITM proxy is HTTPS-only and would
	// return 405 for plain http:// requests routed through it.
	if v, ok := vars["HTTP_PROXY"]; ok {
		t.Errorf("HTTP_PROXY should not be set (MITM is HTTPS-only), got %q", v)
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
	srv := fakeMITMServer(t, fakePEM, 0) // no header
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
	for _, k := range []string{"HTTPS_PROXY", "NO_PROXY", "NODE_USE_ENV_PROXY", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "DENO_CERT"} {
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
