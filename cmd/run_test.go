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

	env, ok, err := augmentEnvWithMITM(baseEnv, srv.URL, "av_sess_abc", "default", caPath)
	if err != nil {
		t.Fatalf("expected nil err on 404, got %v", err)
	}
	if ok {
		t.Fatal("expected ok=false when server 404s")
	}
	if len(env) != len(baseEnv) || env[0] != "FOO=bar" {
		t.Errorf("env should be unchanged on 404, got %v", env)
	}
	if _, err := os.Stat(caPath); !os.IsNotExist(err) {
		t.Errorf("expected no CA file on 404, stat err=%v", err)
	}
}

func TestAugmentEnvWithMITM_Enabled(t *testing.T) {
	const fakePEM = "-----BEGIN CERTIFICATE-----\nMIIFAKE\n-----END CERTIFICATE-----\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write([]byte(fakePEM))
	}))
	defer srv.Close()

	caPath := filepath.Join(t.TempDir(), "mitm-ca.pem")
	env, ok, err := augmentEnvWithMITM(nil, srv.URL, "av_sess_abc", "default", caPath)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true on 200")
	}

	got, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("reading CA file: %v", err)
	}
	if string(got) != fakePEM {
		t.Errorf("CA file contents mismatch:\nwant %q\n got %q", fakePEM, string(got))
	}

	want := map[string]string{
		"HTTP_PROXY":          "", // checked separately below
		"HTTPS_PROXY":         "",
		"NO_PROXY":            "localhost,127.0.0.1",
		"SSL_CERT_FILE":       caPath,
		"NODE_EXTRA_CA_CERTS": caPath,
		"REQUESTS_CA_BUNDLE":  caPath,
		"CURL_CA_BUNDLE":      caPath,
		"GIT_SSL_CAINFO":      caPath,
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

	// Proxy URL must parse cleanly and carry token:vault userinfo.
	proxyURL := vars["HTTPS_PROXY"]
	if proxyURL == "" {
		t.Fatal("HTTPS_PROXY not set")
	}
	if proxyURL != vars["HTTP_PROXY"] {
		t.Errorf("HTTP_PROXY and HTTPS_PROXY should match, got %q vs %q", vars["HTTP_PROXY"], proxyURL)
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
	wantHost := fmt.Sprintf("127.0.0.1:%d", DefaultMITMPort)
	if !strings.HasSuffix(u.Host, fmt.Sprintf(":%d", DefaultMITMPort)) {
		t.Errorf("proxy host = %q, want suffix :%d", u.Host, DefaultMITMPort)
	}
	// httptest servers bind to 127.0.0.1, so the derived host should match.
	if u.Host != wantHost {
		t.Errorf("proxy host = %q, want %q", u.Host, wantHost)
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
