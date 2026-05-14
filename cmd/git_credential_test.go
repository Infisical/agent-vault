package cmd

import (
	"strings"
	"testing"
)

func TestParseGitCredentialRequest(t *testing.T) {
	req, err := parseGitCredentialRequest(strings.NewReader("protocol=https\nhost=github.com\npath=owner/repo.git\nusername=ignored\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if req.Protocol != "https" || req.Host != "github.com" || req.Path != "owner/repo.git" || req.Username != "ignored" {
		t.Fatalf("unexpected request: %+v", req)
	}
}

func TestGitCredentialHelperGetReturnsOnlySentinelCredentials(t *testing.T) {
	var out strings.Builder
	err := runGitCredentialHelper(strings.NewReader("protocol=https\nhost=github.com\npath=owner/repo.git\n\n"), &out, "get")
	if err != nil {
		t.Fatal(err)
	}
	got := out.String()
	wantPasswordLine := "password=" + gitCredentialPassword() + "\n"
	if !strings.Contains(got, "username=agent-vault\n") || !strings.Contains(got, wantPasswordLine) {
		t.Fatalf("expected sentinel credentials, got %q", got)
	}
	if strings.Contains(got, "real-upstream-credential") || strings.Contains(got, "vault-secret-value") {
		t.Fatalf("helper output contains secret material: %q", got)
	}
}

func TestGitCredentialHelperIgnoresUnsupportedProtocolsAndHosts(t *testing.T) {
	cases := []string{
		"protocol=http\nhost=github.com\n\n",
		"protocol=https\nhost=localhost\n\n",
		"protocol=https\nhost=127.0.0.1\n\n",
		"protocol=https\nhost=bad host\n\n",
	}
	for _, input := range cases {
		var out strings.Builder
		if err := runGitCredentialHelper(strings.NewReader(input), &out, "get"); err != nil {
			t.Fatalf("input %q: %v", input, err)
		}
		if out.String() != "" {
			t.Fatalf("input %q: expected no output, got %q", input, out.String())
		}
	}
}

func TestGitCredentialHelperStoreEraseAreNoops(t *testing.T) {
	for _, op := range []string{"store", "erase"} {
		var out strings.Builder
		if err := runGitCredentialHelper(strings.NewReader("protocol=https\nhost=github.com\n\n"), &out, op); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if out.String() != "" {
			t.Fatalf("%s: expected no output, got %q", op, out.String())
		}
	}
}

func TestGitConfigEnvDoesNotIncludeSecrets(t *testing.T) {
	env := gitConfigEnv([]string{
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=credential.helper",
		"GIT_CONFIG_VALUE_0=example-helper-value",
		"OTHER=ok",
	}, "/bin/agent-vault", "/tmp/ca.pem")
	joined := strings.Join(env, "\n")
	for _, forbidden := range []string{"example-helper-value", "real-upstream-credential", "vault-secret-value"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("git env leaked forbidden value %q in %s", forbidden, joined)
		}
	}
	for _, required := range []string{"GIT_TERMINAL_PROMPT=0", "credential.helper", "!/bin/agent-vault git-credential", "http.sslCAInfo", "/tmp/ca.pem", "OTHER=ok"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("git env missing %q in %s", required, joined)
		}
	}
}
