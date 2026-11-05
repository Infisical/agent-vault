package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/session"
	"github.com/spf13/cobra"
)

const cliStdinSentinel = "CLI_STDIN_SENTINEL_7d31"

func TestCredentialSetStdinSendsExactlyOneNamedCredential(t *testing.T) {
	resetCredentialStdinFlags(t)
	t.Setenv("HOME", t.TempDir())
	received := make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		received <- body
		_, _ = io.WriteString(w, `{"set":["DB_PASSWORD"]}`)
	}))
	defer srv.Close()
	if err := session.Save(&session.ClientSession{Token: "owner-token", Address: srv.URL}); err != nil {
		t.Fatal(err)
	}
	rootCmd.SetIn(strings.NewReader(cliStdinSentinel + "\n"))
	t.Cleanup(func() { rootCmd.SetIn(nil) })
	output, err := executeCommand("vault", "credential", "set", "--stdin", "DB_PASSWORD", "--vault", "default")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output, cliStdinSentinel) {
		t.Fatal("credential leaked to command output")
	}
	body := <-received
	credentials, ok := body["credentials"].(map[string]any)
	if !ok || len(credentials) != 1 || credentials["DB_PASSWORD"] != cliStdinSentinel {
		t.Fatalf("credentials=%#v", body["credentials"])
	}
}

func TestCredentialSetStdinRejectsPositionalAndEmptyValues(t *testing.T) {
	resetCredentialStdinFlags(t)
	t.Setenv("HOME", t.TempDir())
	if err := session.Save(&session.ClientSession{Token: "owner-token", Address: "http://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	rootCmd.SetIn(strings.NewReader(""))
	t.Cleanup(func() { rootCmd.SetIn(nil) })
	if _, err := executeCommand("vault", "credential", "set", "KEY=value", "--stdin", "OTHER"); err == nil {
		t.Fatal("expected positional/stdin conflict")
	}
	if _, err := executeCommand("vault", "credential", "set", "--stdin", "EMPTY"); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty stdin error=%v", err)
	}
}

func TestProposalApproveCredentialStdin(t *testing.T) {
	resetCredentialStdinFlags(t)
	t.Setenv("HOME", t.TempDir())
	received := make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/admin/proposals/9":
			_, _ = io.WriteString(w, `{"id":9,"status":"pending","message":"stdin approval","services_json":"[]","credentials_json":"[{\"action\":\"set\",\"key\":\"API_TOKEN\",\"type\":\"static\"},{\"action\":\"set\",\"key\":\"OTHER_TOKEN\",\"type\":\"static\"}]","created_at":"2026-09-24T00:00:00Z"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/admin/proposals/9/approve":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode approve: %v", err)
			}
			received <- body
			_, _ = io.WriteString(w, `{}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	if err := session.Save(&session.ClientSession{Token: "reviewer-token", Address: srv.URL}); err != nil {
		t.Fatal(err)
	}
	rootCmd.SetIn(strings.NewReader(cliStdinSentinel + "\n"))
	t.Cleanup(func() { rootCmd.SetIn(nil) })
	output, err := executeCommand("vault", "proposal", "approve", "9", "--yes", "--credential-stdin", "API_TOKEN", "--vault", "default")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output, cliStdinSentinel) {
		t.Fatal("credential leaked to command output")
	}
	body := <-received
	credentials, ok := body["credentials"].(map[string]any)
	if !ok || len(credentials) != 1 || credentials["API_TOKEN"] != cliStdinSentinel {
		t.Fatalf("credentials=%#v", body["credentials"])
	}
}

func TestReadCredentialStdinBoundsAndLineEnding(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("two\nlines\r\n"))
	value, err := readCredentialStdin(cmd, "TOKEN")
	if err != nil || value != "two\nlines" {
		t.Fatalf("value=%q err=%v", value, err)
	}
	cmd.SetIn(strings.NewReader(strings.Repeat("x", maxCredentialStdinBytes+1)))
	if _, err := readCredentialStdin(cmd, "TOKEN"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized error=%v", err)
	}
	cmd.SetIn(strings.NewReader("ends-with-cr\r"))
	value, err = readCredentialStdin(cmd, "TOKEN")
	if err != nil || value != "ends-with-cr\r" {
		t.Fatalf("lone CR value=%q err=%v", value, err)
	}
}

type partialCredentialErrorReader struct{ sent bool }

func (r *partialCredentialErrorReader) Read(p []byte) (int, error) {
	if r.sent {
		return 0, io.EOF
	}
	r.sent = true
	return copy(p, cliStdinSentinel), errors.New("synthetic read failure")
}

func TestReadCredentialStdinRejectsPartialReadErrorsWithoutEchoingData(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetIn(&partialCredentialErrorReader{})
	_, err := readCredentialStdin(cmd, "TOKEN")
	if err == nil || !strings.Contains(err.Error(), "synthetic read failure") || strings.Contains(err.Error(), cliStdinSentinel) {
		t.Fatalf("partial read error=%v", err)
	}
}

func TestReadCredentialStdinRejectsTerminalInput(t *testing.T) {
	old := credentialStdinIsTerminal
	credentialStdinIsTerminal = func(io.Reader) bool { return true }
	t.Cleanup(func() { credentialStdinIsTerminal = old })
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader(cliStdinSentinel))
	if _, err := readCredentialStdin(cmd, "TOKEN"); err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Fatalf("terminal stdin error=%v", err)
	}
}

func TestProposalApproveCredentialStdinRequiresNonInteractiveExclusiveUse(t *testing.T) {
	resetCredentialStdinFlags(t)
	if _, err := executeCommand("vault", "proposal", "approve", "1", "TOKEN=value", "--credential-stdin", "TOKEN"); err == nil {
		t.Fatal("expected positional/stdin conflict")
	}
	if _, err := executeCommand("vault", "proposal", "approve", "1", "--credential-stdin", "TOKEN"); err == nil || !strings.Contains(err.Error(), "requires --yes") {
		t.Fatalf("missing --yes error=%v", err)
	}
}

func TestProposalApproveHelpWarnsAboutArgvCredentials(t *testing.T) {
	if !strings.Contains(proposalApproveCmd.Long, "process table") || !strings.Contains(proposalApproveCmd.Long, "--credential-stdin") {
		t.Fatalf("approve help does not explain secure stdin alternative: %q", proposalApproveCmd.Long)
	}
}

func resetCredentialStdinFlags(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		rootCmd.SetIn(nil)
		_ = credentialSetCmd.Flags().Set("stdin", "")
		credentialSetCmd.Flags().Lookup("stdin").Changed = false
		_ = proposalApproveCmd.Flags().Set("credential-stdin", "")
		proposalApproveCmd.Flags().Lookup("credential-stdin").Changed = false
		_ = proposalApproveCmd.Flags().Set("yes", "false")
		proposalApproveCmd.Flags().Lookup("yes").Changed = false
	})
}
