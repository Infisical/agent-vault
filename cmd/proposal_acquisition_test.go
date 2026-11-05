package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/session"
)

func TestProposalAcquisitionCommandsAndFlags(t *testing.T) {
	proposal := findSubcommand(findSubcommand(rootCmd, "vault"), "proposal")
	if proposal == nil {
		t.Fatal("vault proposal command not found")
	}
	for _, name := range []string{"acquire", "acquisition-status", "acquisition-cancel"} {
		if findSubcommand(proposal, name) == nil {
			t.Errorf("expected proposal subcommand %q", name)
		}
	}
	acquire := findSubcommand(proposal, "acquire")
	if acquire != nil {
		for _, name := range []string{"handler", "profile"} {
			if acquire.Flags().Lookup(name) == nil {
				t.Errorf("expected acquire flag --%s", name)
			}
		}
	}
}

func TestProposalAcquisitionCLIUsesSafeControlPlaneEndpoints(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	requests := make(chan struct {
		method string
		path   string
		query  url.Values
		body   map[string]string
	}, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer reviewer-token" {
			t.Errorf("authorization=%q", got)
		}
		body := make(map[string]string)
		if r.Body != nil {
			raw, _ := io.ReadAll(r.Body)
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &body); err != nil {
					t.Errorf("decode request body: %v", err)
				}
			}
		}
		requests <- struct {
			method string
			path   string
			query  url.Values
			body   map[string]string
		}{r.Method, r.URL.Path, r.URL.Query(), body}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && r.URL.Query().Get("key") == "" {
			_, _ = io.WriteString(w, `{"acquisitions":[{"id":"job-1","proposal_id":7,"key":"GITHUB_TOKEN","attempt":1,"handler_id":"github-cli","profile":"github.com","mode":"native","state":"running","created_at":"2026-09-24T00:00:00Z","updated_at":"2026-09-24T00:00:00Z"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"id":"job-1","proposal_id":7,"key":"GITHUB_TOKEN","attempt":1,"handler_id":"github-cli","profile":"github.com","mode":"native","state":"running","created_at":"2026-09-24T00:00:00Z","updated_at":"2026-09-24T00:00:00Z"}`)
	}))
	defer srv.Close()
	if err := session.Save(&session.ClientSession{Token: "reviewer-token", Address: srv.URL}); err != nil {
		t.Fatal(err)
	}

	commands := [][]string{
		{"vault", "proposal", "acquire", "7", "GITHUB_TOKEN", "--handler", "github-cli", "--profile", "github.com", "--vault", "default"},
		{"vault", "proposal", "acquisition-status", "7", "GITHUB_TOKEN", "--vault", "default"},
		{"vault", "proposal", "acquisition-status", "7", "--vault", "default"},
		{"vault", "proposal", "acquisition-cancel", "7", "GITHUB_TOKEN", "--vault", "default"},
	}
	for _, args := range commands {
		if output, err := executeCommand(args...); err != nil {
			t.Fatalf("%v: %v output=%s", args, err, output)
		}
	}

	close(requests)
	var got []struct {
		method string
		path   string
		query  url.Values
		body   map[string]string
	}
	for request := range requests {
		got = append(got, request)
	}
	if len(got) != 4 {
		t.Fatalf("requests=%d want=4", len(got))
	}
	if got[0].method != http.MethodPost || got[0].path != "/v1/admin/proposals/7/acquisitions/GITHUB_TOKEN/start" ||
		got[0].body["vault"] != "default" || got[0].body["handler"] != "github-cli" || got[0].body["profile"] != "github.com" {
		t.Fatalf("start request=%+v", got[0])
	}
	if got[1].method != http.MethodGet || got[1].query.Get("vault") != "default" || got[1].query.Get("key") != "GITHUB_TOKEN" {
		t.Fatalf("key status request=%+v", got[1])
	}
	if got[2].method != http.MethodGet || got[2].query.Get("vault") != "default" || got[2].query.Get("key") != "" {
		t.Fatalf("list status request=%+v", got[2])
	}
	if got[3].method != http.MethodPost || !strings.HasSuffix(got[3].path, "/cancel") || got[3].body["vault"] != "default" {
		t.Fatalf("cancel request=%+v", got[3])
	}
}
