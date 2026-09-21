package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

func proposalJSONTestCommand(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.Flags().String("message", "", "")
	cmd.Flags().String("user-message", "", "")
	cmd.Flags().String("context-binding-id", "", "")
	return cmd
}

func TestBuildFromJSONPreservesContextBindingWithMessageOverride(t *testing.T) {
	cmd := proposalJSONTestCommand(t)
	if err := cmd.Flags().Set("message", "overridden"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "proposal.json")
	input := `{
		"credentials":[{"action":"set","key":"TOKEN","acquisition":{"handler":"provider","profile":"default","mode":"native"}}],
		"context_binding":{"context_binding_id":"av_ctx_01JQ6T9J2WR8MVB7F2K4N6P8RA"},
		"message":"original"
	}`
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	encoded, err := buildFromJSON(cmd, path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded proposalCreateRequest
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Message != "overridden" {
		t.Fatalf("message=%q", decoded.Message)
	}
	if decoded.ContextBinding == nil || decoded.ContextBinding.ContextBindingID != "av_ctx_01JQ6T9J2WR8MVB7F2K4N6P8RA" {
		t.Fatalf("context binding lost during override: %+v", decoded.ContextBinding)
	}
}

func TestBuildFromJSONRejectsInvalidContextBindingFlag(t *testing.T) {
	cmd := proposalJSONTestCommand(t)
	if err := cmd.Flags().Set("context-binding-id", "../override"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "proposal.json")
	if err := os.WriteFile(path, []byte(`{"credentials":[{"action":"set","key":"TOKEN"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildFromJSON(cmd, path); err == nil {
		t.Fatal("expected invalid context binding flag to be rejected")
	}
}

func TestParseAndDisplayProposalContextBinding(t *testing.T) {
	proposal, err := parseProposalJSON([]byte(`{
		"id":1,
		"status":"pending",
		"services_json":"[]",
		"credentials_json":"[]",
		"context_binding_id":"av_ctx_01JQ6T9J2WR8MVB7F2K4N6P8RA",
		"created_at":"2026-09-21T00:00:00Z"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if proposal.ContextBindingID == nil || *proposal.ContextBindingID != "av_ctx_01JQ6T9J2WR8MVB7F2K4N6P8RA" {
		t.Fatalf("parsed proposal lost context binding: %+v", proposal)
	}
	var output bytes.Buffer
	displayProposal(&output, proposal)
	if !bytes.Contains(output.Bytes(), []byte("av_ctx_01JQ6T9J2WR8MVB7F2K4N6P8RA")) {
		t.Fatalf("display omitted context binding: %s", output.String())
	}
}
