package proposal

import (
	"encoding/json"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
)

func TestExplicitFilterRejected(t *testing.T) {
	raw := json.RawMessage(`[{"action":"set","name":"gh","host":"github.com","filter":{"url":"http://127.0.0.1:9"}}]`)
	i, ok := ExplicitFilterIndex(raw)
	if !ok || i != 0 {
		t.Fatalf("index=%d ok=%v", i, ok)
	}
}

func TestFilterPolicyDeleteAndShadow(t *testing.T) {
	existing := []broker.Service{{
		Name:   "push",
		Host:   "github.com",
		Path:   "/*/git-receive-pack",
		Filter: &broker.Filter{URL: "http://127.0.0.1:9"},
		Auth:   broker.Auth{Type: "bearer", Token: "GITHUB_PAT"},
	}}
	if err := CheckFilterPolicy(existing, []Service{{Action: ActionDelete, Name: "push"}}); err == nil {
		t.Fatal("deleting a filtered service should fail")
	}
	overlap := []Service{{
		Action: ActionSet,
		Name:   "open-push",
		Host:   "github.com",
		Path:   "/*/git-receive-pack",
		Auth:   &broker.Auth{Type: "passthrough"},
	}}
	if err := CheckFilterPolicy(existing, overlap); err == nil {
		t.Fatal("overlapping unfiltered matcher should fail")
	}
	disjoint := []Service{{
		Action: ActionSet,
		Name:   "gitlab",
		Host:   "gitlab.com",
		Auth:   &broker.Auth{Type: "passthrough"},
	}}
	if err := CheckFilterPolicy(existing, disjoint); err != nil {
		t.Fatal(err)
	}
	preserve := []Service{{
		Action: ActionSet,
		Name:   "push",
		Host:   "github.com",
		Path:   "/*/git-receive-pack",
		Auth:   &broker.Auth{Type: "bearer", Token: "GITHUB_PAT"},
	}}
	if err := CheckFilterPolicy(existing, preserve); err != nil {
		t.Fatal(err)
	}
	merged, _ := MergeServices(existing, preserve)
	if len(merged) != 1 || merged[0].Filter == nil {
		t.Fatalf("filter not preserved: %+v", merged)
	}
	narrow := []Service{{
		Action: ActionSet,
		Name:   "push",
		Host:   "github.com",
		Path:   "/nonexistent-org/*",
		Auth:   &broker.Auth{Type: "bearer", Token: "GITHUB_PAT"},
	}}
	if err := CheckFilterPolicy(existing, narrow); err == nil {
		t.Fatal("narrowing a filtered matcher should fail")
	}
	port := 443
	withPort := []Service{{
		Action: ActionSet,
		Name:   "push",
		Host:   "github.com",
		Path:   "/*/git-receive-pack",
		Port:   &port,
		Auth:   &broker.Auth{Type: "bearer", Token: "GITHUB_PAT"},
	}}
	if err := CheckFilterPolicy(existing, withPort); err == nil {
		t.Fatal("changing the port of a filtered service should fail")
	}
}
