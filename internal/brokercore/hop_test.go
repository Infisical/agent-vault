package brokercore

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/store"
)

type memVaults struct {
	byName map[string]*store.Vault
	byID   map[string]*store.Vault
}

func (m memVaults) GetVault(_ context.Context, name string) (*store.Vault, error) {
	return m.byName[name], nil
}
func (m memVaults) GetVaultByID(_ context.Context, id string) (*store.Vault, error) {
	return m.byID[id], nil
}

func testVaults() memVaults {
	dev := &store.Vault{ID: "vault-dev", Name: "dev"}
	return memVaults{byName: map[string]*store.Vault{"dev": dev}, byID: map[string]*store.Vault{"vault-dev": dev}}
}

func testService() broker.Service {
	return broker.Service{
		Name: "push",
		Host: "github.com",
		Path: "/*/git-receive-pack",
		Auth: broker.Auth{Type: "bearer", Token: "GITHUB_PAT"},
	}
}

func TestHopJWTRoundTripAndFailures(t *testing.T) {
	dek := make32(0x42)
	now := time.Unix(1_700_000_000, 0)
	minter := &StoreHopMinter{Vaults: testVaults(), DEK: dek, Now: func() time.Time { return now }}
	cont, pol, err := minter.Mint(context.Background(), HopMintInput{
		SourceVaultID: "vault-dev",
		ActorID:       "agent-1",
		Bind:          HopBind{Method: "POST", Scheme: "https", Authority: "github.com:443", Path: "/org/repo/git-receive-pack", Query: "a=b"},
		Service:       testService(),
		PolicyVault:   "dev",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cont, PrefixContinuation) || !strings.HasPrefix(pol, PrefixPolicy) {
		t.Fatalf("prefixes cont=%q pol=%q", cont, pol)
	}
	got, err := VerifyHopToken(context.Background(), testVaults(), dek, cont, now.Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got.Frozen == nil || got.Frozen.Auth.Token != "GITHUB_PAT" || got.Frozen.Host != "github.com" {
		t.Fatalf("frozen = %+v", got.Frozen)
	}
	if got.Kind != "cont" || got.ActorID != "agent-1" {
		t.Fatalf("claims = %+v", got)
	}

	omitted, policy, err := minter.Mint(context.Background(), HopMintInput{
		SourceVaultID: "vault-dev",
		ActorID:       "agent-1",
		Bind:          HopBind{Method: "GET", Scheme: "https", Authority: "github.com:443", Path: "/"},
		Service:       testService(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if policy != "" {
		t.Fatal("omitted policy_vault minted a policy token")
	}
	if _, err := VerifyHopToken(context.Background(), testVaults(), dek, omitted, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyHopToken(context.Background(), testVaults(), dek, cont+"tamper", now); err == nil {
		t.Fatal("bad signature should fail")
	}
	if _, err := VerifyHopToken(context.Background(), testVaults(), dek, cont, now.Add(31*time.Second)); err == nil {
		t.Fatal("expired token should fail")
	}
	gone := testVaults()
	delete(gone.byID, "vault-dev")
	if _, err := VerifyHopToken(context.Background(), gone, dek, cont, now); err == nil {
		t.Fatal("deleted vault should fail closed")
	}

	polTok, err := VerifyHopToken(context.Background(), testVaults(), dek, pol, now)
	if err != nil {
		t.Fatal(err)
	}
	if polTok.Frozen != nil || polTok.Vault.ID != "vault-dev" {
		t.Fatalf("policy token = %+v", polTok)
	}

	// A second verify before exp still succeeds. There is no consume step.
	if _, err := VerifyHopToken(context.Background(), testVaults(), dek, cont, now.Add(20*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestEncodedSlashBindIsByteForByte(t *testing.T) {
	b := HopBind{Method: "GET", Scheme: "https", Authority: "github.com:443", Path: "/a%2Fb", Query: "q=1%2F2"}
	if !b.Matches("GET", "https", "github.com:443", "/a%2Fb", "q=1%2F2") {
		t.Fatal("escaped path should match")
	}
	if b.Matches("GET", "https", "github.com:443", "/a/b", "q=1%2F2") {
		t.Fatal("decoded slash must not match the escaped bind")
	}
}

func TestThawUnknownVersionBeforeCredentialUse(t *testing.T) {
	if _, err := ThawMatch(json.RawMessage(`{"v":99,"name":"push","host":"github.com","auth":{"type":"bearer","token":"GITHUB_PAT"}}`)); err == nil {
		t.Fatal("unknown match version should fail")
	}
}

func TestMatchDoesNotReadCredentialsForFilter(t *testing.T) {
	key32 := make32(0x11)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Name:   "push",
		Host:   "github.com",
		Auth:   broker.Auth{Type: "bearer", Token: "GITHUB_PAT"},
		Filter: &broker.Filter{URL: "http://127.0.0.1:9"},
	}})
	f.setCred(t, key32, "v1", "GITHUB_PAT", "s3cret")
	p := NewStoreCredentialProvider(f, key32)
	before := f.getCredentialCalls
	matched, err := p.Match(context.Background(), "v1", "github.com", 443, "/org/repo/git-receive-pack")
	if err != nil {
		t.Fatal(err)
	}
	if matched.Service.Filter == nil {
		t.Fatal("expected a filter match")
	}
	if f.getCredentialCalls != before {
		t.Fatalf("match read credentials %d times", f.getCredentialCalls-before)
	}
	res, err := p.Resolve(context.Background(), "v1", matched.Service)
	if err != nil {
		t.Fatal(err)
	}
	if res.Headers["Authorization"] != "Bearer s3cret" {
		t.Fatalf("headers = %v", res.Headers)
	}
}

func TestResolveUsesUpdatedValueAndFailsClosedOnDelete(t *testing.T) {
	key32 := make32(0x11)
	f := newFakeCredStore()
	svc := broker.Service{Name: "push", Host: "github.com", Auth: broker.Auth{Type: "bearer", Token: "GITHUB_PAT"}}
	f.setServices(t, "v1", []broker.Service{svc})
	f.setCred(t, key32, "v1", "GITHUB_PAT", "old")
	p := NewStoreCredentialProvider(f, key32)
	f.setCred(t, key32, "v1", "GITHUB_PAT", "new")
	res, err := p.Resolve(context.Background(), "v1", svc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Headers["Authorization"] != "Bearer new" {
		t.Fatalf("got %v", res.Headers)
	}
	delete(f.creds, "v1|GITHUB_PAT")
	if _, err := p.Resolve(context.Background(), "v1", svc); err == nil {
		t.Fatal("deleted key should fail closed")
	}
}

func TestFrozenHostDoesNotRetarget(t *testing.T) {
	key32 := make32(0x11)
	f := newFakeCredStore()
	live := broker.Service{Name: "push", Host: "evil.example", Auth: broker.Auth{Type: "bearer", Token: "OTHER"}}
	f.setServices(t, "v1", []broker.Service{live})
	f.setCred(t, key32, "v1", "GITHUB_PAT", "pat")
	f.setCred(t, key32, "v1", "OTHER", "nope")
	frozen := broker.Service{Name: "push", Host: "github.com", Auth: broker.Auth{Type: "bearer", Token: "GITHUB_PAT"}}
	p := NewStoreCredentialProvider(f, key32)
	res, err := p.Resolve(context.Background(), "v1", frozen)
	if err != nil {
		t.Fatal(err)
	}
	if res.Headers["Authorization"] != "Bearer pat" || res.MatchedHost != "github.com" {
		t.Fatalf("result = %+v", res)
	}
}

func TestMatchErrorDoesNotResolve(t *testing.T) {
	f := newFakeCredStore()
	f.brokerCfgErr = errBoom
	f.policy = PolicyDeny
	p := NewStoreCredentialProvider(f, make32(0x11))
	if _, err := p.Match(context.Background(), "v1", "github.com", 443, "/"); err == nil {
		t.Fatal("store error should fail match")
	}
	if f.getCredentialCalls != 0 {
		t.Fatal("match error resolved a credential")
	}
}

var errBoom = errString("boom")

type errString string

func (e errString) Error() string { return string(e) }

func TestHopTokenLogOmitsSecrets(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ev := ProxyEvent{
		MatchedService: "push",
		CredentialKeys: []string{"GITHUB_PAT"},
		InvocationID:   "abc",
	}
	ev.Emit(logger, time.Now(), 200, "")
	line := buf.String()
	if strings.Contains(line, "av_cont_") || strings.Contains(line, "s3cret") {
		t.Fatalf("log leaked secret material: %s", line)
	}
	if !strings.Contains(line, "invocation_id=abc") || !strings.Contains(line, "GITHUB_PAT") {
		t.Fatalf("log = %s", line)
	}
}
