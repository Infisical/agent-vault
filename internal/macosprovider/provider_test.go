package macosprovider

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/acquisition"
)

const testBindingID = "018f47b2-13c4-7abc-8def-0123456789ab"

type commandCall struct {
	path string
	args []string
	env  []string
}

type commandRunnerFunc func(context.Context, string, []string, []string) ([]byte, []byte, error)

func (f commandRunnerFunc) Run(ctx context.Context, path string, args, env []string) ([]byte, []byte, error) {
	return f(ctx, path, args, env)
}

type fakeKeychain struct {
	item KeychainItem
	data []byte
	err  error
}

func (f *fakeKeychain) CopyMatching(_ context.Context, item KeychainItem) ([]byte, error) {
	f.item = item
	return f.data, f.err
}

func TestServeGitHubCLIValidatesHostBeforeTokenAndRedacts(t *testing.T) {
	ghPath := filepath.Join(t.TempDir(), "gh")
	callLog := filepath.Join(t.TempDir(), "gh-calls.log")
	fakeGH := "#!/bin/sh\n" +
		"if [ \"${GH_TOKEN+x}\" = x ]; then echo GH_TOKEN_PRESENT >&2; fi\n" +
		"printf '%s\\n' \"$*\" >> " + callLog + "\n" +
		"if [ \"$2\" = status ]; then printf '{\"hosts\":{\"github.com\":[{\"active\":true,\"host\":\"github.com\",\"login\":\"octocat\",\"state\":\"success\"}]}}'; printf status-diagnostic-sentinel >&2; exit 0; fi\n" +
		"if [ \"$2\" = token ]; then printf 'ghs_provider_sentinel\\n'; printf token-diagnostic-sentinel >&2; exit 0; fi\n" +
		"exit 9\n"
	if err := os.WriteFile(ghPath, []byte(fakeGH), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ghPath, 0o700); err != nil {
		t.Fatal(err)
	}
	var calls []commandCall
	var tokenBytes []byte
	provider := testProvider()
	provider.ghPath = ghPath
	provider.commands = commandRunnerFunc(func(_ context.Context, path string, args, env []string) ([]byte, []byte, error) {
		calls = append(calls, commandCall{path: path, args: append([]string(nil), args...), env: append([]string(nil), env...)})
		stdout, stderr, err := (execCommandRunner{}).Run(context.Background(), path, args, env)
		if len(args) > 1 && args[1] == "token" {
			tokenBytes = stdout
		}
		return stdout, stderr, err
	})
	t.Setenv("GH_TOKEN", "ambient-test-sentinel")
	t.Setenv("GITHUB_TOKEN", "ambient-test-sentinel")
	requestWire := requestWire(t, "github.com", "native")
	var response bytes.Buffer
	if err := provider.Serve(context.Background(), bytes.NewReader(requestWire), &response); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0].path != ghPath || calls[1].path != ghPath ||
		!reflect.DeepEqual(calls[0].args, []string{"auth", "status", "--active", "--hostname", "github.com", "--json", "hosts"}) ||
		!reflect.DeepEqual(calls[1].args, []string{"auth", "token", "--hostname", "github.com", "--user", "octocat"}) {
		t.Fatalf("gh call order/args = %#v", calls)
	}
	wantEnv := []string{"GH_NO_UPDATE_NOTIFIER=1", "HOME=/Users/test", "LANG=C", "PATH=/usr/bin:/bin", "USER=test"}
	for _, call := range calls {
		if !reflect.DeepEqual(call.env, wantEnv) {
			t.Fatalf("unexpected command environment %#v", call.env)
		}
	}
	if !allZero(tokenBytes) {
		t.Fatal("captured token output was not wiped")
	}
	if bytes.Contains(response.Bytes(), []byte("status-output")) || bytes.Contains(response.Bytes(), []byte("diagnostic")) || bytes.Contains(response.Bytes(), []byte("GH_TOKEN_PRESENT")) {
		t.Fatal("provider diagnostics reached protocol output")
	}
	callText, err := os.ReadFile(callLog)
	if err != nil {
		t.Fatal(err)
	}
	if string(callText) != "auth status --active --hostname github.com --json hosts\nauth token --hostname github.com --user octocat\n" {
		t.Fatalf("fake gh invocation log = %q", callText)
	}
	reply, err := acquisition.ReadProviderMessage(&response)
	if err != nil {
		t.Fatal(err)
	}
	got := reply.(acquisition.Reply)
	defer got.Secret.Destroy()
	if !got.Secret.Equal([]byte("ghs_provider_sentinel")) {
		t.Fatal("unexpected secret in AVSH reply")
	}
}

func TestServeGitHubHostMismatchNeverRequestsToken(t *testing.T) {
	provider := testProvider()
	var argsSeen [][]string
	provider.commands = commandRunnerFunc(func(_ context.Context, _ string, args, _ []string) ([]byte, []byte, error) {
		argsSeen = append(argsSeen, append([]string(nil), args...))
		return []byte("private status"), []byte("private diagnostic"), errCommandRejected
	})
	var response bytes.Buffer
	err := provider.Serve(context.Background(), bytes.NewReader(requestWire(t, "github.com", "native")), &response)
	if err == nil || len(argsSeen) != 1 || !reflect.DeepEqual(argsSeen[0], []string{"auth", "status", "--active", "--hostname", "github.com", "--json", "hosts"}) {
		t.Fatalf("Serve err=%v args=%v", err, argsSeen)
	}
	if strings.Contains(err.Error(), "private") || response.Len() != 0 {
		t.Fatalf("error/output leaked provider text: %v %q", err, response.String())
	}
}

func TestServeGitHubRejectsUnhealthyOrAmbiguousActiveAccount(t *testing.T) {
	statuses := []string{
		`{"hosts":{"github.com":[{"active":true,"host":"github.com","login":"octocat","state":"error"}]}}`,
		`{"hosts":{"github.com":[{"active":true,"host":"github.com","login":"one","state":"success"},{"active":true,"host":"github.com","login":"two","state":"success"}]}}`,
		`{"hosts":{"github.example":[{"active":true,"host":"github.example","login":"octocat","state":"success"}]}}`,
		`not-json`,
	}
	for _, status := range statuses {
		provider := testProvider()
		calls := 0
		provider.commands = commandRunnerFunc(func(context.Context, string, []string, []string) ([]byte, []byte, error) {
			calls++
			return []byte(status), nil, nil
		})
		var response bytes.Buffer
		if err := provider.Serve(context.Background(), bytes.NewReader(requestWire(t, "github.com", "native")), &response); err == nil {
			t.Fatalf("status %q was accepted", status)
		}
		if calls != 1 || response.Len() != 0 {
			t.Fatalf("status %q reached token command or emitted output", status)
		}
	}
}

func TestServeRejectsMalformedGitHubTokenAndWipesCapture(t *testing.T) {
	provider := testProvider()
	var captured []byte
	calls := 0
	provider.commands = commandRunnerFunc(func(context.Context, string, []string, []string) ([]byte, []byte, error) {
		calls++
		if calls == 1 {
			return []byte(`{"hosts":{"github.com":[{"active":true,"host":"github.com","login":"octocat","state":"success"}]}}`), nil, nil
		}
		captured = []byte("token-sentinel\nextra\n")
		return captured, nil, nil
	})
	var response bytes.Buffer
	err := provider.Serve(context.Background(), bytes.NewReader(requestWire(t, "github.com", "native")), &response)
	if err == nil || calls != 2 || response.Len() != 0 || !allZero(captured) {
		t.Fatalf("Serve err=%v calls=%d response=%q captured_wiped=%v", err, calls, response.String(), allZero(captured))
	}
}

func TestServeRejectsUnknownProfileAndUnsupportedModesBeforeProvider(t *testing.T) {
	for _, tc := range []struct{ profile, mode string }{{"evil.example", "native"}, {"github.com", "guided"}, {"github.com", "oauth"}, {"github.com", "device"}, {"github.com", "server_passthrough"}} {
		provider := testProvider()
		provider.commands = commandRunnerFunc(func(context.Context, string, []string, []string) ([]byte, []byte, error) {
			t.Fatal("unsupported request reached GitHub CLI")
			return nil, nil, nil
		})
		provider.keychain = &fakeKeychain{}
		var response bytes.Buffer
		if err := provider.Serve(context.Background(), bytes.NewReader(requestWire(t, tc.profile, tc.mode)), &response); err == nil {
			t.Fatalf("profile=%q mode=%q was accepted", tc.profile, tc.mode)
		}
		if response.Len() != 0 {
			t.Fatalf("profile=%q mode=%q emitted a response", tc.profile, tc.mode)
		}
	}
}

func TestServeKeychainUsesExactCompiledRecipeAndWipesBytes(t *testing.T) {
	provider := testProvider()
	secret := []byte("keychain_provider_sentinel")
	fake := &fakeKeychain{data: secret}
	provider.keychain = fake
	var response bytes.Buffer
	if err := provider.Serve(context.Background(), bytes.NewReader(requestWire(t, "agent-vault-local", "native")), &response); err != nil {
		t.Fatal(err)
	}
	want := KeychainItem{Service: "agent-vault", Account: "credential", AllowUserInteraction: true}
	if !reflect.DeepEqual(fake.item, want) {
		t.Fatalf("keychain query = %#v, want %#v", fake.item, want)
	}
	if !allZero(secret) {
		t.Fatal("keychain result bytes were not wiped")
	}
	reply, err := acquisition.ReadProviderMessage(&response)
	if err != nil {
		t.Fatal(err)
	}
	got := reply.(acquisition.Reply)
	defer got.Secret.Destroy()
	if !got.Secret.Equal([]byte("keychain_provider_sentinel")) {
		t.Fatal("unexpected keychain secret")
	}
}

func TestServeKeychainFailureDoesNotLeakError(t *testing.T) {
	provider := testProvider()
	provider.keychain = &fakeKeychain{err: errWithText("keychain private sentinel")}
	var response bytes.Buffer
	err := provider.Serve(context.Background(), bytes.NewReader(requestWire(t, "agent-vault-local", "native")), &response)
	if err == nil || strings.Contains(err.Error(), "private sentinel") || response.Len() != 0 {
		t.Fatalf("Serve err=%v response=%q", err, response.String())
	}
}

func TestServeRejectsUnexpectedRequestParams(t *testing.T) {
	provider := testProvider()
	var wire bytes.Buffer
	frame, err := acquisition.EncodeFrame(acquisition.Request{
		Kind: acquisition.MessageRequest, Ticket: bytes.Repeat([]byte{1}, acquisition.TicketBytes),
		ResourceID: "GITHUB_TOKEN", Params: map[string]string{"mode": "native", "profile": "github.com", "command": "security"},
		ContextBindingID: testBindingID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer frame.Destroy()
	if err := acquisition.WriteProviderFrame(&wire, frame); err != nil {
		t.Fatal(err)
	}
	provider.commands = commandRunnerFunc(func(context.Context, string, []string, []string) ([]byte, []byte, error) {
		t.Fatal("unexpected params reached provider")
		return nil, nil, nil
	})
	if err := provider.Serve(context.Background(), &wire, io.Discard); err == nil {
		t.Fatal("unexpected provider params accepted")
	}
}

var errCommandRejected = errWithText("private command diagnostic")

type textError string

func (e textError) Error() string    { return string(e) }
func errWithText(value string) error { return textError(value) }

func requestWire(t *testing.T, profile, mode string) []byte {
	t.Helper()
	var wire bytes.Buffer
	err := acquisition.WriteProviderRequest(&wire, acquisition.Request{
		Kind: acquisition.MessageRequest, Ticket: bytes.Repeat([]byte{0x6b}, acquisition.TicketBytes),
		ResourceID: "GITHUB_TOKEN", Params: map[string]string{"mode": mode, "profile": profile}, ContextBindingID: testBindingID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return wire.Bytes()
}

func testProvider() *Provider {
	return &Provider{ghPath: "/opt/homebrew/bin/gh", now: func() time.Time { return time.Unix(1, 0) }, home: "/Users/test", user: "test"}
}

func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}
