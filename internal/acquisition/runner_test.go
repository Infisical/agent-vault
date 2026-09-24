//go:build (darwin || linux) && cgo

package acquisition

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
	"golang.org/x/sys/unix"
)

const (
	runnerFixtureSecret   = "RUNNER_SENTINEL_SECRET_7f86e19a"
	runnerFixtureContext  = "av_ctx_01JQ6T9J2WR8MVB7F2K4N6P8RA"
	runnerFixtureResource = "TEST_TOKEN"
)

func TestMain(m *testing.M) {
	if os.Getenv("AVSH_TICKET_FD") == "3" {
		os.Exit(runProviderFixture(3))
	}
	os.Exit(m.Run())
}

func TestRunProviderSuccessUsesPreparedSpawnContract(t *testing.T) {
	handler := runnerTestHandler(t)
	result, err := runTestProvider(context.Background(), handler, ProviderInvocation{
		VaultID:          "test-vault",
		ResourceID:       runnerFixtureResource,
		Profile:          "default",
		ContextBindingID: runnerFixtureContext,
		Params:           map[string]string{"fixture_mode": "contract"},
	})
	if err != nil {
		t.Fatalf("RunProvider: %v", err)
	}
	defer result.Secret.Destroy()
	if !result.Secret.Equal([]byte(runnerFixtureSecret)) {
		t.Fatal("provider secret mismatch")
	}
	if result.Meta.Source != "test_fixture" || result.Meta.TTLSeconds != 3600 {
		t.Fatalf("metadata=%+v", result.Meta)
	}
}

func TestRunProviderRejectsRegistryAndInvocationPolicyBeforeSpawn(t *testing.T) {
	base := runnerTestHandler(t)
	tests := []struct {
		name string
		edit func(*store.AcquisitionHandler, *ProviderInvocation)
		code string
	}{
		{"disabled", func(h *store.AcquisitionHandler, _ *ProviderInvocation) { h.Enabled = false }, "handler_disabled"},
		{"key", func(_ *store.AcquisitionHandler, i *ProviderInvocation) { i.ResourceID = "OTHER_TOKEN" }, "handler_not_allowed"},
		{"vault", func(_ *store.AcquisitionHandler, i *ProviderInvocation) { i.VaultID = "other-vault" }, "handler_not_allowed"},
		{"profile", func(_ *store.AcquisitionHandler, i *ProviderInvocation) { i.Profile = "other" }, "handler_not_allowed"},
		{"context", func(_ *store.AcquisitionHandler, i *ProviderInvocation) { i.ContextBindingID = "wrong" }, "invalid_invocation"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := base
			invocation := ProviderInvocation{
				VaultID: "test-vault", ResourceID: runnerFixtureResource, Profile: "default",
				ContextBindingID: runnerFixtureContext,
			}
			tt.edit(&handler, &invocation)
			_, err := runTestProvider(context.Background(), handler, invocation)
			if got := ProviderErrorCode(err); got != tt.code {
				t.Fatalf("code=%q error=%v", got, err)
			}
		})
	}
}

func TestRunProviderFailsClosedOnProviderViolations(t *testing.T) {
	tests := []struct {
		mode    string
		code    string
		timeout int
		limit   int
	}{
		{"wrong_ticket", "ticket_mismatch", 3, 4096},
		{"wrong_context", "context_binding_mismatch", 3, 4096},
		{"malformed", "protocol_violation", 3, 4096},
		{"oversized", "protocol_violation", 3, 4096},
		{"progress_overflow", "progress_limit", 3, 4096},
		{"ancillary_data", "protocol_violation", 3, 4096},
		{"trailing_output", "protocol_violation", 3, 4096},
		{"exit_nonzero", "provider_error", 3, 4096},
		{"timeout", "provider_timeout", 1, 4096},
		{"stderr_overflow", "output_limit", 3, 1024},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			handler := runnerTestHandler(t)
			handler.TimeoutSeconds = tt.timeout
			handler.OutputLimitBytes = tt.limit
			_, err := runTestProvider(context.Background(), handler, ProviderInvocation{
				VaultID: "test-vault", ResourceID: runnerFixtureResource, Profile: "default",
				ContextBindingID: runnerFixtureContext,
				Params:           map[string]string{"fixture_mode": tt.mode},
			})
			if got := ProviderErrorCode(err); got != tt.code {
				t.Fatalf("code=%q want=%q error=%v", got, tt.code, err)
			}
			if err != nil && strings.Contains(err.Error(), runnerFixtureSecret) {
				t.Fatalf("error leaked sentinel: %v", err)
			}
		})
	}
}

func TestRunProviderDiscardsStderrAndHonorsCancellation(t *testing.T) {
	handler := runnerTestHandler(t)
	result, err := runTestProvider(context.Background(), handler, ProviderInvocation{
		VaultID: "test-vault", ResourceID: runnerFixtureResource, Profile: "default",
		ContextBindingID: runnerFixtureContext,
		Params:           map[string]string{"fixture_mode": "stderr_secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	result.Secret.Destroy()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = runTestProvider(ctx, handler, ProviderInvocation{
		VaultID: "test-vault", ResourceID: runnerFixtureResource, Profile: "default",
		ContextBindingID: runnerFixtureContext,
		Params:           map[string]string{"fixture_mode": "timeout"},
	})
	if got := ProviderErrorCode(err); got != "cancelled" {
		t.Fatalf("code=%q error=%v", got, err)
	}
}

func TestRunPreparedProviderCancellationWinsBeforeSpawn(t *testing.T) {
	handler := runnerTestHandler(t)
	prepared, err := PrepareExecutable(context.Background(), handler)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if err := os.Chmod(prepared.Path(), 0o600); err != nil {
		t.Fatal(err)
	}

	ticket := make([]byte, TicketBytes)
	requestFrame, err := EncodeFrame(Request{
		Kind:             MessageRequest,
		Ticket:           ticket,
		ResourceID:       runnerFixtureResource,
		Params:           map[string]string{"profile": "default"},
		ContextBindingID: runnerFixtureContext,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer requestFrame.Destroy()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = runPreparedProvider(ctx, prepared, handler, ProviderInvocation{
		VaultID: "test-vault", ResourceID: runnerFixtureResource, Profile: "default",
		ContextBindingID: runnerFixtureContext,
	}, requestFrame, ticket)
	if got := ProviderErrorCode(err); got != "cancelled" {
		t.Fatalf("code=%q error=%v", got, err)
	}
}

func TestVerifySpawnedProviderRejectsWrongExecutable(t *testing.T) {
	handler := runnerTestHandler(t)
	if err := verifySpawnedProvider(context.Background(), os.Getpid(), "/definitely/not/the/current/executable", handler); err == nil {
		t.Fatal("expected wrong executable to fail post-spawn verification")
	}
}

func TestRunProviderProgressExposesStateButNotProviderText(t *testing.T) {
	handler := runnerTestHandler(t)
	progressCh := make(chan Progress, 1)
	result, err := runTestProvider(context.Background(), handler, ProviderInvocation{
		VaultID: "test-vault", ResourceID: runnerFixtureResource, Profile: "default",
		ContextBindingID: runnerFixtureContext,
		Params:           map[string]string{"fixture_mode": "progress_then_reply"},
		ProgressSink:     progressCh,
	})
	if err != nil {
		t.Fatal(err)
	}
	result.Secret.Destroy()
	observed := <-progressCh
	if observed.Status != ProgressWorking || observed.ContextBindingID != runnerFixtureContext {
		t.Fatalf("progress state=%+v", observed)
	}
	if observed.Message != "" {
		t.Fatalf("provider progress text crossed runner boundary: %q", observed.Message)
	}
}

func TestRunProviderBlockedProgressSinkFailsWithoutBlocking(t *testing.T) {
	handler := runnerTestHandler(t)
	started := time.Now()
	_, err := runTestProvider(context.Background(), handler, ProviderInvocation{
		VaultID: "test-vault", ResourceID: runnerFixtureResource, Profile: "default",
		ContextBindingID: runnerFixtureContext,
		Params:           map[string]string{"fixture_mode": "progress_then_reply"},
		ProgressSink:     make(chan Progress),
	})
	if got := ProviderErrorCode(err); got != "progress_delivery_failed" {
		t.Fatalf("code=%q error=%v", got, err)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("blocked progress sink delayed failure: %s", elapsed)
	}
}

func TestRunProviderRejectsZeroLengthTrailingSequencePacket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux SOCK_SEQPACKET behavior")
	}
	handler := runnerTestHandler(t)
	_, err := runTestProvider(context.Background(), handler, ProviderInvocation{
		VaultID: "test-vault", ResourceID: runnerFixtureResource, Profile: "default",
		ContextBindingID: runnerFixtureContext,
		Params:           map[string]string{"fixture_mode": "zero_trailing_record"},
	})
	if got := ProviderErrorCode(err); got != "protocol_violation" {
		t.Fatalf("code=%q error=%v", got, err)
	}
}

func TestRunProviderRequiresStoreResolution(t *testing.T) {
	handler := runnerTestHandler(t)
	invocation := ProviderInvocation{
		VaultID: "test-vault", ResourceID: runnerFixtureResource, Profile: "default",
		ContextBindingID: runnerFixtureContext,
	}
	_, err := RunProvider(context.Background(), nil, handler.ID, invocation)
	if got := ProviderErrorCode(err); got != "handler_unavailable" {
		t.Fatalf("nil resolver code=%q error=%v", got, err)
	}

	resolver := &runnerHandlerResolver{handler: handler}
	resolver.handler.ID = "different-handler"
	_, err = RunProvider(context.Background(), resolver, handler.ID, invocation)
	if got := ProviderErrorCode(err); got != "handler_unavailable" {
		t.Fatalf("mismatched store row code=%q error=%v", got, err)
	}
}

func TestProviderEnvironmentIgnoresAmbientIdentityValues(t *testing.T) {
	t.Setenv("HOME", "/tmp/AMBIENT_UNTRUSTED\nHOME")
	t.Setenv("USER", "AMBIENT_UNTRUSTED=USER")
	environment, err := providerEnvironment(runnerTestHandler(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range environment {
		if strings.Contains(entry, "AMBIENT_UNTRUSTED") || strings.ContainsAny(entry, "\r\n\x00") {
			t.Fatalf("ambient or control data crossed provider environment: %q", entry)
		}
	}
}

func TestOwnedFDCloseCannotCloseReusedDescriptor(t *testing.T) {
	pair, err := closeOnExecSocketpair(unix.SOCK_STREAM)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFD(pair[1])
	owned := newOwnedFD(pair[0])
	reused := owned.Value()
	owned.Close()
	if err := unix.Dup2(pair[1], reused); err != nil {
		t.Fatal(err)
	}
	defer closeFD(reused)
	owned.Close()
	if _, err := unix.FcntlInt(uintptr(reused), unix.F_GETFD, 0); err != nil {
		t.Fatalf("second owner close affected reused fd: %v", err)
	}
}

func TestSendFrameContextHonorsCancellationWhilePeerDoesNotRead(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin stream transport")
	}
	pair, err := closeOnExecSocketpair(unix.SOCK_STREAM)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFD(pair[0])
	defer closeFD(pair[1])
	if err := unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_SNDBUF, 1024); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, MaxFrameBodyBytes+4)
	binaryPutFrameLength(raw, MaxFrameBodyBytes)
	frame, err := newFrame(raw)
	zeroBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer frame.Destroy()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = sendFrameContext(ctx, pair[0], frame)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v", err)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("cancellable send took %s", elapsed)
	}
}

type runnerHandlerResolver struct {
	handler store.AcquisitionHandler
	err     error
}

func (r *runnerHandlerResolver) GetAcquisitionHandler(context.Context, string) (*store.AcquisitionHandler, error) {
	if r == nil || r.err != nil {
		return nil, r.err
	}
	handler := r.handler
	return &handler, nil
}

func runTestProvider(ctx context.Context, handler store.AcquisitionHandler, invocation ProviderInvocation) (*ProviderResult, error) {
	return RunProvider(ctx, &runnerHandlerResolver{handler: handler}, handler.ID, invocation)
}

func runnerTestHandler(t *testing.T) store.AcquisitionHandler {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return store.AcquisitionHandler{
		ID: "test-provider", Generation: "test-generation", Kind: "executable",
		ExecutablePath: path, SHA256: hex.EncodeToString(digest[:]),
		AllowedKeys: []string{runnerFixtureResource}, AllowedVaults: []string{"test-vault"},
		AllowedProfiles: []string{"default"}, TimeoutSeconds: 3, OutputLimitBytes: 4096,
		Enabled: true,
	}
}

func runProviderFixture(fd int) int {
	frame, err := receiveFrame(fd)
	if err != nil {
		return 31
	}
	decoded, err := DecodeFrame(frame)
	if err != nil {
		return 32
	}
	request, ok := decoded.(Request)
	if !ok {
		return 33
	}
	mode := request.Params["fixture_mode"]
	if mode == "contract" && (!fixtureSpawnContractValid() || request.Params["profile"] != "default") {
		return 34
	}
	switch mode {
	case "timeout":
		time.Sleep(5 * time.Second)
		return 35
	case "exit_nonzero":
		return 17
	case "malformed":
		malformed, frameErr := newFrame([]byte{3, 0, 0, 0, 0xff, 0xff, 0xff})
		if frameErr != nil || sendFrame(fd, malformed) != nil {
			return 36
		}
		return 0
	case "oversized":
		payload := make([]byte, MaxFrameBodyBytes+5)
		binaryPutFrameLength(payload, MaxFrameBodyBytes+1)
		if _, sendErr := unix.SendmsgN(fd, payload, nil, nil, 0); sendErr != nil {
			return 37
		}
		return 0
	case "progress_overflow":
		for i := 0; i <= MaxProgressMessages; i++ {
			progress, frameErr := EncodeFrame(Progress{
				Kind: MessageProgress, ContextBindingID: request.ContextBindingID,
				Status: ProgressWorking, Message: "working",
			})
			if frameErr != nil || sendFrame(fd, progress) != nil {
				return 38
			}
		}
		return 0
	case "progress_then_reply":
		progress, frameErr := EncodeFrame(Progress{
			Kind: MessageProgress, ContextBindingID: request.ContextBindingID,
			Status: ProgressWorking, Message: "provider-owned text",
		})
		if frameErr != nil || sendFrame(fd, progress) != nil {
			return 44
		}
	case "ancillary_data":
		progress, frameErr := EncodeFrame(Progress{
			Kind: MessageProgress, ContextBindingID: request.ContextBindingID,
			Status: ProgressWorking,
		})
		if frameErr != nil {
			return 42
		}
		defer progress.Destroy()
		if sendErr := progress.withBytes(func(raw []byte) error {
			_, err := unix.SendmsgN(fd, raw, unix.UnixRights(1), nil, 0)
			return err
		}); sendErr != nil {
			return 43
		}
	case "stderr_overflow":
		_, _ = os.Stderr.Write([]byte(strings.Repeat("x", 8192)))
		return 0
	case "stderr_secret":
		_, _ = fmt.Fprintln(os.Stderr, runnerFixtureSecret)
	}

	secret, err := NewSecretBuffer([]byte(runnerFixtureSecret))
	if err != nil {
		return 39
	}
	defer secret.Destroy()
	ticket := append([]byte(nil), request.Ticket...)
	contextID := request.ContextBindingID
	if mode == "wrong_ticket" {
		ticket[0] ^= 0xff
	}
	if mode == "wrong_context" {
		contextID = "av_ctx_01JQ6T9J2WR8MVB7F2K4N6P8RB"
	}
	reply, err := EncodeFrame(Reply{
		Kind: MessageReply, Ticket: ticket, ContextBindingID: contextID, Secret: secret,
		Meta: ReplyMeta{IssuedAtUnix: time.Now().Unix(), TTLSeconds: 3600, Source: "test_fixture"},
	})
	zeroBytes(ticket)
	if err != nil || sendFrame(fd, reply) != nil {
		return 40
	}
	if mode == "trailing_output" {
		progress, frameErr := EncodeFrame(Progress{
			Kind: MessageProgress, ContextBindingID: request.ContextBindingID,
			Status: ProgressWorking, Message: "trailing",
		})
		if frameErr != nil || sendFrame(fd, progress) != nil {
			return 41
		}
	}
	if mode == "zero_trailing_record" {
		if _, sendErr := unix.SendmsgN(fd, nil, nil, nil, 0); sendErr != nil {
			return 45
		}
	}
	return 0
}

func fixtureSpawnContractValid() bool {
	if len(os.Args) != 1 || filepath.Base(os.Args[0]) != "provider" {
		return false
	}
	if cwd, err := os.Getwd(); err != nil || cwd != "/" {
		return false
	}
	keys := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		keys = append(keys, key)
	}
	sort.Strings(keys)
	want := []string{"AVSH_TICKET_FD", "HOME", "LANG", "PATH", "USER"}
	sort.Strings(want)
	return strings.Join(keys, ",") == strings.Join(want, ",")
}

func binaryPutFrameLength(raw []byte, length int) {
	raw[0] = byte(length)
	raw[1] = byte(length >> 8)
	raw[2] = byte(length >> 16)
	raw[3] = byte(length >> 24)
}

func TestProviderErrorNeverWrapsRawStderr(t *testing.T) {
	err := newProviderError("provider_error", errors.New(runnerFixtureSecret))
	if strings.Contains(err.Error(), runnerFixtureSecret) {
		t.Fatal("provider error included wrapped secret")
	}
}
