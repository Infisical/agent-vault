package acquisition

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/fxamacker/cbor/v2"
)

const testAVSHContextID = "av_ctx_01JQ6T9J2WR8MVB7F2K4N6P8RA"

func testTicket() []byte {
	ticket := make([]byte, TicketBytes)
	for i := range ticket {
		ticket[i] = byte(i + 1)
	}
	return ticket
}

func TestAVSH1RoundTripMessagesAndLittleEndianFraming(t *testing.T) {
	request := Request{
		Kind: MessageRequest, Ticket: testTicket(), ResourceID: "GITHUB_TOKEN",
		Params:           map[string]string{"profile": "github.com", "mode": "native"},
		ContextBindingID: testAVSHContextID,
	}
	frame, err := EncodeFrame(request)
	if err != nil {
		t.Fatal(err)
	}
	raw := frameBytesForTest(t, frame)
	if got := binary.LittleEndian.Uint32(raw[:4]); got != uint32(len(raw)-4) {
		t.Fatalf("prefix=%d body=%d", got, len(raw)-4)
	}
	decoded, err := DecodeFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	gotRequest, ok := decoded.(Request)
	if !ok || gotRequest.ResourceID != request.ResourceID || gotRequest.ContextBindingID != testAVSHContextID || string(gotRequest.Ticket) != string(request.Ticket) {
		t.Fatalf("request round trip: %#v", decoded)
	}
	if frame.Len() != 0 {
		t.Fatal("DecodeFrame did not destroy its owned input frame")
	}

	progress := Progress{
		Kind:             MessageProgress,
		Status:           ProgressAwaitingUser,
		Message:          "Touch ID required",
		ContextBindingID: testAVSHContextID,
	}
	frame, err = EncodeFrame(progress)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = DecodeFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := decoded.(Progress); !ok || got.Status != ProgressAwaitingUser || got.ContextBindingID != testAVSHContextID {
		t.Fatalf("progress round trip: %#v", decoded)
	}

	secret, err := NewSecretBuffer([]byte("synthetic-test-secret"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	reply := Reply{
		Kind: MessageReply, Ticket: testTicket(), Secret: secret,
		ContextBindingID: testAVSHContextID,
		Meta:             ReplyMeta{IssuedAtUnix: time.Now().Unix(), TTLSeconds: 3600, Source: "test_fixture"},
	}
	frame, err = EncodeFrame(reply)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = DecodeFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	gotReply, ok := decoded.(Reply)
	if !ok || gotReply.Meta.Source != "test_fixture" || !gotReply.Secret.Equal([]byte("synthetic-test-secret")) {
		t.Fatalf("reply round trip: %#v", decoded)
	}
	gotReply.Secret.Destroy()
}

func TestAVSH1RejectsMalformedAndOversizedFrames(t *testing.T) {
	valid, err := EncodeFrame(Progress{Kind: MessageProgress, Status: ProgressWorking, ContextBindingID: testAVSHContextID})
	if err != nil {
		t.Fatal(err)
	}
	validRaw := frameBytesForTest(t, valid)
	valid.Destroy()
	tests := []struct {
		name  string
		frame *Frame
	}{
		{"short prefix", frameForRaw([]byte{1, 2, 3})},
		{"length mismatch", frameForRaw(append([]byte{99, 0, 0, 0}, validRaw[4:]...))},
		{"zero length", frameForRaw([]byte{0, 0, 0, 0})},
		{"oversized declaration", frameForRaw([]byte{1, 0, 1, 0})},
		{"duplicate kind key", frameForBody([]byte{0xa2, 0x00, 0x00, 0x00, 0x01})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecodeFrame(tt.frame); err == nil {
				t.Fatal("expected malformed frame rejection")
			}
		})
	}
}

func TestAVSH1RejectsUnknownFieldsAndInvalidMessageShapes(t *testing.T) {
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	unknown, _ := enc.Marshal(map[uint64]any{0: uint64(MessageProgress), 5: string(ProgressWorking), 99: true})
	if _, err := DecodeFrame(frameForBody(unknown)); err == nil {
		t.Fatal("expected unknown field rejection")
	}

	tests := []struct {
		name string
		msg  any
		want string
	}{
		{"short ticket", Request{Kind: MessageRequest, Ticket: []byte("short"), ResourceID: "TOKEN", ContextBindingID: testAVSHContextID}, "ticket"},
		{"bad resource", Request{Kind: MessageRequest, Ticket: testTicket(), ResourceID: "token", ContextBindingID: testAVSHContextID}, "resource"},
		{"bad context", Request{Kind: MessageRequest, Ticket: testTicket(), ResourceID: "TOKEN", ContextBindingID: "wrong"}, "context"},
		{"bad progress status", Progress{Kind: MessageProgress, Status: "page-text"}, "status"},
		{"missing progress context", Progress{Kind: MessageProgress, Status: ProgressWorking}, "context"},
		{"large progress", Progress{Kind: MessageProgress, Status: ProgressWorking, Message: strings.Repeat("x", MaxProgressBodyBytes), ContextBindingID: testAVSHContextID}, "progress"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncodeFrame(tt.msg)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), tt.want) {
				t.Fatalf("want error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestSecretBufferRedactsFormattingAndZeroizes(t *testing.T) {
	secret, err := NewSecretBuffer([]byte("SENTINEL_SHOULD_NOT_FORMAT"))
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%v %#v", secret, secret); strings.Contains(got, "SENTINEL") || !strings.Contains(got, "REDACTED") {
		t.Fatalf("secret formatting was not redacted: %s", got)
	}
	secret.Destroy()
	if secret.Len() != 0 || secret.Equal([]byte("SENTINEL_SHOULD_NOT_FORMAT")) {
		t.Fatal("destroyed secret retained bytes")
	}
	secret.Destroy() // idempotent
}

func TestSecretBufferEncryptWithKeyKeepsPlaintextInsideLockedBuffer(t *testing.T) {
	secret, err := NewSecretBuffer([]byte("LOCKED_BUFFER_SENTINEL"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	key := make([]byte, 32)
	ciphertext, nonce, err := secret.EncryptWithKey(key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := vaultcrypto.Decrypt(ciphertext, nonce, key)
	if err != nil {
		t.Fatal(err)
	}
	defer vaultcrypto.WipeBytes(plaintext)
	if string(plaintext) != "LOCKED_BUFFER_SENTINEL" {
		t.Fatal("encrypted secret did not round trip")
	}
}

func TestProgressTrackerEnforcesEightMessageCap(t *testing.T) {
	var tracker ProgressTracker
	for i := 0; i < MaxProgressMessages; i++ {
		if err := tracker.Accept(Progress{Kind: MessageProgress, Status: ProgressWorking, ContextBindingID: testAVSHContextID}); err != nil {
			t.Fatalf("progress %d: %v", i, err)
		}
	}
	if err := tracker.Accept(Progress{Kind: MessageProgress, Status: ProgressWorking, ContextBindingID: testAVSHContextID}); !errors.Is(err, ErrProgressLimit) {
		t.Fatalf("expected ErrProgressLimit, got %v", err)
	}
}

func TestProgressTrackerConcurrentCap(t *testing.T) {
	var tracker ProgressTracker
	var accepted atomic.Int32
	var rejected atomic.Int32
	var unexpected atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := tracker.Accept(Progress{Kind: MessageProgress, Status: ProgressWorking, ContextBindingID: testAVSHContextID})
			switch {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, ErrProgressLimit):
				rejected.Add(1)
			default:
				unexpected.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != MaxProgressMessages || rejected.Load() != 64-MaxProgressMessages || unexpected.Load() != 0 {
		t.Fatalf("accepted=%d rejected=%d unexpected=%d", accepted.Load(), rejected.Load(), unexpected.Load())
	}
}

func TestDecodeCBORByteStringRejectsNonCanonicalLengths(t *testing.T) {
	tests := [][]byte{
		{0x58, 0x01, 'x'},
		append([]byte{0x59, 0x00, 0x18}, make([]byte, 24)...),
		append([]byte{0x5a, 0x00, 0x00, 0x01, 0x00}, make([]byte, 256)...),
	}
	for _, encoded := range tests {
		if _, err := decodeCBORByteString(encoded); err == nil {
			t.Fatalf("accepted non-canonical byte string prefix %x", encoded[:min(len(encoded), 5)])
		}
	}
}

func TestFrameSupportsMaximumBodyAndConcurrentSingleConsumer(t *testing.T) {
	maximum := make([]byte, MaxFrameBodyBytes+4)
	binary.LittleEndian.PutUint32(maximum[:4], MaxFrameBodyBytes)
	frame, err := newFrame(maximum)
	zeroBytes(maximum)
	if err != nil {
		t.Fatalf("maximum frame: %v", err)
	}
	if frame.Len() != MaxFrameBodyBytes+4 {
		t.Fatalf("maximum frame length=%d", frame.Len())
	}
	frame.Destroy()

	frame, err = EncodeFrame(Progress{Kind: MessageProgress, Status: ProgressWorking, ContextBindingID: testAVSHContextID})
	if err != nil {
		t.Fatal(err)
	}
	var decoded atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 3 {
			case 0:
				if _, err := DecodeFrame(frame); err == nil {
					decoded.Add(1)
				}
			case 1:
				_ = frame.Len()
			default:
				frame.Destroy()
			}
		}(i)
	}
	wg.Wait()
	if decoded.Load() > 1 {
		t.Fatalf("frame decoded %d times", decoded.Load())
	}
}

func frameForBody(body []byte) *Frame {
	raw := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(raw[:4], uint32(len(body)))
	copy(raw[4:], body)
	return frameForRaw(raw)
}

func frameForRaw(raw []byte) *Frame {
	frame, err := newFrame(raw)
	zeroBytes(raw)
	if err != nil {
		panic(err)
	}
	return frame
}

func frameBytesForTest(t *testing.T, frame *Frame) []byte {
	t.Helper()
	var copied []byte
	if err := frame.withBytes(func(value []byte) error {
		copied = append([]byte(nil), value...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return copied
}
