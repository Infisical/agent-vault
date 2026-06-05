package mitm

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// fakeConn implements net.Conn for testing. Only SetReadDeadline is used
// by copyWSFramesWithSubstitution (via the srcConn parameter).
type fakeConn struct {
	io.Reader
	io.Writer
}

func (fakeConn) Close() error                       { return nil }
func (fakeConn) LocalAddr() net.Addr                { return nil }
func (fakeConn) RemoteAddr() net.Addr               { return nil }
func (fakeConn) SetDeadline(time.Time) error        { return nil }
func (fakeConn) SetReadDeadline(time.Time) error    { return nil }
func (fakeConn) SetWriteDeadline(time.Time) error   { return nil }

func maskedTextFrame(t *testing.T, text string) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := writeWebSocketTextFrame(&buf, text, true); err != nil {
		t.Fatalf("writeWebSocketTextFrame: %v", err)
	}
	return buf.Bytes()
}

func maskedCloseFrame() []byte {
	// Opcode 0x8, FIN=1, masked, zero payload, 4-byte mask
	return []byte{0x88, 0x80, 0x00, 0x00, 0x00, 0x00}
}

func maskedBinaryFrame(payload []byte, mask [4]byte) []byte {
	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	hdr := []byte{0x82, byte(len(masked)) | 0x80}
	hdr = append(hdr, mask[:]...)
	return append(hdr, masked...)
}

func pingFrame(payload []byte) []byte {
	// Opcode 0x9, FIN=1, unmasked
	hdr := []byte{0x89, byte(len(payload))}
	return append(hdr, payload...)
}

func readFrameText(t *testing.T, r io.Reader) string {
	t.Helper()
	text, err := readWebSocketTextFrame(r)
	if err != nil {
		t.Fatalf("readWebSocketTextFrame: %v", err)
	}
	return text
}

func TestCopyWSFramesSubstitutesTextFrame(t *testing.T) {
	subs := []brokercore.ResolvedSubstitution{{
		Placeholder: "__discord_token__",
		Value:       "Bot MTk4NjIyNDk1MTcyMjE3",
		In:          []string{"websocket"},
	}}

	payload := `{"op":2,"d":{"token":"__discord_token__","intents":513}}`
	frame := maskedTextFrame(t, payload)
	// Append a close frame so the copier exits.
	frame = append(frame, maskedCloseFrame()...)

	src := bytes.NewReader(frame)
	var dst bytes.Buffer
	fc := fakeConn{}

	copyWSFramesWithSubstitution(&dst, src, fc, 10*time.Minute, subs)

	text := readFrameText(t, &dst)
	expected := `{"op":2,"d":{"token":"Bot MTk4NjIyNDk1MTcyMjE3","intents":513}}`
	if text != expected {
		t.Fatalf("expected %q, got %q", expected, text)
	}
}

func TestCopyWSFramesNoMatchPassesThrough(t *testing.T) {
	subs := []brokercore.ResolvedSubstitution{{
		Placeholder: "__discord_token__",
		Value:       "real",
		In:          []string{"websocket"},
	}}

	payload := `{"op":11,"d":null}`
	frame := maskedTextFrame(t, payload)
	frame = append(frame, maskedCloseFrame()...)

	src := bytes.NewReader(frame)
	var dst bytes.Buffer
	fc := fakeConn{}

	copyWSFramesWithSubstitution(&dst, src, fc, 10*time.Minute, subs)

	text := readFrameText(t, &dst)
	if text != payload {
		t.Fatalf("expected %q, got %q", payload, text)
	}
}

func TestCopyWSFramesBinaryPassesThrough(t *testing.T) {
	subs := []brokercore.ResolvedSubstitution{{
		Placeholder: "__token__",
		Value:       "real",
		In:          []string{"websocket"},
	}}

	binPayload := []byte{0x01, 0x02, 0x03, 0x04}
	mask := [4]byte{5, 6, 7, 8}
	frame := maskedBinaryFrame(binPayload, mask)
	frame = append(frame, maskedCloseFrame()...)

	src := bytes.NewReader(frame)
	var dst bytes.Buffer
	fc := fakeConn{}

	copyWSFramesWithSubstitution(&dst, src, fc, 10*time.Minute, subs)

	// Read the binary frame header
	hdr := make([]byte, 2)
	out := bytes.NewReader(dst.Bytes())
	if _, err := io.ReadFull(out, hdr); err != nil {
		t.Fatalf("reading binary frame header: %v", err)
	}
	if hdr[0]&0x0F != 0x2 {
		t.Fatalf("expected binary opcode, got 0x%x", hdr[0]&0x0F)
	}
}

func TestCopyWSFramesCloseFrameExits(t *testing.T) {
	subs := []brokercore.ResolvedSubstitution{{
		Placeholder: "__token__",
		Value:       "real",
		In:          []string{"websocket"},
	}}

	frame := maskedCloseFrame()
	src := bytes.NewReader(frame)
	var dst bytes.Buffer
	fc := fakeConn{}

	done := make(chan struct{})
	go func() {
		copyWSFramesWithSubstitution(&dst, src, fc, 10*time.Minute, subs)
		close(done)
	}()

	select {
	case <-done:
		// Good — copier exited after close frame
	case <-time.After(2 * time.Second):
		t.Fatal("copier did not exit after close frame")
	}
}

func TestCopyWSFramesPingPassesThrough(t *testing.T) {
	subs := []brokercore.ResolvedSubstitution{{
		Placeholder: "__token__",
		Value:       "real",
		In:          []string{"websocket"},
	}}

	var frame []byte
	frame = append(frame, pingFrame([]byte("hello"))...)
	frame = append(frame, maskedCloseFrame()...)

	src := bytes.NewReader(frame)
	var dst bytes.Buffer
	fc := fakeConn{}

	copyWSFramesWithSubstitution(&dst, src, fc, 10*time.Minute, subs)

	// First frame should be ping (opcode 0x9)
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(bytes.NewReader(dst.Bytes()), hdr); err != nil {
		t.Fatalf("reading ping frame: %v", err)
	}
	if hdr[0]&0x0F != 0x9 {
		t.Fatalf("expected ping opcode, got 0x%x", hdr[0]&0x0F)
	}
}

func TestCopyWSFramesLengthEncodingTransition(t *testing.T) {
	// Payload ≤125 bytes before substitution, >125 after — tests 7-bit → 16-bit.
	subs := []brokercore.ResolvedSubstitution{{
		Placeholder: "__tk__",
		Value:       strings.Repeat("X", 100),
		In:          []string{"websocket"},
	}}

	// 115 + 6 = 121 bytes (≤125, fits in writeWebSocketTextFrame)
	// After: 115 + 100 = 215 bytes (>125, needs 16-bit encoding)
	prefix := strings.Repeat("A", 115)
	payload := prefix + "__tk__"
	frame := maskedTextFrame(t, payload)
	frame = append(frame, maskedCloseFrame()...)

	src := bytes.NewReader(frame)
	var dst bytes.Buffer
	fc := fakeConn{}

	copyWSFramesWithSubstitution(&dst, src, fc, 10*time.Minute, subs)

	out := dst.Bytes()
	if len(out) < 4 {
		t.Fatal("output too short")
	}

	// Check that masked bit is set and length encoding is 16-bit (126).
	payloadLenByte := out[1] & 0x7F
	expectedLen := 115 + 100
	if payloadLenByte != 126 {
		t.Fatalf("expected 16-bit length encoding (126), got %d", payloadLenByte)
	}
	extLen := binary.BigEndian.Uint16(out[2:4])
	if int(extLen) != expectedLen {
		t.Fatalf("expected payload length %d, got %d", expectedLen, extLen)
	}

	text := readFrameText(t, bytes.NewReader(out))
	if text != prefix+strings.Repeat("X", 100) {
		t.Fatalf("unexpected text after substitution")
	}
}

func TestCopyWSFramesOversizedPassesThrough(t *testing.T) {
	subs := []brokercore.ResolvedSubstitution{{
		Placeholder: "__token__",
		Value:       "real",
		In:          []string{"websocket"},
	}}

	// Build a masked text frame with payload > maxWSSubstitutionPayload
	bigPayload := strings.Repeat("A", maxWSSubstitutionPayload+100) + "__token__"
	bigBytes := []byte(bigPayload)
	mask := [4]byte{1, 2, 3, 4}

	var frame bytes.Buffer
	// FIN=1, opcode=text
	frame.WriteByte(0x81)
	// 16-bit extended length won't work for >64KB, use 64-bit
	frame.WriteByte(127 | 0x80) // masked + 64-bit length
	lenBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBytes, uint64(len(bigBytes)))
	frame.Write(lenBytes)
	frame.Write(mask[:])
	for i := range bigBytes {
		bigBytes[i] ^= mask[i%4]
	}
	frame.Write(bigBytes)
	frame.Write(maskedCloseFrame())

	src := bytes.NewReader(frame.Bytes())
	var dst bytes.Buffer
	fc := fakeConn{}

	copyWSFramesWithSubstitution(&dst, src, fc, 10*time.Minute, subs)

	// The oversized frame should pass through with __token__ NOT replaced.
	// Read the output — it should contain the original masked payload.
	out := dst.Bytes()
	if len(out) < 10 {
		t.Fatal("output too short for oversized frame")
	}
	// Verify opcode is still text
	if out[0]&0x0F != 0x1 {
		t.Fatalf("expected text opcode, got 0x%x", out[0]&0x0F)
	}
}

func TestFilterWebSocketSubs(t *testing.T) {
	subs := []brokercore.ResolvedSubstitution{
		{Placeholder: "__a__", Value: "a", In: []string{"header", "websocket"}},
		{Placeholder: "__b__", Value: "b", In: []string{"body"}},
		{Placeholder: "__c__", Value: "c", In: []string{"websocket"}},
	}
	ws := filterWebSocketSubs(subs)
	if len(ws) != 2 {
		t.Fatalf("expected 2 websocket subs, got %d", len(ws))
	}
	if ws[0].Placeholder != "__a__" || ws[1].Placeholder != "__c__" {
		t.Fatalf("unexpected filtered subs: %+v", ws)
	}
}
