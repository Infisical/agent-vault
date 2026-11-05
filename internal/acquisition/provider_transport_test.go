package acquisition

import (
	"bytes"
	"io"
	"testing"
)

const providerTransportBinding = "018f47b2-13c4-7abc-8def-0123456789ab"

func TestProviderTransportRoundTrip(t *testing.T) {
	request := Request{
		Kind: MessageRequest, Ticket: bytes.Repeat([]byte{0x5a}, TicketBytes),
		ResourceID: "GITHUB_TOKEN", Params: map[string]string{"mode": "native", "profile": "github.com"},
		ContextBindingID: providerTransportBinding,
	}
	var wire bytes.Buffer
	if err := WriteProviderProgress(&wire, Progress{
		Kind: MessageProgress, ContextBindingID: providerTransportBinding, Status: ProgressWorking,
	}); err != nil {
		t.Fatal(err)
	}
	if err := WriteProviderRequest(&wire, request); err != nil {
		t.Fatal(err)
	}
	progress, err := ReadProviderMessage(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := progress.(Progress); !ok || got.Status != ProgressWorking {
		t.Fatalf("progress = %#v", progress)
	}
	message, err := ReadProviderRequest(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if message.ResourceID != request.ResourceID || message.Params["profile"] != "github.com" || !bytes.Equal(message.Ticket, request.Ticket) {
		t.Fatalf("request = %#v", message)
	}

	secret, err := NewSecretBuffer([]byte("transport-sentinel"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	var replyWire bytes.Buffer
	if err := WriteProviderReply(&replyWire, Reply{
		Kind: MessageReply, Ticket: request.Ticket, ContextBindingID: providerTransportBinding,
		Secret: secret, Meta: ReplyMeta{IssuedAtUnix: 1, Source: "test"},
	}); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadProviderMessage(&replyWire)
	if err != nil {
		t.Fatal(err)
	}
	reply, ok := decoded.(Reply)
	if !ok {
		t.Fatalf("reply = %#v", decoded)
	}
	defer reply.Secret.Destroy()
	if !reply.Secret.Equal([]byte("transport-sentinel")) {
		t.Fatal("reply secret did not round trip")
	}
}

func TestReadProviderRequestRejectsWrongMessage(t *testing.T) {
	var wire bytes.Buffer
	if err := WriteProviderProgress(&wire, Progress{
		Kind: MessageProgress, ContextBindingID: providerTransportBinding, Status: ProgressWorking,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProviderRequest(&wire); err == nil {
		t.Fatal("expected non-request message rejection")
	}
}

func TestProviderTransportRejectsTruncatedFrame(t *testing.T) {
	if _, err := ReadProviderMessage(bytes.NewReader([]byte{3, 0, 0, 0, 0xa1})); err == nil || err == io.EOF {
		t.Fatalf("truncated frame error = %v", err)
	}
}
