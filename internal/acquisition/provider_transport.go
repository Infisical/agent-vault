package acquisition

import (
	"encoding/binary"
	"fmt"
	"io"
)

// ReadProviderMessage reads one length-delimited AVSH/1 message from the
// provider socket. The frame is assembled in locked memory and consumed by
// DecodeFrame, so reply secrets never pass through an ordinary byte buffer.
func ReadProviderMessage(reader io.Reader) (any, error) {
	if reader == nil {
		return nil, ErrFrameMalformed
	}
	buffer, err := newLockedBuffer(MaxFrameBodyBytes+4, MaxFrameBodyBytes+4)
	if err != nil {
		return nil, fmt.Errorf("allocate AVSH/1 frame: %w", err)
	}
	if _, err := io.ReadFull(reader, buffer.value[:4]); err != nil {
		buffer.Destroy()
		return nil, err
	}
	bodyLength := binary.LittleEndian.Uint32(buffer.value[:4])
	if bodyLength == 0 {
		buffer.Destroy()
		return nil, ErrFrameMalformed
	}
	if bodyLength > MaxFrameBodyBytes {
		buffer.Destroy()
		return nil, ErrFrameTooLarge
	}
	frameLength := int(bodyLength) + 4
	if _, err := io.ReadFull(reader, buffer.value[4:frameLength]); err != nil {
		buffer.Destroy()
		return nil, err
	}
	buffer.value = buffer.value[:frameLength:frameLength]
	return DecodeFrame(&Frame{buffer: buffer})
}

// ReadProviderRequest reads and type-checks the server's initial AVSH/1
// request. Call DestroyProviderRequest after the exchange to wipe its ticket.
func ReadProviderRequest(reader io.Reader) (Request, error) {
	message, err := ReadProviderMessage(reader)
	if err != nil {
		return Request{}, err
	}
	request, ok := message.(Request)
	if !ok {
		if reply, isReply := message.(Reply); isReply && reply.Secret != nil {
			reply.Secret.Destroy()
		}
		return Request{}, fmt.Errorf("expected AVSH/1 request")
	}
	return request, nil
}

// DestroyProviderRequest wipes the one-use ticket held by a decoded request.
func DestroyProviderRequest(request *Request) {
	if request == nil {
		return
	}
	zeroBytes(request.Ticket)
	request.Ticket = nil
}

// WriteProviderFrame writes one complete encoded AVSH/1 frame, handling short
// writes without copying its locked backing buffer into ordinary memory.
func WriteProviderFrame(writer io.Writer, frame *Frame) error {
	if writer == nil || frame == nil {
		return ErrFrameMalformed
	}
	return frame.withBytes(func(raw []byte) error {
		for len(raw) > 0 {
			n, err := writer.Write(raw)
			if n < 0 || n > len(raw) {
				return io.ErrShortWrite
			}
			raw = raw[n:]
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
		}
		return nil
	})
}

func WriteProviderRequest(writer io.Writer, request Request) error {
	return writeProviderMessage(writer, request)
}

func WriteProviderProgress(writer io.Writer, progress Progress) error {
	return writeProviderMessage(writer, progress)
}

func WriteProviderReply(writer io.Writer, reply Reply) error {
	return writeProviderMessage(writer, reply)
}

func writeProviderMessage(writer io.Writer, message any) error {
	frame, err := EncodeFrame(message)
	if err != nil {
		return err
	}
	defer frame.Destroy()
	return WriteProviderFrame(writer, frame)
}
