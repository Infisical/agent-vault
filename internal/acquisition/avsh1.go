package acquisition

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"sync"
	"unicode"

	"github.com/Infisical/agent-vault/internal/contextbinding"
	"github.com/fxamacker/cbor/v2"
)

const (
	TicketBytes             = 32
	MaxFrameBodyBytes       = 64 * 1024
	MaxProgressBodyBytes    = 1024
	MaxProgressMessages     = 8
	MaxSecretBytes          = 64 * 1024
	MaxRequestParams        = 16
	MaxRequestParamValueLen = 1024
)

type MessageKind uint64

const (
	MessageRequest MessageKind = iota
	MessageProgress
	MessageReply
)

type ProgressStatus string

const (
	ProgressWorking      ProgressStatus = "working"
	ProgressAwaitingUser ProgressStatus = "awaiting_user"
)

type Request struct {
	Kind             MessageKind       `cbor:"0,keyasint"`
	Ticket           []byte            `cbor:"1,keyasint"`
	ResourceID       string            `cbor:"2,keyasint"`
	Params           map[string]string `cbor:"3,keyasint,omitempty"`
	ContextBindingID string            `cbor:"4,keyasint"`
}

type Progress struct {
	Kind             MessageKind    `cbor:"0,keyasint"`
	ContextBindingID string         `cbor:"4,keyasint"`
	Status           ProgressStatus `cbor:"5,keyasint"`
	Message          string         `cbor:"6,keyasint,omitempty"`
}

type Reply struct {
	Kind             MessageKind   `cbor:"0,keyasint"`
	Ticket           []byte        `cbor:"1,keyasint"`
	ContextBindingID string        `cbor:"4,keyasint"`
	Secret           *SecretBuffer `cbor:"7,keyasint"`
	Meta             ReplyMeta     `cbor:"8,keyasint"`
}

type ReplyMeta struct {
	IssuedAtUnix int64  `cbor:"0,keyasint"`
	TTLSeconds   uint32 `cbor:"1,keyasint"`
	Source       string `cbor:"2,keyasint"`
}

var (
	ErrFrameMalformed  = errors.New("malformed AVSH/1 frame")
	ErrFrameTooLarge   = errors.New("AVSH/1 frame exceeds limit")
	ErrProgressLimit   = errors.New("AVSH/1 progress limit exceeded")
	ErrSecretDestroyed = errors.New("secret buffer is destroyed")
	resourceIDPattern  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
	paramNamePattern   = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	sourcePattern      = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	avshEncMode        cbor.EncMode
	avshDecMode        cbor.DecMode
)

func init() {
	var err error
	avshEncMode, err = cbor.EncOptions{
		Sort:        cbor.SortCanonical,
		IndefLength: cbor.IndefLengthForbidden,
		TagsMd:      cbor.TagsForbidden,
	}.EncMode()
	if err != nil {
		panic(err)
	}
	avshDecMode, err = cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels:   8,
		MaxArrayElements:  16,
		MaxMapPairs:       32,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		MapKeyByteString:  cbor.MapKeyByteStringForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		UTF8:              cbor.UTF8RejectInvalid,
	}.DecMode()
	if err != nil {
		panic(err)
	}
}

func (r Request) validate() error {
	if r.Kind != MessageRequest {
		return fmt.Errorf("request kind is invalid")
	}
	if len(r.Ticket) != TicketBytes {
		return fmt.Errorf("request ticket must be %d bytes", TicketBytes)
	}
	if !resourceIDPattern.MatchString(r.ResourceID) {
		return fmt.Errorf("request resource_id is invalid")
	}
	if err := contextbinding.ValidateBindingID(r.ContextBindingID); err != nil {
		return fmt.Errorf("request context binding: %w", err)
	}
	if len(r.Params) > MaxRequestParams {
		return fmt.Errorf("request params exceed limit")
	}
	for key, value := range r.Params {
		if !paramNamePattern.MatchString(key) || len(value) > MaxRequestParamValueLen || containsControl(value) {
			return fmt.Errorf("request param %q is invalid", key)
		}
	}
	return nil
}

func (p Progress) validate() error {
	if p.Kind != MessageProgress {
		return fmt.Errorf("progress kind is invalid")
	}
	if p.Status != ProgressWorking && p.Status != ProgressAwaitingUser {
		return fmt.Errorf("progress status is invalid")
	}
	if err := contextbinding.ValidateBindingID(p.ContextBindingID); err != nil {
		return fmt.Errorf("progress context binding: %w", err)
	}
	if containsControl(p.Message) {
		return fmt.Errorf("progress message contains control characters")
	}
	return nil
}

func (r Reply) validate() error {
	if r.Kind != MessageReply {
		return fmt.Errorf("reply kind is invalid")
	}
	if len(r.Ticket) != TicketBytes {
		return fmt.Errorf("reply ticket must be %d bytes", TicketBytes)
	}
	if err := contextbinding.ValidateBindingID(r.ContextBindingID); err != nil {
		return fmt.Errorf("reply context binding: %w", err)
	}
	if r.Secret == nil || r.Secret.Len() == 0 || r.Secret.Len() > MaxSecretBytes {
		return fmt.Errorf("reply secret length is invalid")
	}
	if r.Meta.IssuedAtUnix <= 0 || !sourcePattern.MatchString(r.Meta.Source) {
		return fmt.Errorf("reply metadata is invalid")
	}
	return nil
}

func containsControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func EncodeFrame(message any) (*Frame, error) {
	limit := MaxFrameBodyBytes
	var reply *Reply
	switch value := message.(type) {
	case Request:
		if err := value.validate(); err != nil {
			return nil, err
		}
	case *Request:
		if value == nil {
			return nil, fmt.Errorf("request is nil")
		}
		if err := value.validate(); err != nil {
			return nil, err
		}
	case Progress:
		limit = MaxProgressBodyBytes
		if err := value.validate(); err != nil {
			return nil, err
		}
	case *Progress:
		limit = MaxProgressBodyBytes
		if value == nil {
			return nil, fmt.Errorf("progress is nil")
		}
		if err := value.validate(); err != nil {
			return nil, err
		}
	case Reply:
		if err := value.validate(); err != nil {
			return nil, err
		}
		reply = &value
	case *Reply:
		if value == nil {
			return nil, fmt.Errorf("reply is nil")
		}
		if err := value.validate(); err != nil {
			return nil, err
		}
		reply = value
	default:
		return nil, fmt.Errorf("unsupported AVSH/1 message %T", message)
	}
	if reply != nil {
		return encodeReplyFrame(reply)
	}
	body, err := avshEncMode.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("encode AVSH/1 body: %w", err)
	}
	defer zeroBytes(body)
	if len(body) == 0 || len(body) > limit {
		if limit == MaxProgressBodyBytes {
			return nil, fmt.Errorf("progress frame exceeds %d-byte limit: %w", limit, ErrFrameTooLarge)
		}
		return nil, ErrFrameTooLarge
	}
	raw := make([]byte, 4+len(body))
	defer zeroBytes(raw)
	binary.LittleEndian.PutUint32(raw[:4], uint32(len(body)))
	copy(raw[4:], body)
	return newFrame(raw)
}

// Frame owns a page-backed, locked wire message. DecodeFrame consumes and
// destroys it. Call Destroy when an encoded frame is not sent or decoded.
type Frame struct {
	mu     sync.Mutex
	buffer *SecretBuffer
}

func newFrame(raw []byte) (*Frame, error) {
	buffer, err := newLockedBuffer(len(raw), MaxFrameBodyBytes+4)
	if err != nil {
		return nil, err
	}
	copy(buffer.value, raw)
	return &Frame{buffer: buffer}, nil
}

func encodeReplyFrame(reply *Reply) (*Frame, error) {
	bodyLength := replyBodyLength(reply)
	if bodyLength <= 0 || bodyLength > MaxFrameBodyBytes {
		return nil, ErrFrameTooLarge
	}
	buffer, err := newLockedBuffer(4+bodyLength, MaxFrameBodyBytes+4)
	if err != nil {
		return nil, err
	}
	frame := &Frame{buffer: buffer}
	err = buffer.withBytes(func(raw []byte) error {
		binary.LittleEndian.PutUint32(raw[:4], uint32(bodyLength))
		writer := cborFrameWriter{dst: raw[4:]}
		writer.byte(0xa5)
		writer.uint(0)
		writer.uint(uint64(MessageReply))
		writer.uint(1)
		writer.bytes(reply.Ticket)
		writer.uint(4)
		writer.text(reply.ContextBindingID)
		writer.uint(7)
		if err := reply.Secret.withBytes(func(secret []byte) error {
			writer.bytes(secret)
			return nil
		}); err != nil {
			return err
		}
		writer.uint(8)
		writer.byte(0xa3)
		writer.uint(0)
		writer.uint(uint64(reply.Meta.IssuedAtUnix))
		writer.uint(1)
		writer.uint(uint64(reply.Meta.TTLSeconds))
		writer.uint(2)
		writer.text(reply.Meta.Source)
		if writer.err != nil {
			return writer.err
		}
		if writer.offset != bodyLength {
			return fmt.Errorf("encode AVSH/1 reply length mismatch")
		}
		return nil
	})
	if err != nil {
		frame.Destroy()
		return nil, fmt.Errorf("encode AVSH/1 reply: %w", err)
	}
	return frame, nil
}

func replyBodyLength(reply *Reply) int {
	return 1 +
		cborUintLength(0) + cborUintLength(uint64(MessageReply)) +
		cborUintLength(1) + cborBytesLength(len(reply.Ticket)) +
		cborUintLength(4) + cborTextLength(reply.ContextBindingID) +
		cborUintLength(7) + cborBytesLength(reply.Secret.Len()) +
		cborUintLength(8) + 1 +
		cborUintLength(0) + cborUintLength(uint64(reply.Meta.IssuedAtUnix)) +
		cborUintLength(1) + cborUintLength(uint64(reply.Meta.TTLSeconds)) +
		cborUintLength(2) + cborTextLength(reply.Meta.Source)
}

func cborUintLength(value uint64) int { return cborHeadLength(value) }
func cborBytesLength(length int) int  { return cborHeadLength(uint64(length)) + length }
func cborTextLength(value string) int { return cborHeadLength(uint64(len(value))) + len(value) }

func cborHeadLength(value uint64) int {
	switch {
	case value < 24:
		return 1
	case value <= 0xff:
		return 2
	case value <= 0xffff:
		return 3
	case value <= 0xffffffff:
		return 5
	default:
		return 9
	}
}

type cborFrameWriter struct {
	dst    []byte
	offset int
	err    error
}

func (w *cborFrameWriter) reserve(length int) []byte {
	if w.err != nil {
		return nil
	}
	if length < 0 || w.offset > len(w.dst)-length {
		w.err = fmt.Errorf("encode AVSH/1 reply exceeds locked frame")
		return nil
	}
	value := w.dst[w.offset : w.offset+length]
	w.offset += length
	return value
}

func (w *cborFrameWriter) byte(value byte) {
	if dst := w.reserve(1); dst != nil {
		dst[0] = value
	}
}

func (w *cborFrameWriter) uint(value uint64) { w.head(0, value) }

func (w *cborFrameWriter) bytes(value []byte) {
	w.head(2, uint64(len(value)))
	if dst := w.reserve(len(value)); dst != nil {
		copy(dst, value)
	}
}

func (w *cborFrameWriter) text(value string) {
	w.head(3, uint64(len(value)))
	if dst := w.reserve(len(value)); dst != nil {
		copy(dst, value)
	}
}

func (w *cborFrameWriter) head(major byte, value uint64) {
	prefix := major << 5
	switch {
	case value < 24:
		w.byte(prefix | byte(value))
	case value <= 0xff:
		if dst := w.reserve(2); dst != nil {
			dst[0], dst[1] = prefix|24, byte(value)
		}
	case value <= 0xffff:
		if dst := w.reserve(3); dst != nil {
			dst[0], dst[1], dst[2] = prefix|25, byte(value>>8), byte(value)
		}
	case value <= 0xffffffff:
		if dst := w.reserve(5); dst != nil {
			dst[0] = prefix | 26
			binary.BigEndian.PutUint32(dst[1:], uint32(value))
		}
	default:
		if dst := w.reserve(9); dst != nil {
			dst[0] = prefix | 27
			binary.BigEndian.PutUint64(dst[1:], value)
		}
	}
}

func (f *Frame) Len() int {
	if f == nil {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.buffer == nil {
		return 0
	}
	return f.buffer.Len()
}

func (f *Frame) Destroy() {
	buffer := f.takeBuffer()
	if buffer == nil {
		return
	}
	buffer.Destroy()
}

func (f *Frame) withBytes(fn func([]byte) error) error {
	if f == nil {
		return ErrSecretDestroyed
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.buffer == nil {
		return ErrSecretDestroyed
	}
	return f.buffer.withBytes(fn)
}

func (f *Frame) takeBuffer() *SecretBuffer {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	buffer := f.buffer
	f.buffer = nil
	return buffer
}

func DecodeFrame(frame *Frame) (any, error) {
	if frame == nil {
		return nil, ErrFrameMalformed
	}
	buffer := frame.takeBuffer()
	if buffer == nil {
		return nil, ErrFrameMalformed
	}
	defer buffer.Destroy()
	var decoded any
	err := buffer.withBytes(func(raw []byte) error {
		var err error
		decoded, err = decodeFrameBytes(raw)
		return err
	})
	return decoded, err
}

func decodeFrameBytes(frame []byte) (any, error) {
	if len(frame) < 4 {
		return nil, ErrFrameMalformed
	}
	length := binary.LittleEndian.Uint32(frame[:4])
	if length == 0 || length > MaxFrameBodyBytes {
		if length > MaxFrameBodyBytes {
			return nil, ErrFrameTooLarge
		}
		return nil, ErrFrameMalformed
	}
	if int(length) != len(frame)-4 {
		return nil, ErrFrameMalformed
	}
	body := frame[4:]
	var fields map[uint64]cbor.RawMessage
	if err := avshDecMode.Unmarshal(body, &fields); err != nil {
		return nil, fmt.Errorf("decode AVSH/1 envelope: %w", err)
	}
	rawKind, ok := fields[0]
	if !ok {
		return nil, fmt.Errorf("AVSH/1 message kind missing: %w", ErrFrameMalformed)
	}
	var kind MessageKind
	if err := avshDecMode.Unmarshal(rawKind, &kind); err != nil {
		return nil, fmt.Errorf("decode AVSH/1 message kind: %w", err)
	}
	switch kind {
	case MessageRequest:
		var request Request
		if err := avshDecMode.Unmarshal(body, &request); err != nil {
			return nil, fmt.Errorf("decode AVSH/1 request: %w", err)
		}
		if err := request.validate(); err != nil {
			return nil, err
		}
		if err := requireCanonicalCBOR(body, request); err != nil {
			return nil, err
		}
		return request, nil
	case MessageProgress:
		if len(body) > MaxProgressBodyBytes {
			return nil, fmt.Errorf("progress frame exceeds %d-byte limit: %w", MaxProgressBodyBytes, ErrFrameTooLarge)
		}
		var progress Progress
		if err := avshDecMode.Unmarshal(body, &progress); err != nil {
			return nil, fmt.Errorf("decode AVSH/1 progress: %w", err)
		}
		if err := progress.validate(); err != nil {
			return nil, err
		}
		if err := requireCanonicalCBOR(body, progress); err != nil {
			return nil, err
		}
		return progress, nil
	case MessageReply:
		var reply Reply
		if err := avshDecMode.Unmarshal(body, &reply); err != nil {
			if reply.Secret != nil {
				reply.Secret.Destroy()
			}
			return nil, fmt.Errorf("decode AVSH/1 reply: %w", err)
		}
		if err := reply.validate(); err != nil {
			if reply.Secret != nil {
				reply.Secret.Destroy()
			}
			return nil, err
		}
		if err := requireCanonicalCBOR(body, reply); err != nil {
			reply.Secret.Destroy()
			return nil, err
		}
		return reply, nil
	default:
		return nil, fmt.Errorf("unknown AVSH/1 message kind %d", kind)
	}
}

func requireCanonicalCBOR(body []byte, message any) error {
	switch value := message.(type) {
	case Reply:
		return requireCanonicalReply(body, &value)
	case *Reply:
		return requireCanonicalReply(body, value)
	}
	canonical, err := avshEncMode.Marshal(message)
	if err != nil {
		return fmt.Errorf("re-encode AVSH/1 canonical body: %w", err)
	}
	defer zeroBytes(canonical)
	if !bytes.Equal(body, canonical) {
		return fmt.Errorf("AVSH/1 body is not canonical: %w", ErrFrameMalformed)
	}
	return nil
}

func requireCanonicalReply(body []byte, reply *Reply) error {
	canonical, err := encodeReplyFrame(reply)
	if err != nil {
		return fmt.Errorf("re-encode AVSH/1 canonical reply: %w", err)
	}
	defer canonical.Destroy()
	return canonical.withBytes(func(raw []byte) error {
		if len(raw) < 4 || !bytes.Equal(body, raw[4:]) {
			return fmt.Errorf("AVSH/1 body is not canonical: %w", ErrFrameMalformed)
		}
		return nil
	})
}

type ProgressTracker struct {
	mu    sync.Mutex
	count int
}

func (t *ProgressTracker) Accept(progress Progress) error {
	if err := progress.validate(); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.count >= MaxProgressMessages {
		return ErrProgressLimit
	}
	t.count++
	return nil
}

// SecretBuffer redacts formatting, pins its bytes where supported, and wipes
// them before release. Call Destroy as soon as encryption completes.
type SecretBuffer struct {
	mu        sync.RWMutex
	value     []byte
	region    []byte
	destroyed bool
}

func NewSecretBuffer(input []byte) (*SecretBuffer, error) {
	if len(input) == 0 || len(input) > MaxSecretBytes {
		return nil, fmt.Errorf("secret length is invalid")
	}
	secret, err := newLockedBuffer(len(input), MaxSecretBytes)
	if err != nil {
		return nil, fmt.Errorf("pin secret memory: %w", err)
	}
	copy(secret.value, input)
	return secret, nil
}

func newLockedBuffer(length, limit int) (*SecretBuffer, error) {
	if length <= 0 || length > limit {
		return nil, fmt.Errorf("locked buffer length is invalid")
	}
	region, err := allocateSecretRegion(length)
	if err != nil {
		return nil, err
	}
	secret := &SecretBuffer{value: region[:length:length], region: region}
	runtime.SetFinalizer(secret, (*SecretBuffer).Destroy)
	return secret, nil
}

func (s *SecretBuffer) String() string   { return "[REDACTED]" }
func (s *SecretBuffer) GoString() string { return "[REDACTED]" }

func (s *SecretBuffer) Len() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.value)
}

func (s *SecretBuffer) Equal(candidate []byte) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return subtle.ConstantTimeCompare(s.value, candidate) == 1
}

func (s *SecretBuffer) withBytes(fn func([]byte) error) error {
	if s == nil {
		return ErrSecretDestroyed
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.destroyed {
		return ErrSecretDestroyed
	}
	return fn(s.value)
}

func (s *SecretBuffer) Destroy() {
	if s == nil {
		return
	}
	runtime.SetFinalizer(s, nil)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return
	}
	zeroBytes(s.region)
	releaseSecretMemory(s.region)
	s.value = nil
	s.region = nil
	s.destroyed = true
}

func (s *SecretBuffer) UnmarshalCBOR(data []byte) error {
	value, err := decodeCBORByteString(data)
	if err != nil {
		return err
	}
	secret, err := NewSecretBuffer(value)
	if err != nil {
		return err
	}
	runtime.SetFinalizer(secret, nil)
	s.mu.Lock()
	if len(s.value) != 0 || len(s.region) != 0 || s.destroyed {
		s.mu.Unlock()
		secret.Destroy()
		return fmt.Errorf("secret buffer receiver is not empty")
	}
	s.value = secret.value
	s.region = secret.region
	s.destroyed = false
	s.mu.Unlock()
	secret.value = nil
	secret.region = nil
	secret.destroyed = true
	runtime.SetFinalizer(s, (*SecretBuffer).Destroy)
	return nil
}

func decodeCBORByteString(data []byte) ([]byte, error) {
	if len(data) == 0 || data[0]>>5 != 2 {
		return nil, fmt.Errorf("secret must be a CBOR byte string")
	}
	additional := data[0] & 0x1f
	offset := 1
	var length uint64
	switch {
	case additional < 24:
		length = uint64(additional)
	case additional == 24 && len(data) >= 2:
		length, offset = uint64(data[1]), 2
		if length < 24 {
			return nil, fmt.Errorf("secret CBOR byte string length is not canonical")
		}
	case additional == 25 && len(data) >= 3:
		length, offset = uint64(binary.BigEndian.Uint16(data[1:3])), 3
		if length <= 0xff {
			return nil, fmt.Errorf("secret CBOR byte string length is not canonical")
		}
	case additional == 26 && len(data) >= 5:
		length, offset = uint64(binary.BigEndian.Uint32(data[1:5])), 5
		if length <= 0xffff {
			return nil, fmt.Errorf("secret CBOR byte string length is not canonical")
		}
	default:
		return nil, fmt.Errorf("secret CBOR byte string length is invalid")
	}
	if length == 0 || length > MaxSecretBytes || uint64(len(data)-offset) != length {
		return nil, fmt.Errorf("secret CBOR byte string length is invalid")
	}
	return data[offset:], nil
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
	runtime.KeepAlive(value)
}

func (s *SecretBuffer) MarshalJSON() ([]byte, error) {
	return nil, errors.New("secret buffers cannot be serialized to JSON")
}
