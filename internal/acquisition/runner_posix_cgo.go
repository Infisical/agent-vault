//go:build (darwin || linux) && cgo

package acquisition

import (
	"context"
	"errors"
	"io"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
	"golang.org/x/sys/unix"
)

const providerKillGrace = 2 * time.Second

type providerReceiveResult struct {
	result         *ProviderResult
	code           string
	providerOutput bool
}

type providerWaitResult struct {
	status unix.WaitStatus
	err    error
}

type ownedFD struct {
	mu sync.Mutex
	fd int
}

func newOwnedFD(fd int) *ownedFD { return &ownedFD{fd: fd} }

func (o *ownedFD) Value() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.fd
}

func (o *ownedFD) Close() {
	if o == nil {
		return
	}
	o.mu.Lock()
	fd := o.fd
	o.fd = -1
	o.mu.Unlock()
	closeFD(fd)
}

func runPreparedProvider(
	ctx context.Context,
	prepared *PreparedExecutable,
	handler store.AcquisitionHandler,
	invocation ProviderInvocation,
	requestFrame *Frame,
	ticket []byte,
) (*ProviderResult, error) {
	providerPair, err := closeOnExecSocketpair(providerSocketKind())
	if err != nil {
		return nil, newProviderError("spawn_failed", err)
	}
	providerParentOwner := newOwnedFD(providerPair[0])
	providerRawChildOwner := newOwnedFD(providerPair[1])
	defer providerParentOwner.Close()
	defer providerRawChildOwner.Close()
	if err := configureProviderReceiveSocket(providerParentOwner.Value()); err != nil {
		return nil, newProviderError("spawn_failed", err)
	}

	stderrPair, err := closeOnExecSocketpair(unix.SOCK_STREAM)
	if err != nil {
		return nil, newProviderError("spawn_failed", err)
	}
	stderrParentOwner := newOwnedFD(stderrPair[0])
	stderrRawChildOwner := newOwnedFD(stderrPair[1])
	defer stderrParentOwner.Close()
	defer stderrRawChildOwner.Close()

	providerChildFD, err := duplicateFDAtLeast(providerRawChildOwner.Value(), 10)
	if err != nil {
		return nil, newProviderError("spawn_failed", err)
	}
	providerChildOwner := newOwnedFD(providerChildFD)
	defer providerChildOwner.Close()
	providerRawChildOwner.Close()

	stderrChildFD, err := duplicateFDAtLeast(stderrRawChildOwner.Value(), 10)
	if err != nil {
		return nil, newProviderError("spawn_failed", err)
	}
	stderrChildOwner := newOwnedFD(stderrChildFD)
	defer stderrChildOwner.Close()
	stderrRawChildOwner.Close()

	environment, err := providerEnvironment(handler)
	if err != nil {
		return nil, newProviderError("spawn_failed", err)
	}
	// Preparation can involve file I/O and code-signature verification. Recheck
	// the caller immediately before the irreversible process launch so an
	// already-cancelled acquisition cannot trigger provider startup effects.
	if err := ctx.Err(); err != nil {
		return nil, newProviderError(providerContextErrorCode(ctx), err)
	}
	pid, err := spawnProvider(prepared.Path(), environment, providerChildOwner.Value(), stderrChildOwner.Value())
	if err != nil {
		return nil, newProviderError("spawn_failed", err)
	}
	providerChildOwner.Close()
	stderrChildOwner.Close()
	providerParent := providerParentOwner.Value()
	stderrParent := stderrParentOwner.Value()
	providerCtx, cancel := context.WithTimeout(ctx, time.Duration(handler.TimeoutSeconds)*time.Second)
	defer cancel()

	var terminateOnce sync.Once
	terminate := func() {
		terminateOnce.Do(func() { _ = unix.Kill(-pid, unix.SIGTERM) })
	}
	var abortIOOnce sync.Once
	abortIO := func() {
		abortIOOnce.Do(func() {
			_ = unix.Shutdown(providerParent, unix.SHUT_RDWR)
			_ = unix.Shutdown(stderrParent, unix.SHUT_RD)
		})
	}

	waitCh := make(chan providerWaitResult, 1)
	go func() {
		var status unix.WaitStatus
		for {
			_, waitErr := unix.Wait4(pid, &status, 0, nil)
			if errors.Is(waitErr, unix.EINTR) {
				continue
			}
			waitCh <- providerWaitResult{status: status, err: waitErr}
			return
		}
	}()

	stderrOverflowCh := make(chan struct{}, 1)
	stderrDoneCh := make(chan struct{}, 1)
	go drainProviderStderr(stderrParent, int64(handler.OutputLimitBytes), stderrOverflowCh, stderrDoneCh)

	verifyErr := verifySpawnedProvider(providerCtx, pid, prepared.Path(), handler)
	if providerCtx.Err() != nil {
		terminate()
		abortIO()
		waitForProviderExit(pid, waitCh)
		waitForStderrDrain(stderrDoneCh)
		return nil, newProviderError(providerContextErrorCode(ctx), providerCtx.Err())
	}
	if verifyErr != nil {
		terminate()
		abortIO()
		waitForProviderExit(pid, waitCh)
		waitForStderrDrain(stderrDoneCh)
		return nil, newProviderError("post_spawn_verification_failed", verifyErr)
	}

	sendErr := sendFrameContext(providerCtx, providerParent, requestFrame)
	var sendCode string
	if sendErr != nil {
		if providerCtx.Err() != nil {
			sendCode = providerContextErrorCode(ctx)
		} else {
			sendCode = "protocol_violation"
		}
	}
	var sendWaitResult *providerWaitResult
	if sendCode == "" {
		select {
		case <-stderrOverflowCh:
			sendCode = "output_limit"
		case waited := <-waitCh:
			sendWaitResult = &waited
			if waited.err != nil || !waited.status.Exited() || waited.status.ExitStatus() != 0 {
				sendCode = "provider_error"
			} else {
				sendCode = "protocol_violation"
			}
		default:
		}
	}
	if providerCtx.Err() != nil {
		sendCode = providerContextErrorCode(ctx)
	}
	if sendCode != "" {
		terminate()
		abortIO()
		if sendWaitResult == nil {
			waited := waitForProviderExit(pid, waitCh)
			sendWaitResult = &waited
			if sendCode == "protocol_violation" && (waited.err != nil || !waited.status.Exited() || waited.status.ExitStatus() != 0) {
				sendCode = "provider_error"
			}
		}
		waitForStderrDrain(stderrDoneCh)
		if providerCtx.Err() != nil {
			sendCode = providerContextErrorCode(ctx)
		}
		return nil, newProviderError(sendCode, nil)
	}
	requestFrame.Destroy()

	receiveCh := make(chan providerReceiveResult, 1)
	go func() {
		receiveCh <- receiveProviderMessages(providerParent, pid, ticket, invocation.ContextBindingID, invocation.ProgressSink)
	}()

	var (
		receiveResult *providerReceiveResult
		waitResult    *providerWaitResult
		stderrDone    bool
		failureCode   string
		killTimer     *time.Timer
		killCh        <-chan time.Time
	)
	for receiveResult == nil || waitResult == nil || !stderrDone {
		select {
		case received := <-receiveCh:
			receiveResult = &received
			if received.code != "" && failureCode == "" {
				failureCode = received.code
				terminate()
				abortIO()
				killTimer = time.NewTimer(providerKillGrace)
				killCh = killTimer.C
			}
		case waited := <-waitCh:
			waitResult = &waited
			killCh = nil
			if killTimer != nil {
				killTimer.Stop()
			}
		case <-stderrOverflowCh:
			if failureCode == "" {
				failureCode = "output_limit"
				terminate()
				abortIO()
				killTimer = time.NewTimer(providerKillGrace)
				killCh = killTimer.C
			}
		case <-stderrDoneCh:
			stderrDone = true
		case <-providerCtx.Done():
			if failureCode == "" {
				failureCode = providerContextErrorCode(ctx)
				terminate()
				abortIO()
				killTimer = time.NewTimer(providerKillGrace)
				killCh = killTimer.C
			}
		case <-killCh:
			_ = unix.Kill(-pid, unix.SIGKILL)
			killCh = nil
		}
	}
	if killTimer != nil {
		killTimer.Stop()
	}
	if providerCtx.Err() != nil {
		failureCode = providerContextErrorCode(ctx)
	}

	if failureCode == "output_limit" || failureCode == "cancelled" || failureCode == "provider_timeout" {
		destroyProviderResult(receiveResult.result)
		return nil, newProviderError(failureCode, nil)
	}
	if receiveResult.code != "" && receiveResult.providerOutput {
		destroyProviderResult(receiveResult.result)
		return nil, newProviderError(receiveResult.code, nil)
	}
	if waitResult.err != nil || !waitResult.status.Exited() || waitResult.status.ExitStatus() != 0 {
		destroyProviderResult(receiveResult.result)
		return nil, newProviderError("provider_error", waitResult.err)
	}
	if receiveResult.code != "" {
		destroyProviderResult(receiveResult.result)
		return nil, newProviderError(receiveResult.code, nil)
	}
	if receiveResult.result == nil || receiveResult.result.Secret == nil {
		return nil, newProviderError("protocol_violation", nil)
	}
	return receiveResult.result, nil
}

func providerContextErrorCode(parent context.Context) string {
	if errors.Is(parent.Err(), context.Canceled) || errors.Is(parent.Err(), context.DeadlineExceeded) {
		return "cancelled"
	}
	return "provider_timeout"
}

func receiveProviderMessages(fd, providerPID int, ticket []byte, contextBindingID string, progressSink chan<- Progress) providerReceiveResult {
	tracker := &ProgressTracker{}
	var result *ProviderResult
	providerOutput := false
	for {
		frame, err := receiveFrame(fd, providerPID)
		if err != nil {
			if errors.Is(err, io.EOF) {
				if result == nil {
					return providerReceiveResult{code: "protocol_violation"}
				}
				return providerReceiveResult{result: result, providerOutput: providerOutput}
			}
			destroyProviderResult(result)
			return providerReceiveResult{code: "protocol_violation", providerOutput: true}
		}
		providerOutput = true
		message, err := DecodeFrame(frame)
		if err != nil {
			destroyProviderResult(result)
			if errors.Is(err, ErrProgressLimit) {
				return providerReceiveResult{code: "progress_limit", providerOutput: true}
			}
			return providerReceiveResult{code: "protocol_violation", providerOutput: true}
		}
		switch value := message.(type) {
		case Progress:
			if result != nil {
				destroyProviderResult(result)
				return providerReceiveResult{code: "protocol_violation", providerOutput: true}
			}
			if value.ContextBindingID != contextBindingID {
				return providerReceiveResult{code: "context_binding_mismatch", providerOutput: true}
			}
			if err := tracker.Accept(value); err != nil {
				if errors.Is(err, ErrProgressLimit) {
					return providerReceiveResult{code: "progress_limit", providerOutput: true}
				}
				return providerReceiveResult{code: "protocol_violation", providerOutput: true}
			}
			if progressSink != nil {
				// Provider text is untrusted output and must not cross into jobs,
				// audit records, MCP payloads, or agent-visible state. Expose only
				// the protocol state transition and its context binding.
				value.Message = ""
				if !deliverProgress(progressSink, value) {
					return providerReceiveResult{code: "progress_delivery_failed", providerOutput: true}
				}
			}
		case Reply:
			if result != nil {
				value.Secret.Destroy()
				destroyProviderResult(result)
				return providerReceiveResult{code: "protocol_violation", providerOutput: true}
			}
			ticketMatches := ticketsEqual(value.Ticket, ticket)
			zeroBytes(value.Ticket)
			value.Ticket = nil
			if !ticketMatches {
				value.Secret.Destroy()
				return providerReceiveResult{code: "ticket_mismatch", providerOutput: true}
			}
			if value.ContextBindingID != contextBindingID {
				value.Secret.Destroy()
				return providerReceiveResult{code: "context_binding_mismatch", providerOutput: true}
			}
			result = &ProviderResult{Secret: value.Secret, Meta: value.Meta}
		default:
			destroyProviderResult(result)
			return providerReceiveResult{code: "protocol_violation", providerOutput: true}
		}
	}
}

// deliverProgress treats a caller-closed channel exactly like a full channel:
// delivery fails closed without allowing an asynchronous provider message to
// panic the Agent Vault process. The runner never owns or closes the sink.
func deliverProgress(progressSink chan<- Progress, value Progress) (delivered bool) {
	defer func() {
		if recover() != nil {
			delivered = false
		}
	}()
	select {
	case progressSink <- value:
		return true
	default:
		return false
	}
}

func receiveFrame(fd int, expectedPID ...int) (*Frame, error) {
	providerPID := 0
	if len(expectedPID) > 0 {
		providerPID = expectedPID[0]
	}
	buffer, err := newLockedBuffer(MaxFrameBodyBytes+4, MaxFrameBodyBytes+4)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS == "darwin" {
		if err := readProviderStreamFrame(fd, providerPID, buffer); err != nil {
			buffer.Destroy()
			return nil, err
		}
		return &Frame{buffer: buffer}, nil
	}
	n, flags, record, err := recvProviderBytes(fd, buffer.value, providerPID)
	if err != nil {
		buffer.Destroy()
		if errors.Is(err, unix.EINTR) {
			return receiveFrame(fd, providerPID)
		}
		return nil, err
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n > MaxFrameBodyBytes+4 {
		buffer.Destroy()
		return nil, ErrFrameTooLarge
	}
	if n == 0 {
		buffer.Destroy()
		if record || flags&unix.MSG_EOR != 0 {
			return nil, ErrFrameMalformed
		}
		return nil, io.EOF
	}
	buffer.mu.Lock()
	buffer.value = buffer.value[:n:n]
	buffer.mu.Unlock()
	return &Frame{buffer: buffer}, nil
}

func sendFrame(fd int, frame *Frame) error {
	return frame.withBytes(func(raw []byte) error {
		if runtime.GOOS == "darwin" {
			for len(raw) > 0 {
				n, err := unix.Write(fd, raw)
				if err != nil {
					if errors.Is(err, unix.EINTR) {
						continue
					}
					return err
				}
				if n == 0 {
					return io.ErrUnexpectedEOF
				}
				raw = raw[n:]
			}
			return nil
		}
		n, err := unix.SendmsgN(fd, raw, nil, nil, 0)
		if err != nil {
			return err
		}
		if n != len(raw) {
			return io.ErrShortWrite
		}
		return nil
	})
}

func sendFrameContext(ctx context.Context, fd int, frame *Frame) error {
	if err := unix.SetNonblock(fd, true); err != nil {
		return err
	}
	defer unix.SetNonblock(fd, false)
	return frame.withBytes(func(raw []byte) error {
		if runtime.GOOS == "darwin" {
			for len(raw) > 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
				n, err := unix.Write(fd, raw)
				if errors.Is(err, unix.EINTR) {
					continue
				}
				if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
					if err := waitProviderWritable(ctx, fd); err != nil {
						return err
					}
					continue
				}
				if err != nil {
					return err
				}
				if n == 0 {
					return io.ErrUnexpectedEOF
				}
				raw = raw[n:]
			}
			return nil
		}
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			n, err := unix.SendmsgN(fd, raw, nil, nil, 0)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				if err := waitProviderWritable(ctx, fd); err != nil {
					return err
				}
				continue
			}
			if err != nil {
				return err
			}
			if n != len(raw) {
				return io.ErrShortWrite
			}
			return nil
		}
	})
}

func waitProviderWritable(ctx context.Context, fd int) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		ready, err := unix.Poll(poll, 50)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if ready == 0 {
			continue
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return unix.EPIPE
		}
		if poll[0].Revents&unix.POLLOUT != 0 {
			return nil
		}
	}
}

func readProviderStreamFrame(fd, providerPID int, buffer *SecretBuffer) error {
	if err := readProviderStreamFull(fd, providerPID, buffer.value[:4]); err != nil {
		return err
	}
	length := int(buffer.value[0]) | int(buffer.value[1])<<8 | int(buffer.value[2])<<16 | int(buffer.value[3])<<24
	if length <= 0 {
		return ErrFrameMalformed
	}
	if length > MaxFrameBodyBytes {
		return ErrFrameTooLarge
	}
	if err := readProviderStreamFull(fd, providerPID, buffer.value[4:4+length]); err != nil {
		return err
	}
	buffer.mu.Lock()
	buffer.value = buffer.value[: 4+length : 4+length]
	buffer.mu.Unlock()
	return nil
}

func readProviderStreamFull(fd, providerPID int, destination []byte) error {
	for len(destination) > 0 {
		n, flags, _, err := recvProviderBytes(fd, destination, providerPID)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if flags&unix.MSG_CTRUNC != 0 {
			return ErrFrameMalformed
		}
		if n == 0 {
			if len(destination) == 4 {
				return io.EOF
			}
			return io.ErrUnexpectedEOF
		}
		destination = destination[n:]
	}
	return nil
}

func recvProviderBytes(fd int, destination []byte, expectedPID int) (n int, flags int, record bool, err error) {
	var outOfBand [4096]byte
	n, oobn, flags, _, err := unix.Recvmsg(fd, destination, outOfBand[:], 0)
	if oobn > 0 {
		messages, parseErr := unix.ParseSocketControlMessage(outOfBand[:oobn])
		if parseErr != nil {
			err = ErrFrameMalformed
		} else {
			record, parseErr = inspectProviderControlMessages(messages, expectedPID)
			if parseErr != nil {
				err = parseErr
			}
		}
	} else if providerCredentialsRequired(expectedPID) && n > 0 {
		err = ErrFrameMalformed
	}
	zeroBytes(outOfBand[:])
	return n, flags, record, err
}

func drainProviderStderr(fd int, limit int64, overflowCh chan<- struct{}, doneCh chan<- struct{}) {
	defer func() { doneCh <- struct{}{} }()
	buffer, err := newLockedBuffer(4096, 4096)
	if err != nil {
		overflowCh <- struct{}{}
		return
	}
	defer buffer.Destroy()
	var total int64
	reported := false
	for {
		var n int
		err := buffer.withBytes(func(raw []byte) error {
			var readErr error
			n, readErr = unix.Read(fd, raw)
			if n > 0 {
				zeroBytes(raw[:n])
			}
			return readErr
		})
		if n > 0 {
			total += int64(n)
			if total > limit && !reported {
				reported = true
				select {
				case overflowCh <- struct{}{}:
				default:
				}
			}
		}
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return
		}
		if n == 0 {
			return
		}
	}
}

func providerEnvironment(handler store.AcquisitionHandler) ([]string, error) {
	identity, err := user.Current()
	if err != nil || identity == nil {
		return nil, ErrExecutableUnavailable
	}
	home := filepath.Clean(identity.HomeDir)
	username := identity.Username
	if !filepath.IsAbs(home) || home != identity.HomeDir || len(home) > 4096 || containsControl(home) || strings.ContainsRune(home, '\x00') {
		return nil, ErrExecutableUnavailable
	}
	if username == "" || len(username) > 256 || containsControl(username) || strings.ContainsAny(username, "=\x00") {
		return nil, ErrExecutableUnavailable
	}
	environment := []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + home,
		"USER=" + username,
		"LANG=C",
		"AVSH_TICKET_FD=3",
	}
	if handler.ID == "github-cli" {
		environment = append(environment, "GH_NO_UPDATE_NOTIFIER=1")
	}
	return environment, nil
}

func duplicateFDAtLeast(fd, minimum int) (int, error) {
	return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, minimum)
}

func closeOnExecSocketpair(kind int) ([2]int, error) {
	pair, err := unix.Socketpair(unix.AF_UNIX, kind, 0)
	if err != nil {
		return [2]int{}, err
	}
	unix.CloseOnExec(pair[0])
	unix.CloseOnExec(pair[1])
	return pair, nil
}

func providerSocketKind() int {
	// Darwin does not implement AF_UNIX SOCK_SEQPACKET. AVSH/1 retains its
	// explicit length framing over a private AF_UNIX stream socket there.
	if runtime.GOOS == "darwin" {
		return unix.SOCK_STREAM
	}
	return unix.SOCK_SEQPACKET
}

func closeFD(fd int) {
	if fd >= 0 {
		_ = unix.Close(fd)
	}
}

func destroyProviderResult(result *ProviderResult) {
	if result != nil && result.Secret != nil {
		result.Secret.Destroy()
	}
}

func waitForProviderExit(pid int, waitCh <-chan providerWaitResult) providerWaitResult {
	timer := time.NewTimer(providerKillGrace)
	defer timer.Stop()
	select {
	case waited := <-waitCh:
		return waited
	case <-timer.C:
		_ = unix.Kill(-pid, unix.SIGKILL)
		return <-waitCh
	}
}

func waitForStderrDrain(doneCh <-chan struct{}) {
	<-doneCh
}
