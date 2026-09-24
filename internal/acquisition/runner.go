package acquisition

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"runtime"

	"github.com/Infisical/agent-vault/internal/contextbinding"
	"github.com/Infisical/agent-vault/internal/store"
)

// ProviderInvocation contains only server-resolved acquisition inputs. The
// executable, arguments, environment, and platform selectors always come from
// the registered handler and runner implementation, never from a proposal.
type ProviderInvocation struct {
	VaultID          string
	ResourceID       string
	Profile          string
	ContextBindingID string
	Params           map[string]string

	// ProgressSink receives only redacted protocol state. Delivery is
	// non-blocking; a nil sink discards progress and a full sink fails closed.
	ProgressSink chan<- Progress
}

// ProviderResult owns the acquired secret. Call Secret.Destroy immediately
// after the existing proposal-encryption path has consumed it.
type ProviderResult struct {
	Secret *SecretBuffer
	Meta   ReplyMeta
}

// HandlerResolver is the narrow store capability required by the runner. A
// caller supplies only a registered ID; executable and policy fields are
// always resolved from the current server-owned row immediately before use.
type HandlerResolver interface {
	GetAcquisitionHandler(context.Context, string) (*store.AcquisitionHandler, error)
}

// ProviderError exposes only a stable non-secret code. Underlying provider,
// stderr, protocol, and platform error text is deliberately discarded.
type ProviderError struct {
	Code string
}

func (e *ProviderError) Error() string {
	if e == nil || e.Code == "" {
		return "provider_error"
	}
	return e.Code
}

func newProviderError(code string, _ error) error {
	return &ProviderError{Code: code}
}

func ProviderErrorCode(err error) string {
	var providerErr *ProviderError
	if errors.As(err, &providerErr) {
		return providerErr.Code
	}
	return ""
}

// RunProvider verifies a registered executable, spawns the verified private
// copy, and completes exactly one context-bound AVSH/1 exchange.
func RunProvider(ctx context.Context, resolver HandlerResolver, handlerID string, invocation ProviderInvocation) (*ProviderResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, newProviderError("cancelled", err)
	}

	if resolver == nil || store.ValidateAcquisitionHandlerID(handlerID) != nil {
		return nil, newProviderError("handler_unavailable", nil)
	}
	resolved, err := resolver.GetAcquisitionHandler(ctx, handlerID)
	if err != nil || resolved == nil || resolved.ID != handlerID {
		return nil, newProviderError("handler_unavailable", err)
	}
	handler := cloneHandler(*resolved)
	invocation.Params = cloneParams(invocation.Params)
	if invocation.Params == nil {
		invocation.Params = make(map[string]string, 1)
	}
	// Profile is a server-resolved identifier. It is carried in the protocol
	// params map but cannot be overridden by caller-provided provider params.
	invocation.Params["profile"] = invocation.Profile
	if err := validateProviderInvocation(handler, invocation); err != nil {
		return nil, err
	}

	ticket := make([]byte, TicketBytes)
	if _, err := rand.Read(ticket); err != nil {
		zeroBytes(ticket)
		return nil, newProviderError("random_unavailable", err)
	}
	defer zeroBytes(ticket)

	request := Request{
		Kind:             MessageRequest,
		Ticket:           ticket,
		ResourceID:       invocation.ResourceID,
		Params:           invocation.Params,
		ContextBindingID: invocation.ContextBindingID,
	}
	requestFrame, err := EncodeFrame(request)
	if err != nil {
		return nil, newProviderError("invalid_invocation", err)
	}
	defer requestFrame.Destroy()

	prepared, err := PrepareExecutable(ctx, handler)
	if err != nil {
		return nil, newProviderError(VerificationCode(err), err)
	}
	defer prepared.Close()

	result, err := runPreparedProvider(ctx, prepared, handler, invocation, requestFrame, ticket)
	runtime.KeepAlive(ticket)
	return result, err
}

func validateProviderInvocation(handler store.AcquisitionHandler, invocation ProviderInvocation) error {
	if err := handler.ValidateRegistration(); err != nil {
		return newProviderError("invalid_handler", err)
	}
	if !handler.Enabled {
		return newProviderError("handler_disabled", nil)
	}
	if !containsExact(handler.AllowedKeys, invocation.ResourceID) ||
		!containsExact(handler.AllowedVaults, invocation.VaultID) ||
		!containsExact(handler.AllowedProfiles, invocation.Profile) {
		return newProviderError("handler_not_allowed", nil)
	}
	if err := contextbinding.ValidateBindingID(invocation.ContextBindingID); err != nil {
		return newProviderError("invalid_invocation", err)
	}
	// Reuse the wire validator without allocating or accepting a real ticket.
	validationTicket := make([]byte, TicketBytes)
	defer zeroBytes(validationTicket)
	if err := (Request{
		Kind:             MessageRequest,
		Ticket:           validationTicket,
		ResourceID:       invocation.ResourceID,
		Params:           invocation.Params,
		ContextBindingID: invocation.ContextBindingID,
	}).validate(); err != nil {
		return newProviderError("invalid_invocation", err)
	}
	return nil
}

func containsExact(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func cloneHandler(handler store.AcquisitionHandler) store.AcquisitionHandler {
	handler.AllowedKeys = append([]string(nil), handler.AllowedKeys...)
	handler.AllowedVaults = append([]string(nil), handler.AllowedVaults...)
	handler.AllowedProfiles = append([]string(nil), handler.AllowedProfiles...)
	return handler
}

func cloneParams(params map[string]string) map[string]string {
	if params == nil {
		return nil
	}
	cloned := make(map[string]string, len(params))
	for key, value := range params {
		cloned[key] = value
	}
	return cloned
}

func ticketsEqual(left, right []byte) bool {
	return len(left) == TicketBytes && len(right) == TicketBytes && subtle.ConstantTimeCompare(left, right) == 1
}
