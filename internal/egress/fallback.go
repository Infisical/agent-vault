package egress

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

const maxReplayBodyBytes = 8 << 20

// RoundTripWithFallback sends a request through via and retries it directly
// only for an unreachable proxy under the fail_open policy. Request bodies
// are buffered only when their declared size is bounded by 8 MiB.
func RoundTripWithFallback(req *http.Request, profile *brokercore.UpstreamProxy, via, direct http.RoundTripper, logger *slog.Logger) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("egress: nil request")
	}
	if via == nil {
		return nil, fmt.Errorf("egress: nil proxy transport")
	}
	if profile == nil || profile.FailureMode() != brokercore.UpstreamProxyFailOpen {
		return via.RoundTrip(req)
	}
	if req.Context().Err() != nil {
		closeRequestBody(req)
		return nil, req.Context().Err()
	}

	var replay func() (io.ReadCloser, error)
	switch {
	case req.Body == nil || req.Body == http.NoBody:
		replay = func() (io.ReadCloser, error) { return http.NoBody, nil }
	case req.ContentLength <= 0 || req.ContentLength > maxReplayBodyBytes:
		// Unknown, chunked, zero-but-present, and large bodies are not replayed.
	default:
		if req.GetBody != nil {
			replay = func() (io.ReadCloser, error) { return req.GetBody() }
		} else {
			body, err := io.ReadAll(io.LimitReader(req.Body, req.ContentLength+1))
			if err != nil {
				closeRequestBody(req)
				return nil, fmt.Errorf("egress: buffering request body for fail_open: %w", err)
			}
			if int64(len(body)) != req.ContentLength {
				closeRequestBody(req)
				return nil, fmt.Errorf("egress: request body length %d does not match declared length %d", len(body), req.ContentLength)
			}
			_ = req.Body.Close()
			req.Body = io.NopCloser(bytes.NewReader(body))
			replay = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		}
	}

	resp, err := via.RoundTrip(req)
	if err == nil || !errors.Is(err, ErrProxyUnreachable) || req.Context().Err() != nil || replay == nil || direct == nil {
		return resp, err
	}
	body, bodyErr := replay()
	if bodyErr != nil {
		return nil, fmt.Errorf("egress: creating request replay body: %w", bodyErr)
	}
	if body == nil {
		return nil, fmt.Errorf("egress: request replay body is nil")
	}
	req.Body = body
	if logger != nil {
		logger.Warn("egress proxy unreachable; retrying directly under fail_open",
			slog.String("profile", profile.Name), slog.String("error", err.Error()))
	}
	return direct.RoundTrip(req)
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil && req.Body != http.NoBody {
		_ = req.Body.Close()
	}
}
