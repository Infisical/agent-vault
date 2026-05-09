package brokercore

import (
	"bytes"
	"errors"
	"io"
	"net/http"
)

// MaterializeRequestBody buffers body fully into memory and returns a
// re-readable copy plus its byte length, so the outbound request can carry
// a real Content-Length instead of falling back to chunked transfer (some
// upstreams reject chunked uploads). Callers must wrap body in
// http.MaxBytesReader before calling so a hostile client cannot exhaust
// memory; size-cap violations surface as *http.MaxBytesError. Returns
// http.NoBody for empty/nil input.
func MaterializeRequestBody(body io.ReadCloser) (io.ReadCloser, int64, error) {
	if body == nil || body == http.NoBody {
		return http.NoBody, 0, nil
	}
	defer func() { _ = body.Close() }()

	data, err := io.ReadAll(body)
	if err != nil {
		return nil, 0, err
	}
	if len(data) == 0 {
		return http.NoBody, 0, nil
	}
	return io.NopCloser(bytes.NewReader(data)), int64(len(data)), nil
}

// RequestBodyErrorCode maps a MaterializeRequestBody error to the proxy
// status + error_code pair: *http.MaxBytesError → 413/request_too_large,
// any other read failure → 400/request_read_error.
func RequestBodyErrorCode(err error) (status int, code string) {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		return http.StatusRequestEntityTooLarge, "request_too_large"
	}
	return http.StatusBadRequest, "request_read_error"
}
