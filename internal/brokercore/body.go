package brokercore

import (
	"bytes"
	"io"
	"net/http"
)

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
