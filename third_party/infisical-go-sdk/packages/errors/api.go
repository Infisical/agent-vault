package errors

import (
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/util"
)

// APIError represents an error response from the API
type APIError struct {
	Operation    string `json:"operation"`
	Method       string `json:"method"`
	URL          string `json:"url"`
	StatusCode   int    `json:"statusCode"`
	ErrorMessage string `json:"message,omitempty"`
	ReqId        string `json:"reqId,omitempty"`
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf(
		"APIError: %s unsuccessful response [%v %v] [status-code=%v] [reqId=%v]",
		e.Operation,
		e.Method,
		e.URL,
		e.StatusCode,
		e.ReqId,
	)

	if e.ErrorMessage != "" {
		return fmt.Sprintf("%s [message=\"%s\"]", msg, e.ErrorMessage)

	}

	return msg
}

func NewAPIError(operation string, res *resty.Response) error {
	return &APIError{
		Operation:  operation,
		Method:     res.Request.Method,
		URL:        res.Request.URL,
		StatusCode: res.StatusCode(),
	}
}

func NewAPIErrorWithResponse(operation string, res *resty.Response) error {
	errorMessage := util.TryParseErrorBody(res)
	reqId := util.TryExtractReqId(res)

	return &APIError{
		Operation:    operation,
		Method:       res.Request.Method,
		URL:          res.Request.URL,
		StatusCode:   res.StatusCode(),
		ErrorMessage: errorMessage,
		ReqId:        reqId,
	}
}

// NotModifiedError is returned when the server responds with 304 Not Modified,
// indicating the resource has not changed since the last request (based on ETag).
type NotModifiedError struct {
	Operation string
}

func (e *NotModifiedError) Error() string {
	return fmt.Sprintf("%s: secrets not modified (HTTP 304)", e.Operation)
}

func NewNotModifiedError(operation string) error {
	return &NotModifiedError{
		Operation: operation,
	}
}
